package downloader

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/agoda-com/macOS-vz-kubelet/internal/buildutil"
	"github.com/agoda-com/macOS-vz-kubelet/pkg/event"
	"github.com/agoda-com/macOS-vz-kubelet/pkg/oci"
	"github.com/agoda-com/macOS-vz-kubelet/pkg/resource"
	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/stretchr/testify/require"
)

func TestLocalImportNeverResolvesRegistry(t *testing.T) {
	for _, damage := range []string{"none", "missing-layer", "invalid-manifest"} {
		t.Run(damage, func(t *testing.T) {
			var requests atomic.Int32
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				http.Error(w, "registry must not be contacted", http.StatusServiceUnavailable)
			}))
			defer srv.Close()
			ref := strings.TrimPrefix(srv.URL, "http://") + "/local:base"
			cache, inputs := t.TempDir(), t.TempDir()
			cfg, err := json.Marshal(oci.Config{HardwareModelData: "aHc=", MachineIdData: "aWQ="})
			require.NoError(t, err)
			for name, data := range map[string][]byte{"disk.img": []byte("disk"), "aux.img": []byte("aux"), "config.json": cfg} {
				require.NoError(t, os.WriteFile(filepath.Join(inputs, name), data, 0o600))
			}
			result, err := buildutil.CacheLocal(context.Background(), buildutil.PushOptions{
				Ref: ref, Disk: filepath.Join(inputs, "disk.img"), Aux: filepath.Join(inputs, "aux.img"), Config: filepath.Join(inputs, "config.json"),
			}, cache)
			require.NoError(t, err)
			dir, err := ImageDir(cache, ref)
			require.NoError(t, err)
			switch damage {
			case "missing-layer":
				require.NoError(t, os.Remove(filepath.Join(dir, "disk.img")))
			case "invalid-manifest":
				require.NoError(t, os.WriteFile(filepath.Join(dir, oci.LocalManifestName), []byte("{}"), 0o600))
			}
			img, verifyErr := VerifyCached(context.Background(), cache, ref, resource.RegistryCredentials{})
			platform, downloadErr := Download(context.Background(), Params{Ref: ref, StorePath: cache, MaxAttempts: 1}, nil)
			if damage == "none" {
				require.NoError(t, verifyErr)
				require.NoError(t, downloadErr)
				require.Equal(t, result.ManifestDigest.String(), img.ManifestDigest)
				require.Equal(t, filepath.Join(dir, "disk.img"), platform.BlockStoragePath)
				require.Equal(t, filepath.Join(dir, "aux.img"), platform.AuxiliaryStoragePath)
				require.Equal(t, "aHc=", platform.HardwareModelData)
			} else {
				require.Error(t, verifyErr)
				require.Error(t, downloadErr)
			}
			require.Zero(t, requests.Load())
		})
	}
}

func TestFailedAlwaysPullKeepsLocalLayer(t *testing.T) {
	var manifest []byte
	var blobRequests atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/manifests/") {
			w.Header().Set("Content-Type", ocispec.MediaTypeImageManifest)
			w.Header().Set("Content-Length", fmt.Sprint(len(manifest)))
			w.Header().Set("Docker-Content-Digest", digest.FromBytes(manifest).String())
			if r.Method != http.MethodHead {
				_, _ = w.Write(manifest)
			}
			return
		}
		blobRequests.Add(1)
		http.Error(w, "interrupted blob", http.StatusForbidden)
	}))
	defer srv.Close()
	ref := strings.TrimPrefix(srv.URL, "http://") + "/local:base"
	cache := t.TempDir()
	input := filepath.Join(t.TempDir(), "disk.img")
	require.NoError(t, os.WriteFile(input, []byte("original disk"), 0600))
	_, err := buildutil.CacheLocal(context.Background(), buildutil.PushOptions{Ref: ref, Disk: input}, cache)
	require.NoError(t, err)
	dir, err := ImageDir(cache, ref)
	require.NoError(t, err)
	manifest, err = os.ReadFile(filepath.Join(dir, oci.LocalManifestName))
	require.NoError(t, err)
	_, err = Download(context.Background(), Params{Ref: ref, StorePath: cache, IgnoreExisiting: true, MinFreeBytes: 1, MaxAttempts: 1}, event.LogEventRecorder{})
	require.Error(t, err)
	require.Positive(t, blobRequests.Load(), "failure must occur after manifest resolution")
	got, err := os.ReadFile(filepath.Join(dir, "disk.img"))
	require.NoError(t, err)
	require.Equal(t, "original disk", string(got))
	_, err = Download(context.Background(), Params{Ref: ref, StorePath: cache, MaxAttempts: 1}, event.LogEventRecorder{})
	require.NoError(t, err, "IfNotPresent must still use the local import")
}

package tart

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/agoda-com/macOS-vz-kubelet/internal/diskguard"
	"github.com/agoda-com/macOS-vz-kubelet/pkg/oci"
	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/stretchr/testify/require"
)

func TestRunImport(t *testing.T) {
	for _, mode := range []string{"success", "local", "disk-corrupt", "space"} {
		t.Run(mode, func(t *testing.T) {
			raw := bytes.Repeat([]byte("disk bytes"), 20000)
			encoded := append(block(t, raw, true), []byte("bv4$")...)
			config, err := os.ReadFile("testdata/config.json")
			require.NoError(t, err)
			blobs := map[string][]byte{}
			desc := func(mt string, b []byte) ocispec.Descriptor {
				d := ocispec.Descriptor{MediaType: mt, Size: int64(len(b)), Digest: digest.FromBytes(b)}
				blobs[d.Digest.String()] = b
				return d
			}
			m := fixtureManifest()
			m.Config = desc(ocispec.MediaTypeImageConfig, []byte("{}"))
			disk := desc(DiskMediaType, encoded)
			disk.Annotations = map[string]string{SizeAnnotation: fmt.Sprint(len(raw)), DigestAnnotation: digest.FromBytes(raw).String()}
			m.Layers = []ocispec.Descriptor{desc(ConfigMediaType, config), disk, desc(NVRAMMediaType, []byte("NVRAM"))}
			m.Annotations[DiskSizeAnnotation] = fmt.Sprint(len(raw))
			manifest, err := json.Marshal(m)
			require.NoError(t, err)
			if mode == "disk-corrupt" {
				blobs[disk.Digest.String()] = bytes.Repeat([]byte("x"), len(encoded))
			}
			src := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if strings.Contains(r.URL.Path, "/manifests/") {
					w.Header().Set("Content-Type", ocispec.MediaTypeImageManifest)
					w.Header().Set("Content-Length", fmt.Sprint(len(manifest)))
					w.Header().Set("Docker-Content-Digest", digest.FromBytes(manifest).String())
					_, _ = w.Write(manifest)
					return
				}
				key := r.URL.Path[strings.LastIndex(r.URL.Path, "/")+1:]
				if b, ok := blobs[key]; ok {
					w.Header().Set("Content-Length", fmt.Sprint(len(b)))
					_, _ = w.Write(b)
					return
				}
				http.NotFound(w, r)
			}))
			defer src.Close()
			oldClient := http.DefaultClient
			http.DefaultClient = src.Client()
			defer func() { http.DefaultClient = oldClient }()
			pushed := map[string][]byte{}
			var output []byte
			destinationRequests := 0
			dst := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				destinationRequests++
				switch {
				case r.Method == http.MethodHead:
					http.NotFound(w, r)
				case r.Method == http.MethodPost:
					w.Header().Set("Location", r.URL.Path+"id")
					w.WriteHeader(http.StatusAccepted)
				case r.Method == http.MethodPut && strings.Contains(r.URL.Path, "/blobs/uploads/"):
					b, e := io.ReadAll(r.Body)
					if e != nil {
						http.Error(w, e.Error(), 500)
						return
					}
					d := r.URL.Query().Get("digest")
					if digest.FromBytes(b).String() != d {
						http.Error(w, "digest", 400)
						return
					}
					pushed[d] = b
					w.WriteHeader(http.StatusCreated)
				case r.Method == http.MethodPut && strings.Contains(r.URL.Path, "/manifests/"):
					output, _ = io.ReadAll(r.Body)
					w.Header().Set("Docker-Content-Digest", digest.FromBytes(output).String())
					w.WriteHeader(http.StatusCreated)
				default:
					http.NotFound(w, r)
				}
			}))
			defer dst.Close()
			cache := t.TempDir()
			o := Options{Source: strings.TrimPrefix(src.URL, "https://") + "/tart:test", Destination: strings.TrimPrefix(dst.URL, "http://") + "/ours:test", CacheDir: cache}
			o.Local = mode == "local"
			if mode == "space" {
				o.MinFreeBytes = 1 << 63
			}
			result, err := Run(context.Background(), o)
			entries, e := os.ReadDir(filepath.Join(cache, "build"))
			require.NoError(t, e)
			require.Len(t, entries, 1)
			require.Equal(t, ".lock", entries[0].Name())
			if mode == "local" {
				require.NoError(t, err)
				require.Zero(t, destinationRequests, "local import must never contact destination")
				dir, err := oci.ImageDir(cache, o.Destination)
				require.NoError(t, err)
				m, d, err := oci.ReadLocalManifest(context.Background(), dir)
				require.NoError(t, err)
				require.Equal(t, result.ManifestDigest, d)
				require.Equal(t, result.Manifest, m)
				for _, l := range m.Layers {
					require.True(t, oci.IsCached(l, dir))
				}
				got, err := os.ReadFile(filepath.Join(dir, "disk.img"))
				require.NoError(t, err)
				require.Equal(t, raw, got)
				return
			}
			if mode != "success" {
				require.Error(t, err)
				require.Empty(t, output)
				if mode == "space" {
					require.ErrorIs(t, err, diskguard.ErrInsufficientSpace)
				}
				return
			}
			require.NoError(t, err)
			require.Equal(t, digest.FromBytes(output), result.ManifestDigest)
			require.Len(t, result.Manifest.Layers, 3)
			for _, l := range result.Manifest.Layers {
				b := pushed[l.Digest.String()]
				switch l.MediaType {
				case string(oci.MediaTypeDiskImage), string(oci.MediaTypeAuxImage):
					r, err := gzip.NewReader(bytes.NewReader(b))
					require.NoError(t, err)
					got, err := io.ReadAll(r)
					require.NoError(t, err)
					require.NoError(t, r.Close())
					if l.MediaType == string(oci.MediaTypeDiskImage) {
						require.Equal(t, raw, got)
					} else {
						require.Equal(t, []byte("NVRAM"), got)
					}
				case string(oci.MediaTypeConfigV1):
					var got oci.Config
					require.NoError(t, json.Unmarshal(b, &got))
					want, err := ConvertConfig(config)
					require.NoError(t, err)
					require.Equal(t, want, got)
				default:
					t.Fatalf("unexpected output type %s", l.MediaType)
				}
			}
		})
	}
}

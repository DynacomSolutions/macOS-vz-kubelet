package buildutil

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/agoda-com/macOS-vz-kubelet/internal/disk"
	"github.com/agoda-com/macOS-vz-kubelet/pkg/oci"
	"github.com/stretchr/testify/require"
)

func TestLocalCacheValidation(t *testing.T) {
	for _, damage := range []string{"none", "layer", "sidecar", "stale", "manifest", "manifest-digest"} {
		t.Run(damage, func(t *testing.T) {
			cache := t.TempDir()
			path := filepath.Join(t.TempDir(), "data.img")
			require.NoError(t, os.WriteFile(path, []byte("disk contents"), 0o600))
			ref := "127.0.0.1:1/test:local"
			res, err := CacheLocal(context.Background(), PushOptions{Ref: ref, Disk: path}, cache)
			require.NoError(t, err)
			dir, err := oci.ImageDir(cache, ref)
			require.NoError(t, err)
			require.Equal(t, filepath.Join(cache, "blobs/127.0.0.1/1/test/local"), dir)
			image := filepath.Join(dir, "disk.img")
			meta := filepath.Join(dir, oci.LocalManifestName)
			switch damage {
			case "layer":
				require.NoError(t, os.Remove(image))
			case "sidecar":
				require.NoError(t, os.WriteFile(image+disk.DigestFileSuffix, []byte("wrong"), 0o600))
			case "stale":
				old := time.Unix(1, 0)
				require.NoError(t, os.Chtimes(image+disk.DigestFileSuffix, old, old))
			case "manifest":
				require.NoError(t, os.WriteFile(meta, []byte("{}"), 0o600))
			case "manifest-digest":
				require.NoError(t, os.Remove(meta+disk.DigestFileSuffix))
			}
			m, d, err := oci.ReadLocalManifest(context.Background(), dir)
			if damage == "manifest" || damage == "manifest-digest" {
				require.Error(t, err)
				require.False(t, os.IsNotExist(err), "corrupt metadata must not permit registry fallback")
				return
			}
			require.NoError(t, err)
			require.Equal(t, res.ManifestDigest, d)
			require.Equal(t, damage == "none", oci.IsCached(m.Layers[0], dir))
		})
	}
}

func TestLocalCacheRefusesReplacementAndCancellation(t *testing.T) {
	cache := t.TempDir()
	path := filepath.Join(t.TempDir(), "data.img")
	ref := "127.0.0.1:1/test:local"
	write := func() { require.NoError(t, os.WriteFile(path, []byte("disk contents"), 0o600)) }
	write()
	_, err := CacheLocal(context.Background(), PushOptions{Ref: ref, Disk: path}, cache)
	require.NoError(t, err)
	write()
	_, err = CacheLocal(context.Background(), PushOptions{Ref: ref, Disk: path}, cache)
	require.ErrorContains(t, err, "already exists")
	require.FileExists(t, path)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = CacheLocal(ctx, PushOptions{Ref: "127.0.0.1:1/test:cancelled", Disk: path}, cache)
	require.ErrorIs(t, err, context.Canceled)
	dir, err := oci.ImageDir(cache, "127.0.0.1:1/test:cancelled")
	require.NoError(t, err)
	require.NoDirExists(t, dir)
}

package oci

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/stretchr/testify/require"
)

func TestCleanupStaleImports(t *testing.T) {
	cache := t.TempDir()
	root := filepath.Join(cache, "blobs", "registry", "image")
	require.NoError(t, os.MkdirAll(root, 0700))
	for _, name := range []string{".import-old", ".import-fresh", "ordinary"} {
		dir := filepath.Join(root, name)
		require.NoError(t, os.Mkdir(dir, 0700))
		require.NoError(t, os.WriteFile(filepath.Join(dir, "disk.img"), []byte("data"), 0600))
		if name != ".import-fresh" {
			old := time.Now().Add(-2 * time.Hour)
			require.NoError(t, os.Chtimes(dir, old, old))
		}
	}
	outside := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(outside, "keep"), []byte("data"), 0600))
	require.NoError(t, os.Symlink(outside, filepath.Join(root, ".import-link")))
	require.NoError(t, CleanupStaleImports(cache))
	require.NoDirExists(t, filepath.Join(root, ".import-old"))
	require.DirExists(t, filepath.Join(root, ".import-fresh"))
	require.DirExists(t, filepath.Join(root, "ordinary"))
	require.FileExists(t, filepath.Join(outside, "keep"))
	require.NoError(t, CleanupStaleImports(t.TempDir()))
}

func TestFailedPlainReplacementPreservesLocalLayer(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "aux.img")
	require.NoError(t, os.WriteFile(path, []byte("original"), 0600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, LocalManifestName), []byte("marker"), 0600))
	store, err := New(dir, true, nil)
	require.NoError(t, err)
	defer store.Close(context.Background())
	err = store.processRegularContent(context.Background(), ocispec.Descriptor{Size: 11, Digest: digest.FromString("replacement")}, bytes.NewBufferString("partial"), path)
	require.Error(t, err)
	got, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Equal(t, "original", string(got))
	require.True(t, HasLocalManifest(dir))
	partials, err := filepath.Glob(path + ".partial-*")
	require.NoError(t, err)
	require.Empty(t, partials)
}

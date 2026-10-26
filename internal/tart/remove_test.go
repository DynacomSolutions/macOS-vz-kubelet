package tart

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/agoda-com/macOS-vz-kubelet/pkg/oci"
	"github.com/stretchr/testify/require"
)

func TestRemoveLocalOnlyRemovesLocalImports(t *testing.T) {
	cache := t.TempDir()
	mk := func(ref string, local bool) string {
		dir, err := oci.ImageDir(cache, ref)
		require.NoError(t, err)
		require.NoError(t, os.MkdirAll(dir, 0o700))
		require.NoError(t, os.WriteFile(filepath.Join(dir, "disk.img"), []byte{1}, 0o600))
		if local {
			require.NoError(t, os.WriteFile(filepath.Join(dir, oci.LocalManifestName), []byte("m"), 0o600))
		}
		return dir
	}
	local := mk("reg.example/img/local:1", true)
	remote := mk("reg.example/img/remote:1", false)

	require.Error(t, RemoveLocal(cache, "reg.example/img/remote:1"), "a registry image must not be removed by name")
	require.DirExists(t, remote)
	require.Error(t, RemoveLocal(cache, "reg.example/img/missing:1"))
	require.NoError(t, RemoveLocal(cache, "reg.example/img/local:1"))
	require.NoDirExists(t, local)
	require.DirExists(t, remote)
}

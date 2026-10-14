package volumes_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/agoda-com/macOS-vz-kubelet/internal/volumes"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestResolvePodVolumesDir(t *testing.T) {
	t.Setenv(volumes.PodVolumesDirEnv, "")
	d, err := volumes.ResolvePodVolumesDir("/cache")
	require.NoError(t, err)
	assert.Equal(t, "/cache/mounts", d)

	t.Setenv(volumes.PodVolumesDirEnv, "/Users/Shared/pods/")
	d, err = volumes.ResolvePodVolumesDir("/cache")
	require.NoError(t, err)
	assert.Equal(t, "/Users/Shared/pods", d)

	t.Setenv(volumes.PodVolumesDirEnv, "relative/dir")
	_, err = volumes.ResolvePodVolumesDir("/cache")
	require.Error(t, err)
}

func TestPreparePodVolumesDir(t *testing.T) {
	t.Run("creates missing dir", func(t *testing.T) {
		dir := filepath.Join(t.TempDir(), "a", "b")
		require.NoError(t, volumes.PreparePodVolumesDir(dir))
		fi, err := os.Stat(dir)
		require.NoError(t, err)
		assert.True(t, fi.IsDir())
	})

	t.Run("removes children only and keeps the dir and its mode", func(t *testing.T) {
		dir := t.TempDir()
		require.NoError(t, os.Chmod(dir, 0o710))
		before, err := os.Stat(dir)
		require.NoError(t, err)
		require.NoError(t, os.MkdirAll(filepath.Join(dir, "uid", "vol"), 0o755))
		require.NoError(t, os.WriteFile(filepath.Join(dir, "stale"), []byte("x"), 0o600))

		require.NoError(t, volumes.PreparePodVolumesDir(dir))

		after, err := os.Stat(dir)
		require.NoError(t, err)
		assert.True(t, os.SameFile(before, after), "dir must not be recreated")
		assert.Equal(t, os.FileMode(0o710), after.Mode().Perm())
		entries, err := os.ReadDir(dir)
		require.NoError(t, err)
		assert.Empty(t, entries)
	})

	t.Run("refuses relative path", func(t *testing.T) {
		require.Error(t, volumes.PreparePodVolumesDir("relative"))
	})

	t.Run("refuses symlinked dir", func(t *testing.T) {
		tmp := t.TempDir()
		target := filepath.Join(tmp, "target")
		require.NoError(t, os.Mkdir(target, 0o755))
		require.NoError(t, os.WriteFile(filepath.Join(target, "keep"), nil, 0o644))
		link := filepath.Join(tmp, "link")
		require.NoError(t, os.Symlink(target, link))

		require.Error(t, volumes.PreparePodVolumesDir(link))
		_, err := os.Stat(filepath.Join(target, "keep"))
		assert.NoError(t, err, "symlink target must be untouched")
	})
}

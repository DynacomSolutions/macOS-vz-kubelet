package volumes_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/agoda-com/macOS-vz-kubelet/internal/volumes"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
)

func hardenMounts(t *testing.T, root string, src corev1.VolumeSource, mountRO bool, cms map[string]*corev1.ConfigMap, secs map[string]*corev1.Secret) ([]volumes.Mount, error) {
	t.Helper()
	pod := &corev1.Pod{Spec: corev1.PodSpec{Volumes: []corev1.Volume{{Name: "v", VolumeSource: src}}}}
	c := corev1.Container{VolumeMounts: []corev1.VolumeMount{{Name: "v", MountPath: "/mnt", ReadOnly: mountRO}}}
	return volumes.CreateContainerMounts(context.Background(), root, c, pod, "tok", cms, secs)
}

func TestGeneratedVolumesAlwaysReadOnly(t *testing.T) {
	cms := map[string]*corev1.ConfigMap{"cm": {Data: map[string]string{"k": "v"}}}
	secs := map[string]*corev1.Secret{"s": {Data: map[string][]byte{"k": []byte("v")}}}
	sources := map[string]corev1.VolumeSource{
		"configMap": {ConfigMap: &corev1.ConfigMapVolumeSource{LocalObjectReference: corev1.LocalObjectReference{Name: "cm"}}},
		"secret":    {Secret: &corev1.SecretVolumeSource{SecretName: "s"}},
		"projected": {Projected: &corev1.ProjectedVolumeSource{Sources: []corev1.VolumeProjection{{ServiceAccountToken: &corev1.ServiceAccountTokenProjection{Path: "t"}}}}},
		"downward":  {Projected: &corev1.ProjectedVolumeSource{Sources: []corev1.VolumeProjection{{DownwardAPI: &corev1.DownwardAPIProjection{}}}}},
	}
	for name, src := range sources {
		t.Run(name, func(t *testing.T) {
			m, err := hardenMounts(t, t.TempDir(), src, false, cms, secs)
			require.NoError(t, err)
			assert.True(t, m[0].ReadOnly)
		})
	}
	t.Run("emptyDir stays writable", func(t *testing.T) {
		m, err := hardenMounts(t, t.TempDir(), corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{}}, false, nil, nil)
		require.NoError(t, err)
		assert.False(t, m[0].ReadOnly)
	})
}

func TestSymlinkSwappedVolumeDirRefused(t *testing.T) {
	cms := map[string]*corev1.ConfigMap{"cm": {Data: map[string]string{"k": "pwn"}}}
	cmSrc := corev1.VolumeSource{ConfigMap: &corev1.ConfigMapVolumeSource{LocalObjectReference: corev1.LocalObjectReference{Name: "cm"}}}
	for _, tc := range []struct {
		name string
		src  corev1.VolumeSource
	}{
		{"configMap", cmSrc},
		{"emptyDir", corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root, target := t.TempDir(), t.TempDir()
			require.NoError(t, os.Symlink(target, filepath.Join(root, "v")))
			_, err := hardenMounts(t, root, tc.src, false, cms, nil)
			require.Error(t, err)
			assert.NoFileExists(t, filepath.Join(target, "k"))
		})
	}
}

func TestSymlinkedPodRootRefused(t *testing.T) {
	base, target := t.TempDir(), t.TempDir()
	root := filepath.Join(base, "uid")
	require.NoError(t, os.Symlink(target, root))
	_, err := hardenMounts(t, root, corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{}}, false, nil, nil)
	require.Error(t, err)
	assert.NoDirExists(t, filepath.Join(target, "v"))
}

func TestFileWriteThroughSymlinkRefused(t *testing.T) {
	cms := map[string]*corev1.ConfigMap{"cm": {Data: map[string]string{"k": "pwn"}}}
	src := corev1.VolumeSource{ConfigMap: &corev1.ConfigMapVolumeSource{LocalObjectReference: corev1.LocalObjectReference{Name: "cm"}}}

	t.Run("file symlink is replaced, target untouched", func(t *testing.T) {
		root, outside := t.TempDir(), filepath.Join(t.TempDir(), "sudoers")
		require.NoError(t, os.WriteFile(outside, []byte("orig"), 0o600))
		require.NoError(t, os.Mkdir(filepath.Join(root, "v"), 0o755))
		require.NoError(t, os.Symlink(outside, filepath.Join(root, "v", "k")))
		_, err := hardenMounts(t, root, src, false, cms, nil)
		require.NoError(t, err)
		b, _ := os.ReadFile(outside)
		assert.Equal(t, "orig", string(b))
		fi, err := os.Lstat(filepath.Join(root, "v", "k"))
		require.NoError(t, err)
		assert.True(t, fi.Mode().IsRegular())
	})
	t.Run("subdir symlink refused", func(t *testing.T) {
		root, outside := t.TempDir(), t.TempDir()
		require.NoError(t, os.Mkdir(filepath.Join(root, "v"), 0o755))
		require.NoError(t, os.Symlink(outside, filepath.Join(root, "v", "sub")))
		items := &corev1.ConfigMapVolumeSource{LocalObjectReference: corev1.LocalObjectReference{Name: "cm"}, Items: []corev1.KeyToPath{{Key: "k", Path: "sub/k"}}}
		_, err := hardenMounts(t, root, corev1.VolumeSource{ConfigMap: items}, false, cms, nil)
		require.Error(t, err)
		assert.NoFileExists(t, filepath.Join(outside, "k"))
	})
}

func TestHostPathRevalidateCatchesLateSymlink(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	require.NoError(t, err)
	outside := t.TempDir()
	t.Setenv(volumes.HostPathAllowlistEnv, root)
	target := filepath.Join(root, "a", "b")
	m, err := hostPathMounts(target, false)
	require.NoError(t, err)
	require.NoError(t, m[0].Revalidate())

	// swap a real directory for a symlink after the first resolve
	require.NoError(t, os.RemoveAll(filepath.Join(root, "a")))
	require.NoError(t, os.Symlink(outside, filepath.Join(root, "a")))
	require.ErrorContains(t, m[0].Revalidate(), "symlink")

	// final component swapped to a file
	require.NoError(t, os.Remove(filepath.Join(root, "a")))
	require.NoError(t, os.MkdirAll(filepath.Join(root, "a"), 0o755))
	require.NoError(t, os.WriteFile(target, nil, 0o644))
	require.ErrorContains(t, m[0].Revalidate(), "not a directory")
}

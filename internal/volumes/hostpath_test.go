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

func hostPathMounts(path string, readOnly bool) ([]volumes.Mount, error) {
	pod := &corev1.Pod{Spec: corev1.PodSpec{Volumes: []corev1.Volume{{
		Name:         "v",
		VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: path}},
	}}}}
	c := corev1.Container{VolumeMounts: []corev1.VolumeMount{{Name: "v", MountPath: "/mnt", ReadOnly: readOnly}}}
	return volumes.CreateContainerMounts(context.Background(), "", c, pod, "", nil, nil)
}

func TestHostPathAllowlist(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	require.NoError(t, err)
	allowed := filepath.Join(root, "a")
	require.NoError(t, os.Mkdir(allowed, 0o755))
	require.NoError(t, os.Mkdir(filepath.Join(root, "ab"), 0o755))
	secret := filepath.Join(root, "secret")
	require.NoError(t, os.Mkdir(secret, 0o755))
	require.NoError(t, os.Symlink(secret, filepath.Join(allowed, "escape")))

	t.Run("default denies and creates nothing", func(t *testing.T) {
		t.Setenv(volumes.HostPathAllowlistEnv, "")
		target := filepath.Join(allowed, "new")
		_, err := hostPathMounts(target, false)
		require.ErrorContains(t, err, "denied")
		assert.NoDirExists(t, target)
	})

	t.Setenv(volumes.HostPathAllowlistEnv, allowed)

	t.Run("allowed prefix creates dir", func(t *testing.T) {
		target := filepath.Join(allowed, "new", "deep")
		m, err := hostPathMounts(target, false)
		require.NoError(t, err)
		assert.Equal(t, target, m[0].HostPath)
		assert.DirExists(t, target)
	})
	t.Run("exact prefix allowed", func(t *testing.T) {
		_, err := hostPathMounts(allowed, false)
		require.NoError(t, err)
	})
	t.Run("sibling prefix denied", func(t *testing.T) {
		target := filepath.Join(root, "ab", "x")
		_, err := hostPathMounts(target, false)
		require.ErrorContains(t, err, "denied")
		assert.NoDirExists(t, target)
	})
	t.Run("dotdot denied", func(t *testing.T) {
		_, err := hostPathMounts(allowed+"/../secret/x", false)
		require.ErrorContains(t, err, "'..'")
		assert.NoDirExists(t, filepath.Join(secret, "x"))
	})
	t.Run("symlink escape denied", func(t *testing.T) {
		_, err := hostPathMounts(filepath.Join(allowed, "escape", "x"), false)
		require.ErrorContains(t, err, "outside")
		assert.NoDirExists(t, filepath.Join(secret, "x"))
	})
	t.Run("relative denied", func(t *testing.T) {
		_, err := hostPathMounts("a/b", false)
		require.ErrorContains(t, err, "absolute")
	})
	t.Run("readOnly honoured", func(t *testing.T) {
		m, err := hostPathMounts(allowed, true)
		require.NoError(t, err)
		assert.True(t, m[0].ReadOnly)
	})
}

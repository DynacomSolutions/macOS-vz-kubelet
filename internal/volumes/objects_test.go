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
	"k8s.io/utils/ptr"
)

func mountsFor(t *testing.T, root string, vol corev1.VolumeSource, cms map[string]*corev1.ConfigMap, secrets map[string]*corev1.Secret) ([]volumes.Mount, error) {
	t.Helper()
	c := corev1.Container{VolumeMounts: []corev1.VolumeMount{{Name: "v", MountPath: "/mnt"}}}
	pod := &corev1.Pod{Spec: corev1.PodSpec{Volumes: []corev1.Volume{{Name: "v", VolumeSource: vol}}}}
	return volumes.CreateContainerMounts(context.Background(), root, c, pod, "", cms, secrets)
}

func perm(t *testing.T, path string) os.FileMode {
	t.Helper()
	fi, err := os.Stat(path)
	require.NoError(t, err)
	return fi.Mode().Perm()
}

func TestConfigMapVolume(t *testing.T) {
	cms := map[string]*corev1.ConfigMap{"cm": {
		Data:       map[string]string{"a": "1", "b": "2"},
		BinaryData: map[string][]byte{"bin": {0, 1}},
	}}

	t.Run("all keys with default mode", func(t *testing.T) {
		root := t.TempDir()
		ms, err := mountsFor(t, root, corev1.VolumeSource{ConfigMap: &corev1.ConfigMapVolumeSource{LocalObjectReference: corev1.LocalObjectReference{Name: "cm"}}}, cms, nil)
		require.NoError(t, err)
		require.Len(t, ms, 1)
		got, _ := os.ReadFile(filepath.Join(root, "v", "b"))
		assert.Equal(t, "2", string(got))
		assert.FileExists(t, filepath.Join(root, "v", "bin"))
	})

	t.Run("items and defaultMode", func(t *testing.T) {
		root := t.TempDir()
		_, err := mountsFor(t, root, corev1.VolumeSource{ConfigMap: &corev1.ConfigMapVolumeSource{
			LocalObjectReference: corev1.LocalObjectReference{Name: "cm"},
			DefaultMode:          ptr.To(int32(0o600)),
			Items: []corev1.KeyToPath{
				{Key: "a", Path: "sub/a.txt"},
				{Key: "b", Path: "b.txt", Mode: ptr.To(int32(0o640))},
			},
		}}, cms, nil)
		require.NoError(t, err)
		assert.Equal(t, os.FileMode(0o600), perm(t, filepath.Join(root, "v", "sub", "a.txt")))
		assert.Equal(t, os.FileMode(0o640), perm(t, filepath.Join(root, "v", "b.txt")))
		assert.NoFileExists(t, filepath.Join(root, "v", "bin"))
	})

	t.Run("missing object errors unless optional", func(t *testing.T) {
		src := &corev1.ConfigMapVolumeSource{LocalObjectReference: corev1.LocalObjectReference{Name: "nope"}}
		_, err := mountsFor(t, t.TempDir(), corev1.VolumeSource{ConfigMap: src}, cms, nil)
		require.Error(t, err)
		src.Optional = ptr.To(true)
		ms, err := mountsFor(t, t.TempDir(), corev1.VolumeSource{ConfigMap: src}, cms, nil)
		require.NoError(t, err)
		assert.Len(t, ms, 1)
	})

	t.Run("missing key errors unless optional", func(t *testing.T) {
		src := &corev1.ConfigMapVolumeSource{LocalObjectReference: corev1.LocalObjectReference{Name: "cm"}, Items: []corev1.KeyToPath{{Key: "zz", Path: "zz"}}}
		_, err := mountsFor(t, t.TempDir(), corev1.VolumeSource{ConfigMap: src}, cms, nil)
		require.Error(t, err)
		src.Optional = ptr.To(true)
		_, err = mountsFor(t, t.TempDir(), corev1.VolumeSource{ConfigMap: src}, cms, nil)
		require.NoError(t, err)
	})

	t.Run("item path escaping the volume is refused", func(t *testing.T) {
		_, err := mountsFor(t, t.TempDir(), corev1.VolumeSource{ConfigMap: &corev1.ConfigMapVolumeSource{
			LocalObjectReference: corev1.LocalObjectReference{Name: "cm"},
			Items:                []corev1.KeyToPath{{Key: "a", Path: "../evil"}},
		}}, cms, nil)
		require.Error(t, err)
	})
}

func TestSecretVolume(t *testing.T) {
	secrets := map[string]*corev1.Secret{"s": {Data: map[string][]byte{"token": []byte("tok"), "other": []byte("o")}}}

	t.Run("items and defaultMode", func(t *testing.T) {
		root := t.TempDir()
		_, err := mountsFor(t, root, corev1.VolumeSource{Secret: &corev1.SecretVolumeSource{
			SecretName:  "s",
			DefaultMode: ptr.To(int32(0o400)),
			Items:       []corev1.KeyToPath{{Key: "token", Path: "t"}},
		}}, nil, secrets)
		require.NoError(t, err)
		got, _ := os.ReadFile(filepath.Join(root, "v", "t"))
		assert.Equal(t, "tok", string(got))
		assert.Equal(t, os.FileMode(0o400), perm(t, filepath.Join(root, "v", "t")))
		assert.NoFileExists(t, filepath.Join(root, "v", "other"))
	})

	t.Run("default mode is 0644 and all keys written", func(t *testing.T) {
		root := t.TempDir()
		_, err := mountsFor(t, root, corev1.VolumeSource{Secret: &corev1.SecretVolumeSource{SecretName: "s"}}, nil, secrets)
		require.NoError(t, err)
		assert.Equal(t, os.FileMode(0o644), perm(t, filepath.Join(root, "v", "other")))
	})

	t.Run("optional missing", func(t *testing.T) {
		src := &corev1.SecretVolumeSource{SecretName: "nope"}
		_, err := mountsFor(t, t.TempDir(), corev1.VolumeSource{Secret: src}, nil, secrets)
		require.Error(t, err)
		src.Optional = ptr.To(true)
		_, err = mountsFor(t, t.TempDir(), corev1.VolumeSource{Secret: src}, nil, secrets)
		require.NoError(t, err)
	})
}

func TestProjectedSecretAndEmptyDirWritable(t *testing.T) {
	root := t.TempDir()
	_, err := mountsFor(t, root, corev1.VolumeSource{Projected: &corev1.ProjectedVolumeSource{Sources: []corev1.VolumeProjection{
		{Secret: &corev1.SecretProjection{LocalObjectReference: corev1.LocalObjectReference{Name: "s"}, Items: []corev1.KeyToPath{{Key: "k", Path: "k"}}}},
	}}}, nil, map[string]*corev1.Secret{"s": {Data: map[string][]byte{"k": []byte("v")}}})
	require.NoError(t, err)
	assert.FileExists(t, filepath.Join(root, "v", "k"))

	root = t.TempDir()
	_, err = mountsFor(t, root, corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{}}, nil, nil)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o777), perm(t, filepath.Join(root, "v")))
}

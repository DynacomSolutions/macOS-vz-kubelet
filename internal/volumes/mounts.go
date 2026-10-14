package volumes

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/virtual-kubelet/virtual-kubelet/log"
	corev1 "k8s.io/api/core/v1"
)

const PodVolPerms os.FileMode = 0755

// Mount represents a universal mount point in a container.
// Note: This is a simplified version of the actual implementation
// and can be replaced by containerd's Mount type whenever (if) containerd
// is integrated into the project.
type Mount struct {
	Name          string
	HostPath      string
	ContainerPath string
	ReadOnly      bool
}

// CreateContainerMounts creates the mounts for a container based on the pod spec.
func CreateContainerMounts(ctx context.Context, podVolRoot string, container corev1.Container, pod *corev1.Pod, serviceAccountToken string, configMaps map[string]*corev1.ConfigMap, secrets map[string]*corev1.Secret) ([]Mount, error) {
	mounts := []Mount{}
	for _, mountSpec := range container.VolumeMounts {
		podVolSpec := findPodVolumeSpec(pod, mountSpec.Name)
		if podVolSpec == nil {
			log.G(ctx).Debugf("Container volume mount %s not found in Pod spec", mountSpec.Name)
			continue
		}

		// Common fields to all mount types
		newMount := Mount{
			Name:          mountSpec.Name,
			ContainerPath: filepath.Join(mountSpec.MountPath, mountSpec.SubPath),
			ReadOnly:      mountSpec.ReadOnly,
		}
		// Iterate over the volume types we care about
		if podVolSpec.HostPath != nil {
			hostPath, err := resolveHostPath(podVolSpec.HostPath.Path)
			if err != nil {
				return nil, err
			}
			// only create the host path once it is known to be allowed
			if err := os.MkdirAll(hostPath, PodVolPerms); err != nil {
				return nil, fmt.Errorf("error making hostPath for path %s: %w", hostPath, err)
			}
			newMount.HostPath = hostPath
		} else if podVolSpec.EmptyDir != nil {
			// TODO: Currently ignores the SizeLimit
			newMount.HostPath = filepath.Join(podVolRoot, mountSpec.Name)
			if err := makeEmptyDir(newMount.HostPath); err != nil {
				return nil, fmt.Errorf("error making emptyDir for path %s: %w", newMount.HostPath, err)
			}
		} else if podVolSpec.ConfigMap != nil || podVolSpec.Secret != nil {
			newMount.HostPath = filepath.Join(podVolRoot, mountSpec.Name)
			if err := os.MkdirAll(newMount.HostPath, PodVolPerms); err != nil {
				return nil, fmt.Errorf("error making volume for path %s: %w", newMount.HostPath, err)
			}
			if err := writeObjectVolume(newMount.HostPath, podVolSpec, configMaps, secrets); err != nil {
				return nil, err
			}
		} else if podVolSpec.Projected != nil {
			newMount.HostPath = filepath.Join(podVolRoot, mountSpec.Name)
			err := os.MkdirAll(newMount.HostPath, PodVolPerms)
			if err != nil {
				return nil, fmt.Errorf("error making projected for path %s: %w", newMount.HostPath, err)
			}
			for _, source := range podVolSpec.Projected.Sources {
				if source.ServiceAccountToken != nil {
					err := os.WriteFile(filepath.Join(newMount.HostPath, source.ServiceAccountToken.Path), []byte(serviceAccountToken), PodVolPerms)
					if err != nil {
						return nil, fmt.Errorf("error writing service account token: %w", err)
					}
				}
				if source.ConfigMap != nil {
					data, ok := configMapData(configMaps[source.ConfigMap.Name])
					if err := writeKeys(newMount.HostPath, "config map", source.ConfigMap.Name, data, ok, source.ConfigMap.Items, projectedDefaultMode(podVolSpec.Projected), source.ConfigMap.Optional); err != nil {
						return nil, err
					}
				}
				if source.Secret != nil {
					data, ok := secretData(secrets[source.Secret.Name])
					if err := writeKeys(newMount.HostPath, "secret", source.Secret.Name, data, ok, source.Secret.Items, projectedDefaultMode(podVolSpec.Projected), source.Secret.Optional); err != nil {
						return nil, err
					}
				}
				if source.DownwardAPI != nil {
					// currently only namespace is supported
					for _, item := range source.DownwardAPI.Items {
						if item.FieldRef.FieldPath == "metadata.namespace" {
							mode := PodVolPerms
							if item.Mode != nil {
								mode = os.FileMode(*item.Mode)
							}
							err := os.WriteFile(filepath.Join(newMount.HostPath, item.Path), []byte(pod.Namespace), mode)
							if err != nil {
								return nil, fmt.Errorf("error writing downward API: %w", err)
							}
						}
					}
				}
			}
		} else {
			continue
		}
		mounts = append(mounts, newMount)
	}

	return mounts, nil
}

// findPodVolumeSpec searches for a particular volume spec by name in the Pod spec
func findPodVolumeSpec(pod *corev1.Pod, name string) *corev1.VolumeSource {
	for _, volume := range pod.Spec.Volumes {
		if volume.Name == name {
			return &volume.VolumeSource
		}
	}
	return nil
}

// emptyDirPerms makes emptyDir writable by the container user, which differs from the provider
// user (root) and from the VM user. 0777 is applied with an explicit chmod because the umask
// would otherwise narrow it. chmod leaves macOS ACL entries alone, so ACEs inherited from the
// parent directory remain.
const emptyDirPerms os.FileMode = 0777

func makeEmptyDir(path string) error {
	if err := os.MkdirAll(path, emptyDirPerms); err != nil {
		return err
	}
	return os.Chmod(path, emptyDirPerms)
}

// projectedDefaultMode keeps the historic 0755 default for projected volumes.
func projectedDefaultMode(p *corev1.ProjectedVolumeSource) os.FileMode {
	if p.DefaultMode != nil {
		return os.FileMode(*p.DefaultMode)
	}
	return PodVolPerms
}

const objectVolumeDefaultMode os.FileMode = 0644 // Kubernetes default for configMap and secret volumes

func writeObjectVolume(dir string, v *corev1.VolumeSource, configMaps map[string]*corev1.ConfigMap, secrets map[string]*corev1.Secret) error {
	if cm := v.ConfigMap; cm != nil {
		data, ok := configMapData(configMaps[cm.Name])
		return writeKeys(dir, "config map", cm.Name, data, ok, cm.Items, modeOr(cm.DefaultMode), cm.Optional)
	}
	s := v.Secret
	data, ok := secretData(secrets[s.SecretName])
	return writeKeys(dir, "secret", s.SecretName, data, ok, s.Items, modeOr(s.DefaultMode), s.Optional)
}

func modeOr(m *int32) os.FileMode {
	if m == nil {
		return objectVolumeDefaultMode
	}
	return os.FileMode(*m)
}

func configMapData(cm *corev1.ConfigMap) (map[string][]byte, bool) {
	if cm == nil {
		return nil, false
	}
	d := map[string][]byte{}
	for k, v := range cm.Data {
		d[k] = []byte(v)
	}
	for k, v := range cm.BinaryData {
		d[k] = v
	}
	return d, true
}

func secretData(s *corev1.Secret) (map[string][]byte, bool) {
	if s == nil {
		return nil, false
	}
	d := map[string][]byte{}
	for k, v := range s.StringData {
		d[k] = []byte(v)
	}
	for k, v := range s.Data {
		d[k] = v
	}
	return d, true
}

// writeKeys writes the selected keys (all keys when items is empty) below dir. A missing object
// or key is an error unless optional is set, in which case it is skipped like the kubelet does.
func writeKeys(dir, kind, name string, data map[string][]byte, found bool, items []corev1.KeyToPath, defaultMode os.FileMode, optional *bool) error {
	opt := optional != nil && *optional
	if !found {
		if opt {
			return nil
		}
		return fmt.Errorf("%s %s not found", kind, name)
	}
	if len(items) == 0 {
		for k := range data {
			items = append(items, corev1.KeyToPath{Key: k, Path: k})
		}
	}
	for _, it := range items {
		v, ok := data[it.Key]
		if !ok {
			if opt {
				continue
			}
			return fmt.Errorf("%s %s has no key %q", kind, name, it.Key)
		}
		// pod-supplied paths must not escape the volume
		if !filepath.IsLocal(it.Path) {
			return fmt.Errorf("%s %s: item path %q escapes the volume", kind, name, it.Path)
		}
		mode := defaultMode
		if it.Mode != nil {
			mode = os.FileMode(*it.Mode)
		}
		target := filepath.Join(dir, it.Path)
		if err := os.MkdirAll(filepath.Dir(target), PodVolPerms); err != nil {
			return fmt.Errorf("error writing %s: %w", kind, err)
		}
		if err := os.WriteFile(target, v, mode); err != nil {
			return fmt.Errorf("error writing %s: %w", kind, err)
		}
	}
	return nil
}

package volumes

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// PodVolumesDirEnv overrides where pod volumes are materialised. It must be an absolute path.
// Point it at a directory the Colima VM shares over virtiofs so Docker bind sources are visible.
const PodVolumesDirEnv = "VZ_POD_VOLUMES_DIR"

// PodMountsDir is the default subdirectory of the cache path used when PodVolumesDirEnv is unset.
const PodMountsDir = "mounts"

// ResolvePodVolumesDir returns the pod volumes directory: $VZ_POD_VOLUMES_DIR, else <cachePath>/mounts.
func ResolvePodVolumesDir(cachePath string) (string, error) {
	dir := os.Getenv(PodVolumesDirEnv)
	if dir == "" {
		return filepath.Join(cachePath, PodMountsDir), nil
	}
	if !filepath.IsAbs(dir) {
		return "", fmt.Errorf("%s must be an absolute path, got %q", PodVolumesDirEnv, dir)
	}
	return filepath.Clean(dir), nil
}

// PreparePodVolumesDir creates dir if missing and removes only its children, never the directory
// itself, so a virtiofs share (or its mode, owner and ACLs) pointing at it survives a restart.
// A symlinked dir is refused. An existing dir keeps its mode, ownership and ACLs.
func PreparePodVolumesDir(dir string) error {
	if !filepath.IsAbs(dir) {
		return fmt.Errorf("pod volumes dir must be an absolute path, got %q", dir)
	}
	fi, err := os.Lstat(dir)
	switch {
	case errors.Is(err, os.ErrNotExist):
		// MkdirAll creates parents too; a symlinked parent is the operator's choice, only dir itself is checked.
		if err := os.MkdirAll(dir, PodVolPerms); err != nil {
			return fmt.Errorf("creating pod volumes dir: %w", err)
		}
		return nil
	case err != nil:
		return fmt.Errorf("inspecting pod volumes dir: %w", err)
	case fi.Mode()&os.ModeSymlink != 0:
		return fmt.Errorf("pod volumes dir %q is a symlink; refusing", dir)
	case !fi.IsDir():
		return fmt.Errorf("pod volumes dir %q is not a directory", dir)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return fmt.Errorf("reading pod volumes dir: %w", err)
	}
	for _, e := range entries {
		if err := os.RemoveAll(filepath.Join(dir, e.Name())); err != nil {
			return fmt.Errorf("removing stale pod volume %q: %w", e.Name(), err)
		}
	}
	return nil
}

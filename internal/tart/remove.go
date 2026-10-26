package tart

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/agoda-com/macOS-vz-kubelet/pkg/oci"
)

// RemoveLocal deletes one local-only cached import (the image `ref` that import-tart --local created), which
// eviction never touches. It refuses anything without the local-only marker, so a registry image cannot be removed
// by name here. Like diskguard.EvictDir it removes only the files directly in the image directory. The caller must
// ensure no VM uses the image.
func RemoveLocal(cacheDir, ref string) error {
	dir, err := oci.ImageDir(cacheDir, ref)
	if err != nil {
		return err
	}
	if fi, err := os.Lstat(dir); err != nil || !fi.IsDir() {
		return fmt.Errorf("%s is not a cached image directory: %v", ref, err)
	}
	if !oci.HasLocalManifest(dir) {
		return fmt.Errorf("%s is not a local-only import; refusing to remove it", ref)
	}
	files, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	for _, f := range files {
		if f.IsDir() {
			continue
		}
		if err := os.Remove(filepath.Join(dir, f.Name())); err != nil {
			return err
		}
	}
	return os.Remove(dir)
}

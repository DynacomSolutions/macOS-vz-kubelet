// Package buildutil holds the pure (no Virtualization.framework) parts of the build-image
// command: safe reading of root-supplied files, the build directory, reference checks and the
// streaming registry push. The command runs as root, so every input is validated here.
package buildutil

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"
)

// FilePolicy says what a root-supplied input file must look like.
type FilePolicy struct {
	MaxSize   int64       // largest accepted size in bytes
	OwnerUID  uint32      // required owner
	ForbidBit os.FileMode // permission bits that must not be set (for example 0o022 or 0o077)
}

// ReadFile reads path under policy. The path must be absolute and already clean, the last
// component is opened with O_NOFOLLOW (a symlink is refused), and the opened file (not the
// path) is checked to be a regular file with the required owner and mode, so there is no
// check-then-use window.
func ReadFile(path string, p FilePolicy) ([]byte, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, fmt.Errorf("%q must be an absolute, clean path", path)
	}
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, fmt.Errorf("open %q: %w", path, err)
	}
	defer f.Close()

	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("%q is not a regular file", path)
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok || st.Uid != p.OwnerUID {
		return nil, fmt.Errorf("%q must be owned by uid %d", path, p.OwnerUID)
	}
	if fi.Mode().Perm()&p.ForbidBit != 0 {
		return nil, fmt.Errorf("%q has too permissive mode %v (must not include %04o)", path, fi.Mode().Perm(), p.ForbidBit)
	}
	if fi.Size() > p.MaxSize {
		return nil, fmt.Errorf("%q is larger than %d bytes", path, p.MaxSize)
	}
	b, err := io.ReadAll(io.LimitReader(f, p.MaxSize+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > p.MaxSize {
		return nil, errors.New("file grew while reading")
	}
	return b, nil
}

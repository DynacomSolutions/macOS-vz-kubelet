package volumes

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

// Pod volume directories sit on a share that a less-trusted user can modify while the provider
// runs as root. Everything below the pod root is therefore created and written through directory
// file descriptors with O_NOFOLLOW, so a component swapped for a symlink is refused, not followed.

const dirFlags = unix.O_RDONLY | unix.O_DIRECTORY | unix.O_NOFOLLOW | unix.O_CLOEXEC

// openRoot creates root if missing and opens it without following a symlink in its last
// component. Parents are the operator's choice (see PreparePodVolumesDir).
func openRoot(root string) (int, error) {
	if err := os.MkdirAll(filepath.Dir(root), PodVolPerms); err != nil {
		return -1, err
	}
	if err := unix.Mkdir(root, uint32(PodVolPerms)); err != nil && !errors.Is(err, unix.EEXIST) {
		return -1, err
	}
	fd, err := unix.Open(root, dirFlags, 0)
	if err != nil {
		return -1, fmt.Errorf("opening %q (symlinks are refused): %w", root, err)
	}
	return fd, nil
}

// mkdirAllUnder creates rel below root one component at a time and returns an fd for the
// final directory. A symlink or non-directory in any component is an error. The caller closes the fd.
func mkdirAllUnder(root, rel string, perm os.FileMode) (int, error) {
	if !filepath.IsLocal(rel) {
		return -1, fmt.Errorf("path %q escapes the volume root", rel)
	}
	cur, err := openRoot(root)
	if err != nil {
		return -1, err
	}
	if rel == "." {
		return cur, nil
	}
	for _, c := range strings.Split(filepath.Clean(rel), string(filepath.Separator)) {
		if err := unix.Mkdirat(cur, c, uint32(perm.Perm())); err != nil && !errors.Is(err, unix.EEXIST) {
			unix.Close(cur)
			return -1, err
		}
		next, err := unix.Openat(cur, c, dirFlags, 0)
		unix.Close(cur)
		if err != nil {
			return -1, fmt.Errorf("component %q of %q is not a plain directory: %w", c, rel, err)
		}
		cur = next
	}
	return cur, nil
}

// writeFileUnder writes data to rel below root, creating parents. An existing entry is unlinked
// first (a symlink or hardlink is removed, never written through) and the file is created O_EXCL.
func writeFileUnder(root, rel string, data []byte, mode os.FileMode) error {
	dir, base := filepath.Split(filepath.Clean(rel))
	if base == "." || base == ".." || !filepath.IsLocal(rel) {
		return fmt.Errorf("invalid file path %q", rel)
	}
	dfd, err := mkdirAllUnder(root, filepath.Clean(dir), PodVolPerms)
	if err != nil {
		return err
	}
	defer unix.Close(dfd)
	if err := unix.Unlinkat(dfd, base, 0); err != nil && !errors.Is(err, unix.ENOENT) {
		return err
	}
	fd, err := unix.Openat(dfd, base, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, uint32(mode.Perm()))
	if err != nil {
		return err
	}
	f := os.NewFile(uintptr(fd), base)
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

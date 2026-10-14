package volumes

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// HostPathAllowlistEnv names the comma-separated list of absolute path prefixes
// that Pod hostPath volumes may live under. Empty (the default) denies all hostPath volumes.
const HostPathAllowlistEnv = "VZ_HOSTPATH_ALLOWLIST"

// resolveHostPath validates a requested hostPath against the allowlist and returns
// the symlink-resolved path to use and the resolved allowlist prefix that contains it.
// It never touches the filesystem beyond reading.
func resolveHostPath(requested string) (string, string, error) {
	var prefixes []string
	for _, p := range strings.Split(os.Getenv(HostPathAllowlistEnv), ",") {
		if p = strings.TrimSpace(p); p != "" {
			prefixes = append(prefixes, p)
		}
	}
	if len(prefixes) == 0 {
		return "", "", fmt.Errorf("hostPath %q denied: %s is empty, hostPath volumes are disabled", requested, HostPathAllowlistEnv)
	}
	if !filepath.IsAbs(requested) {
		return "", "", fmt.Errorf("hostPath %q denied: path must be absolute", requested)
	}
	for _, part := range strings.Split(requested, string(filepath.Separator)) {
		if part == ".." {
			return "", "", fmt.Errorf("hostPath %q denied: '..' is not allowed", requested)
		}
	}
	resolved, err := evalExisting(filepath.Clean(requested))
	if err != nil {
		return "", "", fmt.Errorf("hostPath %q denied: %w", requested, err)
	}
	for _, prefix := range prefixes {
		if !filepath.IsAbs(prefix) {
			continue
		}
		// Resolve the prefix too so a symlinked prefix (e.g. /tmp on macOS) still matches.
		rp, err := evalExisting(filepath.Clean(prefix))
		if err != nil {
			continue
		}
		if resolved == rp || strings.HasPrefix(resolved, strings.TrimSuffix(rp, string(filepath.Separator))+string(filepath.Separator)) {
			return resolved, rp, nil
		}
	}
	return "", "", fmt.Errorf("hostPath %q denied: resolves to %q, outside %s", requested, resolved, HostPathAllowlistEnv)
}

// evalExisting resolves symlinks on the deepest existing ancestor of p and
// re-appends the not-yet-existing remainder.
func evalExisting(p string) (string, error) {
	rest := ""
	for cur := p; ; cur = filepath.Dir(cur) {
		if r, err := filepath.EvalSymlinks(cur); err == nil {
			return filepath.Join(r, rest), nil
		} else if !os.IsNotExist(err) {
			return "", err
		}
		rest = filepath.Join(filepath.Base(cur), rest)
		if filepath.Dir(cur) == cur {
			return "", fmt.Errorf("no existing ancestor of %q", p)
		}
	}
}

// Revalidate re-checks a hostPath mount just before it is handed to the VM or Docker: no symlink
// may exist below the allowlisted prefix and the target must be a real directory. Mounts that are
// not hostPath volumes pass. Remaining window: a swap between this check and the kernel opening
// the path (inside vz.NewSharedDirectory or the Docker daemon) cannot be closed from userspace.
func (m Mount) Revalidate() error {
	if m.HostPathPrefix == "" {
		return nil
	}
	rel, err := filepath.Rel(m.HostPathPrefix, m.HostPath)
	if err != nil || !filepath.IsLocal(rel) && rel != "." {
		return fmt.Errorf("hostPath %q is outside its allowlisted prefix %q", m.HostPath, m.HostPathPrefix)
	}
	cur := m.HostPathPrefix
	parts := []string{"."}
	if rel != "." {
		parts = strings.Split(rel, string(filepath.Separator))
	}
	for _, c := range parts {
		cur = filepath.Join(cur, c)
		fi, err := os.Lstat(cur)
		if err != nil {
			return fmt.Errorf("hostPath %q denied: %w", m.HostPath, err)
		}
		if fi.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("hostPath %q denied: %q is a symlink", m.HostPath, cur)
		}
		if !fi.IsDir() {
			return fmt.Errorf("hostPath %q denied: %q is not a directory", m.HostPath, cur)
		}
	}
	return nil
}

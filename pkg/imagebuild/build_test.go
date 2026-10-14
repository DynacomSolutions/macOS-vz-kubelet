package imagebuild

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/agoda-com/macOS-vz-kubelet/internal/buildutil"
	"github.com/agoda-com/macOS-vz-kubelet/pkg/downloader"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	testFrom = "registry.example.com/macos-vz/base:1"
	testTo   = "registry.example.com/macos-vz/base:2"
)

func copyClone(src, dst string) error {
	b, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, b, 0o600)
}

func testOptions(t *testing.T) Options {
	t.Helper()
	dir := t.TempDir()
	script := filepath.Join(dir, "script.sh")
	require.NoError(t, os.WriteFile(script, []byte("echo hi\n"), 0o600))
	creds := filepath.Join(dir, "creds.json")
	require.NoError(t, os.WriteFile(creds, []byte(`{"username":"u","password":"p"}`), 0o600))
	return Options{
		From: testFrom, To: testTo, ScriptPath: script, CredsPath: creds,
		CacheDir: filepath.Join(dir, "cache"), Prefixes: []string{"registry.example.com/macos-vz/"},
		MinFreeBytes: 1, OwnerUID: uint32(os.Getuid()), CPU: 2, MemoryBytes: 4 << 30,
	}
}

func TestCloneInputsClonesIntoBuildDirAndCleansUp(t *testing.T) {
	old := cloneFile
	cloneFile = copyClone
	defer func() { cloneFile = old }()

	imageDir := t.TempDir()
	for n, c := range map[string]string{"disk.img": "disk", "aux.img": "aux", "config.json": `{"os":"darwin"}`} {
		require.NoError(t, os.WriteFile(filepath.Join(imageDir, n), []byte(c), 0o600))
	}
	root := filepath.Join(t.TempDir(), "build")
	bd, err := buildutil.NewBuildDir(root)
	require.NoError(t, err)

	require.NoError(t, cloneInputs(imageDir, bd, uint32(os.Getuid())))
	for n, c := range map[string]string{"disk.img": "disk", "aux.img": "aux", "config.json": `{"os":"darwin"}`} {
		p, _ := bd.Path(n)
		got, err := os.ReadFile(p)
		require.NoError(t, err)
		assert.Equal(t, c, string(got))
	}

	require.NoError(t, bd.Close())
	assert.NoDirExists(t, bd.Dir(), "the clone is deleted")
}

func TestCloneInputsRefusesSymlinkedDisk(t *testing.T) {
	old := cloneFile
	cloneFile = copyClone
	defer func() { cloneFile = old }()

	imageDir := t.TempDir()
	secret := filepath.Join(t.TempDir(), "secret")
	require.NoError(t, os.WriteFile(secret, []byte("s"), 0o600))
	require.NoError(t, os.Symlink(secret, filepath.Join(imageDir, "disk.img")))
	require.NoError(t, os.WriteFile(filepath.Join(imageDir, "aux.img"), []byte("a"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(imageDir, "config.json"), []byte("{}"), 0o600))

	bd, err := buildutil.NewBuildDir(filepath.Join(t.TempDir(), "build"))
	require.NoError(t, err)
	defer bd.Close()
	assert.ErrorContains(t, cloneInputs(imageDir, bd, uint32(os.Getuid())), "not a regular file")
}

func TestRunRefusals(t *testing.T) {
	oldCount := countVMProcesses
	defer func() { countVMProcesses = oldCount }()
	countVMProcesses = func() (int, error) { return 0, nil }

	t.Run("disallowed destination", func(t *testing.T) {
		o := testOptions(t)
		o.To = "registry.example.com/other/base:2"
		assert.ErrorContains(t, Run(context.Background(), o), "not allowed")
	})

	t.Run("a running VM", func(t *testing.T) {
		o := testOptions(t)
		countVMProcesses = func() (int, error) { return 1, nil }
		defer func() { countVMProcesses = func() (int, error) { return 0, nil } }()
		assert.ErrorContains(t, Run(context.Background(), o), "virtual machine(s) are running")
		assert.NoDirExists(t, filepath.Join(o.CacheDir, "build"))
	})

	t.Run("not enough free space", func(t *testing.T) {
		o := testOptions(t)
		require.NoError(t, os.MkdirAll(o.CacheDir, 0o700))
		o.MinFreeBytes = 1 << 62
		err := Run(context.Background(), o)
		assert.True(t, errors.Is(err, downloader.ErrInsufficientSpace), "got %v", err)
		assert.NoDirExists(t, filepath.Join(o.CacheDir, "build"))
	})

	t.Run("script writable by others", func(t *testing.T) {
		o := testOptions(t)
		require.NoError(t, os.Chmod(o.ScriptPath, 0o666))
		assert.ErrorContains(t, Run(context.Background(), o), "too permissive")
	})

	t.Run("credentials readable by others", func(t *testing.T) {
		o := testOptions(t)
		require.NoError(t, os.Chmod(o.CredsPath, 0o644))
		assert.ErrorContains(t, Run(context.Background(), o), "too permissive")
	})
}

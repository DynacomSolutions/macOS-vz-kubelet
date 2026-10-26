package tart

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/agoda-com/macOS-vz-kubelet/internal/diskguard"
	"github.com/agoda-com/macOS-vz-kubelet/pkg/oci"
	"github.com/sirupsen/logrus"
	logrustest "github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/require"
	"github.com/virtual-kubelet/virtual-kubelet/log"
	logruslogger "github.com/virtual-kubelet/virtual-kubelet/log/logrus"
)

func TestMakeRoomEvictsLRUNeverLocal(t *testing.T) {
	const mib = 1 << 20
	root := t.TempDir()
	mk := func(name string, age time.Duration, local bool) string {
		dir := filepath.Join(root, name)
		require.NoError(t, os.Mkdir(dir, 0o700))
		b := make([]byte, mib)
		for i := range b {
			b[i] = 1 // not sparse
		}
		require.NoError(t, os.WriteFile(filepath.Join(dir, "disk.img"), b, 0o600))
		if local {
			require.NoError(t, os.WriteFile(filepath.Join(dir, oci.LocalManifestName), []byte("m"), 0o600))
		}
		when := time.Now().Add(-age)
		require.NoError(t, os.Chtimes(dir, when, when))
		return dir
	}
	a, b, c := mk("a", 3*time.Hour, false), mk("b", 2*time.Hour, false), mk("c", 5*time.Hour, true)
	sizes := map[string]uint64{a: diskguard.AllocatedBytes(a), b: diskguard.AllocatedBytes(b)}
	// Simulated volume: free grows by the size of each evicted entry.
	freeFn := func(base uint64) func() (uint64, error) {
		return func() (uint64, error) {
			free := base
			for d, n := range sizes {
				if _, err := os.Stat(d); os.IsNotExist(err) {
					free += n
				}
			}
			return free, nil
		}
	}
	exists := func(d string) bool { _, err := os.Stat(d); return err == nil }

	// Needs a little more than free: evicting A alone suffices, B survives.
	require.NoError(t, diskguard.MakeRoom(context.Background(), root, nil, sizes[a]/2+10, 0, freeFn(10)))
	require.False(t, exists(a))
	require.True(t, exists(b))
	require.True(t, exists(c))

	// Now B must go too; C (local-only) is never touched.
	require.NoError(t, diskguard.MakeRoom(context.Background(), root, nil, sizes[b]+sizes[a]/2, 0, freeFn(0)))
	require.False(t, exists(b))
	require.True(t, exists(c))

	// Still short: fails cleanly, C survives.
	err := diskguard.MakeRoom(context.Background(), root, nil, 1<<40, 0, freeFn(0))
	require.ErrorIs(t, err, diskguard.ErrInsufficientSpace)
	require.True(t, exists(c))
}

func TestMakeRoomEvictsNothingWhenHopeless(t *testing.T) {
	root := t.TempDir()
	d := filepath.Join(root, "a")
	require.NoError(t, os.Mkdir(d, 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(d, "disk.img"), []byte{1}, 0o600))
	err := diskguard.MakeRoom(context.Background(), root, map[string]bool{d: true}, 1<<40, 0, func() (uint64, error) { return 0, nil })
	require.ErrorIs(t, err, diskguard.ErrInsufficientSpace)
	require.FileExists(t, filepath.Join(d, "disk.img"), "protected destination must survive")
}

func TestMakeRoomLogsEviction(t *testing.T) {
	root := t.TempDir()
	d := filepath.Join(root, "a")
	require.NoError(t, os.Mkdir(d, 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(d, "disk.img"), make([]byte, 1<<20), 0o600))
	l, hook := logrustest.NewNullLogger()
	ctx := log.WithLogger(context.Background(), logruslogger.FromLogrus(logrus.NewEntry(l)))
	evicted := false
	err := diskguard.MakeRoom(ctx, root, nil, 100, 0, func() (uint64, error) {
		if _, e := os.Stat(d); os.IsNotExist(e) {
			evicted = true
			return 1000, nil
		}
		return 0, nil
	})
	require.NoError(t, err)
	require.True(t, evicted)
	var found bool
	for _, e := range hook.AllEntries() {
		found = found || strings.Contains(e.Message, "Evicting unused cached image "+d)
	}
	require.True(t, found, "eviction must be logged")
}

func TestMakeRoomProtectsKeepAndRecent(t *testing.T) {
	cache := t.TempDir()
	mk := func(ref string, age time.Duration) string {
		dir, err := oci.ImageDir(cache, ref)
		require.NoError(t, err)
		require.NoError(t, os.MkdirAll(dir, 0o700))
		require.NoError(t, os.WriteFile(filepath.Join(dir, "disk.img"), make([]byte, 1<<20), 0o600))
		when := time.Now().Add(-age)
		require.NoError(t, os.Chtimes(dir, when, when))
		return dir
	}
	kept := mk("reg.example/img/kept:1", 72*time.Hour)
	recent := mk("reg.example/img/recent:1", time.Hour)
	stale := mk("reg.example/img/stale:1", 72*time.Hour)
	exists := func(d string) bool { _, err := os.Stat(d); return err == nil }
	free := func() (uint64, error) {
		if exists(stale) {
			return 0, nil
		}
		return 1 << 30, nil
	}
	o := Options{CacheDir: cache, Destination: "reg.example/img/dst:1", Keep: []string{"reg.example/img/kept:1"}}

	// Only the stale image is eligible; even though more space is wanted than it can free,
	// nothing may be evicted (fail fast).
	err := makeRoom(context.Background(), o, free, 1<<40)
	require.ErrorIs(t, err, diskguard.ErrInsufficientSpace)
	require.True(t, exists(kept) && exists(recent) && exists(stale), "nothing evicted when hopeless")

	require.NoError(t, makeRoom(context.Background(), o, free, 1<<20))
	require.False(t, exists(stale))
	require.True(t, exists(kept), "--keep image must survive")
	require.True(t, exists(recent), "image used in the last 24h must survive")
}

func TestMakeRoomIgnoreRecentStillProtectsKeep(t *testing.T) {
	cache := t.TempDir()
	mk := func(ref string, age time.Duration) string {
		dir, err := oci.ImageDir(cache, ref)
		require.NoError(t, err)
		require.NoError(t, os.MkdirAll(dir, 0o700))
		require.NoError(t, os.WriteFile(filepath.Join(dir, "disk.img"), make([]byte, 1<<20), 0o600))
		when := time.Now().Add(-age)
		require.NoError(t, os.Chtimes(dir, when, when))
		return dir
	}
	kept := mk("reg.example/img/kept:1", time.Hour)
	recent := mk("reg.example/img/recent:1", time.Hour)
	exists := func(d string) bool { _, err := os.Stat(d); return err == nil }
	free := func() (uint64, error) {
		if exists(recent) {
			return 0, nil
		}
		return 1 << 30, nil
	}
	o := Options{CacheDir: cache, Destination: "reg.example/img/dst:1", Keep: []string{"reg.example/img/kept:1"}}
	require.ErrorIs(t, makeRoom(context.Background(), o, free, 1<<20), diskguard.ErrInsufficientSpace)
	require.True(t, exists(recent), "recent image survives without IgnoreRecent")
	o.IgnoreRecent = true
	require.NoError(t, makeRoom(context.Background(), o, free, 1<<20))
	require.False(t, exists(recent), "IgnoreRecent evicts a recently used image")
	require.True(t, exists(kept), "--keep image must survive IgnoreRecent")
}

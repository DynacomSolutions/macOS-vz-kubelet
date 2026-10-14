package downloader

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/agoda-com/macOS-vz-kubelet/pkg/oci"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const gib = uint64(1) << 30

func TestRequiredBytes(t *testing.T) {
	dir := t.TempDir()
	compressed := ocispec.Descriptor{Size: 10, Annotations: map[string]string{
		ocispec.AnnotationTitle:          "disk.img",
		oci.AnnotationUncompressedSize:   "40",
		oci.AnnotationUncompressedDigest: "sha256:abc",
	}}
	plain := ocispec.Descriptor{Size: 5, Annotations: map[string]string{ocispec.AnnotationTitle: "aux.img"}}
	layers := []ocispec.Descriptor{compressed, plain}

	// streamed compressed layer = uncompressed output only; plain layer = its size.
	assert.Equal(t, uint64(40+5), requiredBytes(layers, dir, false))

	// a bare file without a digest sidecar is an aborted partial: still counted in full.
	disk := filepath.Join(dir, "disk.img")
	require.NoError(t, os.WriteFile(disk, []byte("x"), 0o600))
	assert.Equal(t, uint64(45), requiredBytes(layers, dir, false))

	// a validated file (sidecar newer than file) costs nothing, unless a re-pull is forced.
	require.NoError(t, os.WriteFile(disk+".digest", []byte("sha256:abc"), 0o600))
	require.NoError(t, os.Chtimes(disk, time.Now().Add(-time.Hour), time.Now().Add(-time.Hour)))
	assert.Equal(t, uint64(5), requiredBytes(layers, dir, false))
	assert.Equal(t, uint64(45), requiredBytes(layers, dir, true))
}

func TestRemoveStale(t *testing.T) {
	dir := t.TempDir()
	layers := []ocispec.Descriptor{
		{Annotations: map[string]string{ocispec.AnnotationTitle: "stale.img"}},
		{Annotations: map[string]string{ocispec.AnnotationTitle: "good.img"}},
	}
	for _, f := range []string{"stale.img", "stale.img.partial-abc", "stale.img.partial", "good.img", "good.img.digest"} {
		require.NoError(t, os.WriteFile(filepath.Join(dir, f), []byte("x"), 0o600))
	}
	old := time.Now().Add(-time.Hour)
	require.NoError(t, os.Chtimes(filepath.Join(dir, "good.img"), old, old))

	removeStale(layers, dir, false)

	for _, f := range []string{"stale.img", "stale.img.partial-abc", "stale.img.partial"} {
		assert.NoFileExists(t, filepath.Join(dir, f))
	}
	for _, f := range []string{"good.img", "good.img.digest"} {
		assert.FileExists(t, filepath.Join(dir, f))
	}
}

func TestFits(t *testing.T) {
	assert.True(t, fits(100*gib, 60*gib, 15*gib))
	assert.True(t, fits(75*gib, 60*gib, 15*gib), "exactly at the floor is allowed")
	assert.False(t, fits(75*gib-1, 60*gib, 15*gib))
	assert.False(t, fits(10*gib, 60*gib, 0), "needed above free must not underflow")
}

func TestSelectEvictions(t *testing.T) {
	base := time.Unix(1000, 0)
	entries := []cacheEntry{
		{dir: "new", size: 30 * gib, lastUsed: base.Add(3 * time.Hour)},
		{dir: "busy", size: 60 * gib, lastUsed: base},
		{dir: "old", size: 30 * gib, lastUsed: base.Add(time.Hour)},
		{dir: "mid", size: 30 * gib, lastUsed: base.Add(2 * time.Hour)},
	}
	inUse := map[string]bool{"busy": true}

	t.Run("no eviction when it fits", func(t *testing.T) {
		ev, ok := selectEvictions(entries, inUse, 100*gib, 60*gib, 15*gib)
		assert.True(t, ok)
		assert.Empty(t, ev)
	})

	t.Run("least recently used first, stops once it fits, skips in-use", func(t *testing.T) {
		// free 10, need 60, floor 15: needs 65 more; old+mid = 60 not enough, new makes 90.
		ev, ok := selectEvictions(entries, inUse, 10*gib, 60*gib, 15*gib)
		assert.True(t, ok)
		assert.Equal(t, []string{"old", "mid", "new"}, dirs(ev))

		ev, ok = selectEvictions(entries, inUse, 40*gib, 60*gib, 15*gib)
		assert.True(t, ok)
		assert.Equal(t, []string{"old", "mid"}, dirs(ev))
	})

	t.Run("in-use never evicted even if that means refusing", func(t *testing.T) {
		ev, ok := selectEvictions(entries, inUse, 1*gib, 200*gib, 15*gib)
		assert.False(t, ok)
		for _, e := range ev {
			assert.NotEqual(t, "busy", e.dir)
		}
	})
}

func TestListCache(t *testing.T) {
	root := t.TempDir()
	img := filepath.Join(root, "reg", "repo", "tag")
	require.NoError(t, os.MkdirAll(img, os.ModePerm))
	require.NoError(t, os.WriteFile(filepath.Join(img, "disk.img"), make([]byte, 7), 0o600))
	require.NoError(t, os.MkdirAll(filepath.Join(root, "empty"), os.ModePerm))

	got := listCache(root)
	require.Len(t, got, 1)
	assert.Equal(t, img, got[0].dir)
	assert.GreaterOrEqual(t, got[0].size, uint64(7))

	// sparse files count by allocated bytes, not logical size
	f, err := os.Create(filepath.Join(img, "sparse.img"))
	require.NoError(t, err)
	require.NoError(t, f.Truncate(1<<40))
	require.NoError(t, f.Close())
	got = listCache(root)
	require.Len(t, got, 1)
	assert.Less(t, got[0].size, uint64(1<<20))
}

func dirs(es []cacheEntry) (out []string) {
	for _, e := range es {
		out = append(out, e.dir)
	}
	return out
}

func TestListCacheImageDirsAreLeaves(t *testing.T) {
	root := t.TempDir()
	outer := filepath.Join(root, "reg", "repo")
	inner := filepath.Join(outer, "tag")
	require.NoError(t, os.MkdirAll(inner, os.ModePerm))
	require.NoError(t, os.WriteFile(filepath.Join(outer, "disk.img"), make([]byte, 5000), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(inner, "disk.img"), make([]byte, 5000), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(root, "stray"), make([]byte, 5000), 0o600))

	got := listCache(root)
	require.Len(t, got, 1, "the cache root and anything below an image dir are not entries")
	assert.Equal(t, outer, got[0].dir)
}

func TestEvictDirKeepsNestedImage(t *testing.T) {
	root := t.TempDir()
	inner := filepath.Join(root, "tag")
	require.NoError(t, os.MkdirAll(inner, os.ModePerm))
	require.NoError(t, os.WriteFile(filepath.Join(root, "disk.img"), []byte("x"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(inner, "disk.img"), []byte("x"), 0o600))

	require.NoError(t, evictDir(root))

	assert.NoFileExists(t, filepath.Join(root, "disk.img"))
	assert.FileExists(t, filepath.Join(inner, "disk.img"), "a nested (possibly in-use) image must survive")
}

func TestReservationsCountOnlyUnwrittenBytes(t *testing.T) {
	guardMu.Lock()
	defer guardMu.Unlock()

	dir := t.TempDir()
	// 100 KiB already allocated in the dir before the pull: the baseline.
	require.NoError(t, os.WriteFile(filepath.Join(dir, "old"), make([]byte, 100<<10), 0o600))
	r := &reservation{dir: dir, needed: 1 << 30, baseline: allocatedBytes(dir)}
	reservations[r] = struct{}{}
	defer delete(reservations, r)

	assert.Equal(t, uint64(1<<30), reservedBytes(), "nothing written yet: full estimate reserved")
	assert.Equal(t, uint64(1<<30), unreserved(2<<30), "free minus the reservation")
	assert.Equal(t, uint64(0), unreserved(1<<20), "reservation above free must not underflow")

	// the pull writes 10 MiB: that is already out of free space, so it is not reserved twice.
	require.NoError(t, os.WriteFile(filepath.Join(dir, "new.partial-x"), make([]byte, 10<<20), 0o600))
	assert.Equal(t, uint64(1<<30)-(10<<20), reservedBytes())

	// written beyond the estimate never underflows.
	require.NoError(t, os.WriteFile(filepath.Join(dir, "more"), make([]byte, 2<<30), 0o600))
	assert.Equal(t, uint64(0), reservedBytes())
	assert.Equal(t, uint64(10), unreserved(10), "no reservation left, all free space is available")
}

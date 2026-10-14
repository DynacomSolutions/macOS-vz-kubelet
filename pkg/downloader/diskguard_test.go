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

	// compressed layer = temp download + unpacked output; plain layer = once.
	assert.Equal(t, uint64(10+40+5), requiredBytes(layers, dir, false))

	// an already cached output costs nothing, unless a re-pull is forced.
	require.NoError(t, os.WriteFile(filepath.Join(dir, "disk.img"), []byte("x"), 0o600))
	assert.Equal(t, uint64(5), requiredBytes(layers, dir, false))
	assert.Equal(t, uint64(55), requiredBytes(layers, dir, true))
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
	assert.Equal(t, uint64(7), got[0].size)
}

func dirs(es []cacheEntry) (out []string) {
	for _, e := range es {
		out = append(out, e.dir)
	}
	return out
}

package downloader

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/agoda-com/macOS-vz-kubelet/internal/disk"
	"github.com/agoda-com/macOS-vz-kubelet/internal/diskguard"
	"github.com/agoda-com/macOS-vz-kubelet/pkg/oci"
	"github.com/agoda-com/macOS-vz-kubelet/pkg/resource"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/virtual-kubelet/virtual-kubelet/log"
	"oras.land/oras-go/v2/content"
)

// ErrInsufficientSpace is returned when a pull would leave less free space than
// the configured floor, or when free space falls below it mid-pull.
var ErrInsufficientSpace = diskguard.ErrInsufficientSpace

// guardMu serialises estimate + eviction so concurrent pulls do not both spend
// the same free space. reservations (guarded by guardMu) are the pulls in flight.
var (
	guardMu      sync.Mutex
	reservations = map[*reservation]struct{}{}
)

// reservation is an active pull's claim on free space: its estimate, minus what it has
// already written (allocated bytes in its image dir above the baseline at start), since
// written bytes are already gone from free space.
type reservation struct {
	dir      string
	needed   uint64
	baseline uint64
}

func (r *reservation) remaining() uint64 {
	written := allocatedBytes(r.dir)
	written -= min(written, r.baseline)
	return r.needed - min(r.needed, written)
}

// reservedBytes is the total still-unwritten bytes of pulls in flight; hold guardMu.
func reservedBytes() (total uint64) {
	for r := range reservations {
		total += r.remaining()
	}
	return total
}

// unreserved returns free minus what other active pulls have yet to write.
func unreserved(free uint64) uint64 {
	return free - min(free, reservedBytes())
}

// cacheEntry is one cached image directory.
type cacheEntry = diskguard.CacheEntry

// allocatedBytes sums the allocated bytes of the regular files directly in dir.
func allocatedBytes(dir string) uint64 { return diskguard.AllocatedBytes(dir) }

// freeBytes reports the space available to unprivileged writers on the volume holding path.
func freeBytes(path string) (uint64, error) { return diskguard.FreeBytes(path) }

// wantDigest is the digest the layer output must have: the uncompressed digest for a
// compressed layer, else the layer digest. It is what the sidecar records.
func wantDigest(l ocispec.Descriptor) string {
	if d := l.Annotations[oci.AnnotationUncompressedDigest]; d != "" {
		return d
	}
	return l.Digest.String()
}

// isCached reports whether the layer output is already in dir and validated: its
// digest sidecar is newer than the file (the test ValidateFileWithDigest uses to skip
// rehashing) and records the expected digest, so a re-pushed tag is not taken for the
// old content. A bare file with no sidecar is a partial from an aborted pull.
func isCached(l ocispec.Descriptor, dir string) bool {
	return oci.IsCached(l, dir)
}

// imageLocks serialises pulls per image dir, so two pulls of the same dir never overlap
// and reservation attribution (bytes written in the dir) is exact.
var (
	imageLocksMu sync.Mutex
	imageLocks   = map[string]chan struct{}{}
)

// lockImage waits for any other pull of dir to finish, then claims it. The returned
// func releases it.
func lockImage(ctx context.Context, dir string) (func(), error) {
	imageLocksMu.Lock()
	ch, ok := imageLocks[dir]
	if !ok {
		ch = make(chan struct{}, 1)
		imageLocks[dir] = ch
	}
	imageLocksMu.Unlock()
	select {
	case ch <- struct{}{}:
		return func() { <-ch }, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// requiredBytes is the peak extra disk a pull of layers needs. A compressed layer is
// streamed through gzip into its output, so it costs its uncompressed size only (the
// annotation is the logical size, an upper bound as zero blocks stay sparse); a plain
// layer costs its size. Layers already cached and validated cost nothing unless
// ignoreExisting forces a re-pull. Stale outputs of layers that will be pulled are
// removed by ensureSpace first, so they are not counted twice.
func requiredBytes(layers []ocispec.Descriptor, workingDir string, ignoreExisting bool) uint64 {
	var total uint64
	for _, l := range layers {
		if !ignoreExisting && isCached(l, workingDir) {
			continue
		}
		_, hasDigest := l.Annotations[oci.AnnotationUncompressedDigest]
		if u, err := oci.ParseUncompressedSize(l.Annotations[oci.AnnotationUncompressedSize]); err == nil && hasDigest {
			total += uint64(u)
		} else {
			total += uint64(max(l.Size, 0)) // nolint: gosec
		}
	}
	return total
}

// removeStale deletes outputs (and leftover .partial-* files) of layers about to be
// pulled: they are invalid or being replaced, and would otherwise hold disk twice.
func removeStale(layers []ocispec.Descriptor, dir string, ignoreExisting bool) {
	// A local image may have no registry copy. Keep its layers until replacement succeeds.
	if oci.HasLocalManifest(dir) {
		return
	}
	for _, l := range layers {
		name := l.Annotations[ocispec.AnnotationTitle]
		if name == "" || (!ignoreExisting && isCached(l, dir)) {
			continue
		}
		for _, f := range []string{name, name + disk.DigestFileSuffix, name + ".partial"} { // .partial: v8 fixed name
			_ = os.Remove(filepath.Join(dir, f))
		}
		partials, _ := filepath.Glob(filepath.Join(dir, name+".partial-*"))
		for _, f := range partials {
			_ = os.Remove(f)
		}
	}
}

// fits reports whether free space after writing needed bytes stays at or above floor.
func fits(free, needed, floor uint64) bool { return diskguard.Fits(free, needed, floor) }

// selectEvictions, listCache and evictDir are shared with the one-shot importer.
func selectEvictions(entries []cacheEntry, inUse map[string]bool, free, needed, floor uint64) ([]cacheEntry, bool) {
	return diskguard.SelectEvictions(entries, inUse, free, needed, floor)
}

func listCache(root string) []cacheEntry { return diskguard.ListCache(root) }

func evictDir(dir string) error { return diskguard.EvictDir(dir) }

// fetchLayers reads the image manifest and returns its layers, all with safe titles.
// Image indexes are refused: the pull would copy every platform and the size cannot be
// bounded up front.
func fetchLayers(ctx context.Context, ref string, creds resource.RegistryCredentials) (ocispec.Descriptor, []ocispec.Descriptor, error) {
	repo, err := newRepository(ref, creds)
	if err != nil {
		return ocispec.Descriptor{}, nil, err
	}
	desc, rc, err := repo.FetchReference(ctx, repo.Reference.Reference)
	if err != nil {
		return desc, nil, fmt.Errorf("failed to fetch manifest: %w", err)
	}
	defer rc.Close()
	if desc.MediaType != ocispec.MediaTypeImageManifest {
		return desc, nil, fmt.Errorf("unsupported manifest media type %q: image indexes are not supported", desc.MediaType)
	}
	b, err := content.ReadAll(rc, desc)
	if err != nil {
		return desc, nil, fmt.Errorf("failed to read manifest: %w", err)
	}
	var m ocispec.Manifest
	if err := json.Unmarshal(b, &m); err != nil {
		return desc, nil, fmt.Errorf("failed to decode manifest: %w", err)
	}
	for _, l := range m.Layers {
		if err := oci.ValidateTitle(l); err != nil {
			return desc, nil, err
		}
		if v, ok := l.Annotations[oci.AnnotationUncompressedSize]; ok {
			if _, err := oci.ParseUncompressedSize(v); err != nil {
				return desc, nil, err
			}
		}
	}
	return desc, m.Layers, nil
}

// ensureSpace refuses the pull unless it fits above the floor, evicting unused
// cached images (LRU first) when that makes it fit. On success the pull's estimate is
// reserved until the returned release is called.
func ensureSpace(ctx context.Context, params Params, imageDir string) (release func(), pin string, err error) {
	guardMu.Lock()
	defer guardMu.Unlock()

	desc, layers, err := fetchLayers(ctx, params.Ref, params.Credentials)
	if err != nil {
		return nil, "", err
	}
	removeStale(layers, imageDir, params.IgnoreExisiting)
	needed := requiredBytes(layers, imageDir, params.IgnoreExisiting)
	root := filepath.Join(params.StorePath, "blobs")
	if err := os.MkdirAll(root, os.ModePerm); err != nil {
		return nil, "", err
	}
	free, err := freeBytes(root)
	if err != nil {
		return nil, "", fmt.Errorf("failed to read free disk space: %w", err)
	}
	logger := log.G(ctx)
	avail := unreserved(free)
	refuse := func(avail uint64) (func(), string, error) {
		logger.Warnf("Disk guard for %s: need %d bytes, %d available (%d free, %d reserved), floor %d: refusing", params.Ref, needed, avail, free, reservedBytes(), params.MinFreeBytes)
		return nil, "", fmt.Errorf("%w: pull of %s needs %d bytes, %d available, floor %d, and no unused cached image can be evicted to make room",
			ErrInsufficientSpace, params.Ref, needed, avail, params.MinFreeBytes)
	}
	if fits(avail, needed, params.MinFreeBytes) {
		logger.Infof("Disk guard for %s: need %d bytes, %d available (%d free, %d reserved), floor %d: pulling without eviction", params.Ref, needed, avail, free, reservedBytes(), params.MinFreeBytes)
	} else {
		protected := map[string]bool{imageDir: true}
		if params.InUse != nil {
			for _, d := range params.InUse() {
				protected[d] = true
			}
		}
		evict, ok := selectEvictions(listCache(root), protected, avail, needed, params.MinFreeBytes)
		if !ok {
			return refuse(avail)
		}
		logger.Infof("Disk guard for %s: need %d bytes, %d available (%d free, %d reserved), floor %d: evicting %d unused image(s)", params.Ref, needed, avail, free, reservedBytes(), params.MinFreeBytes, len(evict))
		for _, e := range evict {
			logger.Warnf("Evicting unused cached image %s (%d bytes, last used %s) to free space for %s", e.Dir, e.Size, e.LastUsed.Format(time.RFC3339), params.Ref)
			if err := evictDir(e.Dir); err != nil {
				return nil, "", fmt.Errorf("failed to evict %s: %w", e.Dir, err)
			}
		}
		// Re-measure: snapshots can keep deleted blocks allocated.
		if free, err = freeBytes(root); err != nil {
			return nil, "", fmt.Errorf("failed to read free disk space: %w", err)
		}
		avail = unreserved(free)
		if !fits(avail, needed, params.MinFreeBytes) {
			return refuse(avail)
		}
	}

	r := &reservation{dir: imageDir, needed: needed, baseline: allocatedBytes(imageDir)}
	reservations[r] = struct{}{}
	return func() {
		guardMu.Lock()
		defer guardMu.Unlock()
		delete(reservations, r)
	}, desc.Digest.String(), nil
}

// watchFreeSpace cancels the returned context with ErrInsufficientSpace if free
// space on path drops below floor. Call stop when the pull is done.
func watchFreeSpace(ctx context.Context, path string, floor uint64) (context.Context, func()) {
	return diskguard.WatchFreeSpace(ctx, path, floor)
}

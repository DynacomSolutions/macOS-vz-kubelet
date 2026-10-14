package downloader

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"syscall"
	"time"

	"github.com/agoda-com/macOS-vz-kubelet/internal/disk"
	"github.com/agoda-com/macOS-vz-kubelet/pkg/oci"
	"github.com/agoda-com/macOS-vz-kubelet/pkg/resource"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/virtual-kubelet/virtual-kubelet/log"
	"oras.land/oras-go/v2/content"
)

// ErrInsufficientSpace is returned when a pull would leave less free space than
// the configured floor, or when free space falls below it mid-pull.
var ErrInsufficientSpace = errors.New("insufficient free disk space")

// diskPollInterval is how often free space is checked during a pull.
const diskPollInterval = time.Second

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

// allocatedBytes sums the allocated bytes of the regular files directly in dir
// (allocated, not logical: decompressed disks are sparse).
func allocatedBytes(dir string) (total uint64) {
	files, _ := os.ReadDir(dir)
	for _, f := range files {
		if info, err := f.Info(); err == nil && f.Type().IsRegular() {
			if st, ok := info.Sys().(*syscall.Stat_t); ok {
				total += uint64(st.Blocks) * 512 // nolint: gosec
			} else {
				total += uint64(info.Size()) // nolint: gosec
			}
		}
	}
	return total
}

// cacheEntry is one cached image directory.
type cacheEntry struct {
	dir      string
	size     uint64
	lastUsed time.Time
}

// freeBytes reports the space available to unprivileged writers on the volume holding path.
func freeBytes(path string) (uint64, error) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil {
		return 0, err
	}
	return uint64(st.Bsize) * uint64(st.Bavail), nil // nolint: gosec
}

// isCached reports whether the layer output is already in dir and validated: its
// digest sidecar is newer than the file, the same test ValidateFileWithDigest uses to
// skip rehashing. A bare file with no sidecar is a partial from an aborted pull.
func isCached(l ocispec.Descriptor, dir string) bool {
	name := l.Annotations[ocispec.AnnotationTitle]
	if name == "" {
		return false
	}
	fi, err := os.Stat(filepath.Join(dir, name))
	if err != nil {
		return false
	}
	si, err := os.Stat(filepath.Join(dir, name+disk.DigestFileSuffix))
	return err == nil && si.ModTime().After(fi.ModTime())
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
func fits(free, needed, floor uint64) bool {
	return free >= needed && free-needed >= floor
}

// selectEvictions picks cached images to delete, least recently used first, never
// one in inUse, until needed fits above floor. ok is false if even evicting every
// candidate is not enough (the caller should then evict nothing).
func selectEvictions(entries []cacheEntry, inUse map[string]bool, free, needed, floor uint64) (evict []cacheEntry, ok bool) {
	var cands []cacheEntry
	for _, e := range entries {
		if !inUse[e.dir] {
			cands = append(cands, e)
		}
	}
	sort.SliceStable(cands, func(i, j int) bool { return cands[i].lastUsed.Before(cands[j].lastUsed) })
	for _, e := range cands {
		if fits(free, needed, floor) {
			break
		}
		evict = append(evict, e)
		free += e.size
	}
	return evict, fits(free, needed, floor)
}

// listCache returns every image directory under root: a directory that directly
// holds files. Image directories are leaves; nothing below one is listed.
func listCache(root string) (entries []cacheEntry) {
	_ = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil || !d.IsDir() || p == root {
			return nil
		}
		e := cacheEntry{dir: p, size: allocatedBytes(p)}
		if e.size == 0 {
			return nil
		}
		if info, err := d.Info(); err == nil {
			e.lastUsed = info.ModTime()
		}
		entries = append(entries, e)
		return fs.SkipDir
	})
	return entries
}

// evictDir removes the files directly inside an image directory, then the directory
// itself if it is now empty. It never recurses, so a nested image directory survives.
func evictDir(dir string) error {
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
	_ = os.Remove(dir)
	return nil
}

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
			logger.Warnf("Evicting unused cached image %s (%d bytes, last used %s) to free space for %s", e.dir, e.size, e.lastUsed.Format(time.RFC3339), params.Ref)
			if err := evictDir(e.dir); err != nil {
				return nil, "", fmt.Errorf("failed to evict %s: %w", e.dir, err)
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
	ctx, cancel := context.WithCancelCause(ctx)
	if floor == 0 {
		return ctx, func() { cancel(nil) }
	}
	done := make(chan struct{})
	go func() {
		t := time.NewTicker(diskPollInterval)
		defer t.Stop()
		for {
			select {
			case <-done:
				return
			case <-ctx.Done():
				return
			case <-t.C:
				if free, err := freeBytes(path); err == nil && free < floor {
					cancel(fmt.Errorf("%w: %d bytes free, floor %d; pull aborted", ErrInsufficientSpace, free, floor))
					return
				}
			}
		}
	}()
	return ctx, func() { close(done); cancel(nil) }
}

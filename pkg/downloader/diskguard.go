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
	"strconv"
	"sync"
	"syscall"
	"time"

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
const diskPollInterval = 5 * time.Second

// guardMu serialises estimate + eviction so concurrent pulls do not both spend
// the same free space.
var guardMu sync.Mutex

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

// requiredBytes is the peak extra disk a pull of layers needs. A compressed layer
// is downloaded to a temp file (kept until the store closes) and then decompressed
// to its output, so it costs compressed + uncompressed size; a plain layer costs its
// size once. Layers whose output file already exists are skipped unless ignoreExisting
// (assumes they validate; an invalid one is re-pulled and caught by the mid-pull poll).
func requiredBytes(layers []ocispec.Descriptor, workingDir string, ignoreExisting bool) uint64 {
	var total uint64
	for _, l := range layers {
		if name := l.Annotations[ocispec.AnnotationTitle]; name != "" && !ignoreExisting {
			if _, err := os.Stat(filepath.Join(workingDir, name)); err == nil {
				continue
			}
		}
		total += uint64(max(l.Size, 0)) // nolint: gosec
		_, hasDigest := l.Annotations[oci.AnnotationUncompressedDigest]
		if u, err := strconv.ParseUint(l.Annotations[oci.AnnotationUncompressedSize], 10, 64); err == nil && hasDigest {
			total += u
		}
	}
	return total
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

// listCache returns every directory under root that directly holds files.
func listCache(root string) (entries []cacheEntry) {
	_ = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil || !d.IsDir() {
			return nil
		}
		files, err := os.ReadDir(p)
		if err != nil {
			return nil
		}
		e := cacheEntry{dir: p}
		for _, f := range files {
			if info, err := f.Info(); err == nil && f.Type().IsRegular() {
				e.size += uint64(info.Size()) // nolint: gosec
			}
		}
		if e.size > 0 {
			if info, err := d.Info(); err == nil {
				e.lastUsed = info.ModTime()
			}
			entries = append(entries, e)
		}
		return nil
	})
	return entries
}

// fetchLayers reads the image manifest and returns its layers. An image index
// yields none, so the estimate is 0 and only the mid-pull poll protects it.
func fetchLayers(ctx context.Context, ref string, creds resource.RegistryCredentials) ([]ocispec.Descriptor, error) {
	repo, err := newRepository(ref, creds)
	if err != nil {
		return nil, err
	}
	desc, rc, err := repo.FetchReference(ctx, repo.Reference.Reference)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch manifest: %w", err)
	}
	defer rc.Close()
	b, err := content.ReadAll(rc, desc)
	if err != nil {
		return nil, fmt.Errorf("failed to read manifest: %w", err)
	}
	var m ocispec.Manifest
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, fmt.Errorf("failed to decode manifest: %w", err)
	}
	return m.Layers, nil
}

// ensureSpace refuses the pull unless it fits above the floor, evicting unused
// cached images (LRU first) when that makes it fit.
func ensureSpace(ctx context.Context, params Params, imageDir string) error {
	guardMu.Lock()
	defer guardMu.Unlock()

	layers, err := fetchLayers(ctx, params.Ref, params.Credentials)
	if err != nil {
		return err
	}
	needed := requiredBytes(layers, imageDir, params.IgnoreExisiting)
	root := filepath.Join(params.StorePath, "blobs")
	if err := os.MkdirAll(root, os.ModePerm); err != nil {
		return err
	}
	free, err := freeBytes(root)
	if err != nil {
		return fmt.Errorf("failed to read free disk space: %w", err)
	}
	if fits(free, needed, params.MinFreeBytes) {
		return nil
	}

	protected := map[string]bool{imageDir: true}
	for _, d := range params.InUse {
		protected[d] = true
	}
	evict, ok := selectEvictions(listCache(root), protected, free, needed, params.MinFreeBytes)
	if !ok {
		return fmt.Errorf("%w: pull of %s needs %d bytes, %d free, floor %d, and no unused cached image can be evicted to make room",
			ErrInsufficientSpace, params.Ref, needed, free, params.MinFreeBytes)
	}
	for _, e := range evict {
		log.G(ctx).Warnf("Evicting unused cached image %s (%d bytes, last used %s) to free space for %s", e.dir, e.size, e.lastUsed.Format(time.RFC3339), params.Ref)
		if err := os.RemoveAll(e.dir); err != nil {
			return fmt.Errorf("failed to evict %s: %w", e.dir, err)
		}
	}
	return nil
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

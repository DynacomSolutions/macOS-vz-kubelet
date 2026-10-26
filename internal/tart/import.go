package tart

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/agoda-com/macOS-vz-kubelet/internal/buildutil"
	"github.com/agoda-com/macOS-vz-kubelet/internal/diskguard"
	"github.com/agoda-com/macOS-vz-kubelet/pkg/oci"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/virtual-kubelet/virtual-kubelet/log"
	"oras.land/oras-go/v2/registry/remote"
	"oras.land/oras-go/v2/registry/remote/auth"
)

type Options struct {
	Source, Destination, CacheDir             string
	SourceCredentials, DestinationCredentials buildutil.Credentials
	MinFreeBytes                              uint64
	Local                                     bool
	// Evict lets the import delete least-recently-used cached images to make room. The
	// caller must ensure no Pod uses the cache: nothing here can see running VMs.
	Evict bool
	// Keep lists image references that eviction must never delete.
	Keep []string
	// IgnoreRecent lets eviction also delete images used within recentUse (never --keep refs, the destination or
	// local-only imports). The caller must ensure no VM runs: the importer cannot see them.
	IgnoreRecent bool
	// FreeTargetBytes, when above MinFreeBytes, makes the import evict (needs Evict) until at least this much is
	// free before it downloads, because requiredSpace counts only non-zero chunks and has been seen to underestimate.
	FreeTargetBytes uint64
}

// recentUse protects cached images used within this window: pulls and Pod starts
// touch the image directory, and the one-shot importer cannot see running Pods.
const recentUse = 24 * time.Hour

// verifiedCopy bounds the read and verifies both the size and digest, including for
// registries that do not validate blob downloads themselves.
func verifiedCopy(src io.Reader, d ocispec.Descriptor, consume func(io.Reader) error) error {
	if err := d.Digest.Validate(); err != nil {
		return err
	}
	if d.Size < 0 || d.Size == int64(^uint64(0)>>1) {
		return fmt.Errorf("invalid blob size")
	}
	v := d.Digest.Verifier()
	r := &countReader{Reader: io.TeeReader(io.LimitReader(src, d.Size+1), v)}
	if err := consume(r); err != nil {
		return err
	}
	if _, err := io.Copy(io.Discard, r); err != nil {
		return err
	}
	if r.n != d.Size || !v.Verified() {
		return fmt.Errorf("blob %s size or digest mismatch", d.Digest)
	}
	return nil
}

type countReader struct {
	io.Reader
	n int64
}

func (r *countReader) Read(b []byte) (int, error) {
	n, err := r.Reader.Read(b)
	r.n += int64(n)
	return n, err
}

type blobSource interface {
	Fetch(context.Context, ocispec.Descriptor) (io.ReadCloser, error)
}

func fetch(ctx context.Context, repo blobSource, d ocispec.Descriptor, consume func(io.Reader) error) error {
	r := &retryReader{ctx: ctx, source: repo, desc: d}
	defer r.Close()
	return verifiedCopy(r, d, consume)
}

// Run imports into a private build directory and uses the same push pipeline as
// build-image. Source credentials are separate to avoid sending destination secrets
// to the public registry. It never boots a VM or changes the guest's SSH settings.
func Run(ctx context.Context, o Options) (result buildutil.PushResult, err error) {
	dst, err := remote.NewRepository(o.Destination)
	if err != nil {
		return result, err
	}
	if dst.Reference.Reference == "" || strings.Contains(o.Destination, "@") {
		return result, fmt.Errorf("destination must be name:tag")
	}
	repo, err := remote.NewRepository(o.Source)
	if err != nil {
		return result, err
	}
	if repo.Reference.Reference == "" || o.Source == o.Destination {
		return result, fmt.Errorf("source needs a tag or digest and must differ from destination")
	}
	repo.Client = &auth.Client{Cache: auth.NewCache(), Credential: auth.StaticCredential(repo.Reference.Registry, auth.Credential{
		Username: o.SourceCredentials.Username, Password: o.SourceCredentials.Password, RefreshToken: o.SourceCredentials.IdentityToken,
	})}
	if !filepath.IsAbs(o.CacheDir) {
		return result, fmt.Errorf("cache directory must be absolute")
	}
	if o.Local {
		dir, err := oci.ImageDir(o.CacheDir, o.Destination)
		if err != nil {
			return result, err
		}
		if _, err := os.Lstat(dir); !os.IsNotExist(err) {
			return result, fmt.Errorf("local destination already exists or cannot be inspected: %s", dir)
		}
	}
	bd, err := buildutil.NewBuildDir(filepath.Join(o.CacheDir, "build"))
	if err != nil {
		return result, err
	}
	defer func() { err = errors.Join(err, bd.Close()) }()
	desc, rc, err := repo.FetchReference(ctx, repo.Reference.Reference)
	if err != nil {
		return result, err
	}
	var data bytes.Buffer
	if strings.Contains(o.Source, "@") && desc.Digest.String() != repo.Reference.Reference {
		rc.Close()
		return result, fmt.Errorf("source manifest does not match the pinned digest")
	}
	if desc.MediaType != ocispec.MediaTypeImageManifest || desc.Size > maxMetadataSize {
		rc.Close()
		return result, fmt.Errorf("expected a bounded OCI image manifest, not an index")
	}
	err = verifiedCopy(rc, desc, func(r io.Reader) error { _, e := io.Copy(&data, r); return e })
	rc.Close()
	if err != nil {
		return result, err
	}
	m, err := ParseManifest(data.Bytes())
	if err != nil {
		return result, err
	}
	free, err := diskguard.FreeBytes(bd.Dir())
	if err != nil {
		return result, err
	}
	needed, err := requiredSpace(m)
	if err != nil {
		return result, err
	}
	if o.FreeTargetBytes > o.MinFreeBytes && o.FreeTargetBytes-o.MinFreeBytes > needed {
		needed = o.FreeTargetBytes - o.MinFreeBytes
	}
	if !diskguard.Fits(free, needed, o.MinFreeBytes) {
		if !o.Evict {
			return result, fmt.Errorf("%w: import needs %d bytes plus floor %d, available %d (--evict can remove unused cached images when no Pod is running)", diskguard.ErrInsufficientSpace, needed, o.MinFreeBytes, free)
		}
		if err := makeRoom(ctx, o, func() (uint64, error) { return diskguard.FreeBytes(bd.Dir()) }, needed); err != nil {
			return result, err
		}
	}
	ctx, stop := diskguard.WatchFreeSpace(ctx, bd.Dir(), o.MinFreeBytes)
	defer stop()
	defer func() {
		if err != nil && context.Cause(ctx) != nil {
			err = errors.Join(err, context.Cause(ctx))
		}
	}()
	// Verify the OCI config blob too, even though it is not the VM configuration.
	var raw ocispec.Manifest
	if err := json.Unmarshal(data.Bytes(), &raw); err != nil {
		return result, err
	}
	if raw.Config.Size < 0 || raw.Config.Size > maxMetadataSize {
		return result, fmt.Errorf("oversized OCI config")
	}
	if err := fetch(ctx, repo, raw.Config, func(r io.Reader) error { _, e := io.Copy(io.Discard, r); return e }); err != nil {
		return result, err
	}
	data.Reset()
	if err := fetch(ctx, repo, m.Config, func(r io.Reader) error { _, e := io.Copy(&data, r); return e }); err != nil {
		return result, err
	}
	cfg, err := ConvertConfig(data.Bytes())
	if err != nil {
		return result, err
	}
	cfgBytes, err := json.Marshal(&cfg)
	if err != nil {
		return result, err
	}
	configPath, _ := bd.Path("config.json")
	if err := os.WriteFile(configPath, cfgBytes, 0o600); err != nil {
		return result, err
	}
	auxPath, _ := bd.Path("aux.img")
	if err := writeFile(auxPath, func(f *os.File) error {
		return fetch(ctx, repo, m.NVRAM, func(r io.Reader) error { _, e := io.Copy(f, r); return e })
	}); err != nil {
		return result, err
	}
	diskPath, _ := bd.Path("disk.img")
	if err := writeFile(diskPath, func(f *os.File) error {
		for i, d := range m.Disks {
			log.G(ctx).Infof("Importing Tart disk chunk %d/%d", i+1, len(m.Disks))
			n, h, err := chunkInfo(d)
			if err != nil {
				return err
			}
			if err := fetch(ctx, repo, d, func(r io.Reader) error { return decodeChunk(ctx, r, f, n, h) }); err != nil {
				return fmt.Errorf("chunk %d: %w", i+1, err)
			}
		}
		return f.Truncate(m.DiskSize) // extends a final hole without allocating blocks
	}); err != nil {
		return result, err
	}
	opts := buildutil.PushOptions{Ref: o.Destination, Creds: o.DestinationCredentials, Disk: diskPath, Aux: auxPath, Config: configPath,
		Annotations: map[string]string{"org.cirruslabs.tart.source-manifest": desc.Digest.String()},
	}
	if o.Local {
		return buildutil.CacheLocal(ctx, opts, o.CacheDir)
	}
	return buildutil.Push(ctx, opts)
}

func writeFile(path string, write func(*os.File) error) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600)
	if err != nil {
		return err
	}
	err = write(f)
	return errors.Join(err, f.Close())
}

// makeRoom evicts least-recently-used cached images until the import fits. It never
// evicts the destination, a local-only import, a --keep reference or, unless IgnoreRecent, an image used
// within recentUse. If the remaining candidates cannot free enough, it evicts nothing
// and fails. free reads the build directory's volume.
func makeRoom(ctx context.Context, o Options, free func() (uint64, error), needed uint64) error {
	dst, err := oci.ImageDir(o.CacheDir, o.Destination)
	if err != nil {
		return err
	}
	root := filepath.Join(o.CacheDir, "blobs")
	protected := map[string]bool{dst: true}
	for _, ref := range o.Keep {
		dir, err := oci.ImageDir(o.CacheDir, ref)
		if err != nil {
			return fmt.Errorf("invalid --keep reference %q: %w", ref, err)
		}
		protected[dir] = true
	}
	for _, e := range diskguard.ListCache(root) {
		if !o.IgnoreRecent && time.Since(e.LastUsed) < recentUse {
			protected[e.Dir] = true
		}
	}
	return diskguard.MakeRoom(ctx, root, protected, needed, o.MinFreeBytes, free)
}

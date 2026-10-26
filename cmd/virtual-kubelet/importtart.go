package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/agoda-com/macOS-vz-kubelet/internal/buildutil"
	"github.com/agoda-com/macOS-vz-kubelet/internal/envcfg"
	"github.com/agoda-com/macOS-vz-kubelet/internal/tart"
	"github.com/sirupsen/logrus"
	"github.com/virtual-kubelet/virtual-kubelet/log"
	logruslogger "github.com/virtual-kubelet/virtual-kubelet/log/logrus"
)

type keepFlag []string

func (k *keepFlag) String() string     { return strings.Join(*k, ",") }
func (k *keepFlag) Set(v string) error { *k = append(*k, v); return nil }

func importTartMain(args []string) int {
	fs := flag.NewFlagSet("import-tart", flag.ContinueOnError)
	local := fs.Bool("local", false, "import into the provider cache without pushing to the destination registry")
	src := fs.String("src", "", "Tart OCI source name:tag or name@sha256:digest (anonymous by default)")
	to := fs.String("to", "", "destination macos-vz OCI name:tag")
	creds := fs.String("creds", "", "destination registry credentials JSON file (optional)")
	srcCreds := fs.String("src-creds", "", "source registry credentials JSON file (optional, separate from destination)")
	evict := fs.Bool("evict", false, "if space is short, delete least-recently-used cached images (never --keep refs or images used in the last 24h)")
	ignoreRecent := fs.Bool("evict-ignore-recent", false, "with --evict, also delete images used in the last 24h (never --keep refs; only when no VM runs)")
	freeTargetGiB := fs.Uint64("free-target-gib", 0, "with --evict, evict until at least this many GiB are free before downloading (the size estimate can be low); fails with nothing evicted if impossible")
	removeOnly := fs.Bool("remove-only", false, "delete the local-only import named by --to from the cache and exit (nothing is downloaded; only when no VM runs)")
	var keep keepFlag
	fs.Var(&keep, "keep", "image reference eviction must never delete (repeatable)")
	cache := fs.String("cache-dir", "", "absolute working cache directory (default: provider cache)")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if *to == "" || fs.NArg() != 0 || (*src == "" && !*removeOnly) {
		fs.Usage()
		return 2
	}
	fail := func(err error) int { fmt.Fprintln(os.Stderr, err); return 1 }
	load := func(path string) (buildutil.Credentials, error) {
		if path == "" {
			return buildutil.Credentials{}, nil
		}
		b, err := buildutil.ReadFile(path, buildutil.FilePolicy{MaxSize: 64 << 10, OwnerUID: uint32(os.Getuid()), ForbidBit: 0o077})
		if err != nil {
			return buildutil.Credentials{}, err
		}
		return buildutil.ParseCredentials(b)
	}
	destAuth, err := load(*creds)
	if err != nil {
		return fail(err)
	}
	sourceAuth, err := load(*srcCreds)
	if err != nil {
		return fail(err)
	}
	if *cache == "" {
		base, err := os.UserCacheDir()
		if err != nil {
			return fail(err)
		}
		*cache = filepath.Join(base, appIdentifier)
	}
	if *removeOnly {
		if err := tart.RemoveLocal(*cache, *to); err != nil {
			return fail(err)
		}
		fmt.Fprintf(os.Stdout, "Removed %s\n", *to)
		return 0
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	log.L = logruslogger.FromLogrus(logrus.NewEntry(logrus.New()))
	ctx = log.WithLogger(ctx, log.L)
	result, err := tart.Run(ctx, tart.Options{Source: *src, Destination: *to, CacheDir: *cache, SourceCredentials: sourceAuth, DestinationCredentials: destAuth, MinFreeBytes: envcfg.MinFreeBytes(), Local: *local, Evict: *evict, Keep: keep, IgnoreRecent: *ignoreRecent, FreeTargetBytes: *freeTargetGiB << 30})
	if err != nil {
		return fail(err)
	}
	fmt.Fprintf(os.Stdout, "Imported %s: %s\n", *to, result.ManifestDigest)
	return 0
}

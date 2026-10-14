package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/agoda-com/macOS-vz-kubelet/internal/envcfg"
	"github.com/agoda-com/macOS-vz-kubelet/pkg/imagebuild"

	"github.com/sirupsen/logrus"
	"github.com/virtual-kubelet/virtual-kubelet/log"
	logruslogger "github.com/virtual-kubelet/virtual-kubelet/log/logrus"
)

const buildImageUsage = `usage: MacOSVK build-image --from <ref> --to <ref> --script <file> --registry-creds-file <file> [flags]

Builds a new macOS image from one already in the provider cache: boots an APFS clone of it,
runs the script in the guest as the VZ_SSH_USER user, stops the VM from the host and streams
the result to the registry. Must run as root. Needs VZ_ALLOWED_IMAGE_PREFIXES, VZ_SSH_USER and
VZ_SSH_PRIVATE_KEY_PATH (or _BASE64); honours VZ_MIN_FREE_BYTES and VZ_BRIDGE_INTERFACE.
Refuses to run while any virtual machine is running on the host.
`

// buildImageMain runs the build-image subcommand and returns the process exit code.
func buildImageMain(args []string) int {
	fs := flag.NewFlagSet("build-image", flag.ContinueOnError)
	var (
		from      = fs.String("from", "", "cached base image reference (name:tag)")
		to        = fs.String("to", "", "image reference to push (name:tag)")
		script    = fs.String("script", "", "absolute path of the provisioning script (root-owned, not group/other writable)")
		creds     = fs.String("registry-creds-file", "", "absolute path of a root-only (0600) JSON file with username and password, or identityToken")
		cacheDir  = fs.String("cache-dir", "", "provider cache directory (default: the provider's)")
		cpu       = fs.Uint("cpu", 4, "virtual CPUs of the build VM")
		memoryGiB = fs.Uint64("memory-gib", 8, "memory of the build VM in GiB")
		growthGiB = fs.Uint64("expected-growth-gib", 10, "disk growth of the clone expected from the script, in GiB")
		timeout   = fs.Duration("script-timeout", 3*time.Hour, "maximum run time of the script")
		logLevel  = fs.String("log-level", "info", "log level")
	)
	fs.SetOutput(os.Stderr)
	fs.Usage = func() { fmt.Fprint(os.Stderr, buildImageUsage); fs.PrintDefaults() }
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *from == "" || *to == "" || *script == "" || *creds == "" {
		fs.Usage()
		return 2
	}
	if os.Geteuid() != 0 {
		fmt.Fprintln(os.Stderr, "build-image must run as root")
		return 1
	}

	lvl, err := logrus.ParseLevel(*logLevel)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	logger := logrus.New()
	logger.SetLevel(lvl)
	log.L = logruslogger.FromLogrus(logrus.NewEntry(logger))
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	ctx = log.WithLogger(ctx, log.L)

	prefixes, err := envcfg.AllowedImagePrefixes()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	dir := *cacheDir
	if dir == "" {
		base, err := os.UserCacheDir()
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		dir = filepath.Join(base, appIdentifier)
	}
	if !filepath.IsAbs(dir) {
		fmt.Fprintln(os.Stderr, "--cache-dir must be absolute")
		return 2
	}

	err = imagebuild.Run(ctx, imagebuild.Options{
		From: *from, To: *to, ScriptPath: *script, CredsPath: *creds, CacheDir: filepath.Clean(dir),
		Prefixes:         prefixes,
		MinFreeBytes:     envcfg.MinFreeBytes(),
		ExpectedGrowth:   *growthGiB << 30,
		OwnerUID:         0,
		CPU:              *cpu,
		MemoryBytes:      *memoryGiB << 30,
		NetworkInterface: os.Getenv("VZ_BRIDGE_INTERFACE"),
		ScriptTimeout:    *timeout,
	})
	if err != nil {
		if errors.Is(err, context.Canceled) {
			fmt.Fprintln(os.Stderr, "build-image: cancelled")
		} else {
			fmt.Fprintln(os.Stderr, "build-image failed:", err)
		}
		return 1
	}
	return 0
}

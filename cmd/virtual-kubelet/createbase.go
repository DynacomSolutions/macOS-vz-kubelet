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

	"github.com/agoda-com/macOS-vz-kubelet/internal/buildutil"
	"github.com/agoda-com/macOS-vz-kubelet/internal/envcfg"
	"github.com/agoda-com/macOS-vz-kubelet/pkg/imagebuild"

	"github.com/sirupsen/logrus"
	"github.com/virtual-kubelet/virtual-kubelet/log"
	logruslogger "github.com/virtual-kubelet/virtual-kubelet/log/logrus"
)

const createBaseUsage = `usage: MacOSVK create-base --ipsw-url <url> --ipsw-sha256 <hex> --to ` + buildutil.BaseRefPrefix + `<name>:<tag> --script <file> --creds <file> [flags]

Builds a vanilla macOS base image from an Apple IPSW: downloads it (HTTPS) and verifies the SHA-256,
installs it with Virtualization.framework, creates the user admin (password from guest_password in the
credentials JSON) with passwordless sudo and key-only sshd, runs the script in the guest, stops the VM
from the host and pushes the result. Must run as root. Needs VZ_SSH_USER=admin and VZ_SSH_PRIVATE_KEY_PATH
(or _BASE64); honours VZ_MIN_FREE_BYTES and VZ_BRIDGE_INTERFACE. The credentials JSON is
{"username","password","guest_password"} (or identityToken instead of username and password).
With --recovery-sip-off the seeded guest is first started once in macOS Recovery, where a keystroke
script (built in, or --recovery-script) turns off SIP and authenticated-root; the guest then boots normally.
Refuses to run while a macOS virtual machine owned by root or a --count-vm-user user is running.
`

// createBaseMain runs the create-base subcommand and returns the process exit code.
func createBaseMain(args []string) int {
	fs := flag.NewFlagSet("create-base", flag.ContinueOnError)
	var (
		ipswURL   = fs.String("ipsw-url", "", "HTTPS URL of the Apple IPSW")
		ipswSHA   = fs.String("ipsw-sha256", "", "expected SHA-256 of the IPSW (64 lower-case hex digits)")
		to        = fs.String("to", "", "image reference to push, under "+buildutil.BaseRefPrefix)
		script    = fs.String("script", "", "absolute path of the provisioning script (root-owned, not group/other writable)")
		creds     = fs.String("creds", "", "absolute path of a root-only (0600) JSON file with username, password and guest_password")
		cacheDir  = fs.String("cache-dir", "", "provider cache directory (default: the provider's)")
		cpu       = fs.Uint("cpu", 4, "virtual CPUs of the VM")
		memoryGiB = fs.Uint64("memory-gib", 8, "memory of the VM in GiB")
		diskGiB   = fs.Uint64("disk-gib", 80, "size of the guest disk in GiB (sparse)")
		timeout   = fs.Duration("script-timeout", 3*time.Hour, "maximum run time of the script")
		recSIP    = fs.Bool("recovery-sip-off", false, "boot once into macOS Recovery and run csrutil disable and csrutil authenticated-root disable (private VNC API, blind keystrokes)")
		recScript = fs.String("recovery-script", "", "absolute path of a root-owned keystroke script replacing the built-in one (see internal/recoverykeys)")
		logLevel  = fs.String("log-level", "info", "log level")
	)
	var countUsers stringList
	fs.Var(&countUsers, "count-vm-user", "also count this user's Virtualization VMs as running macOS guests (repeatable)")
	fs.SetOutput(os.Stderr)
	fs.Usage = func() { fmt.Fprint(os.Stderr, createBaseUsage); fs.PrintDefaults() }
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *ipswURL == "" || *ipswSHA == "" || *to == "" || *script == "" || *creds == "" {
		fs.Usage()
		return 2
	}
	opts := imagebuild.BaseOptions{
		IPSWURL: *ipswURL, IPSWSHA256: *ipswSHA, To: *to, ScriptPath: *script, CredsPath: *creds,
		MinFreeBytes: envcfg.MinFreeBytes(), OwnerUID: 0,
		CPU: *cpu, MemoryBytes: *memoryGiB << 30, DiskBytes: *diskGiB << 30,
		NetworkInterface: os.Getenv("VZ_BRIDGE_INTERFACE"),
		ScriptTimeout:    *timeout, CountVMUsers: countUsers,
		RecoverySIPOff: *recSIP, RecoveryScript: *recScript,
	}
	if err := opts.Check(); err != nil {
		fmt.Fprintln(os.Stderr, "create-base:", err)
		return 2
	}
	if os.Geteuid() != 0 {
		fmt.Fprintln(os.Stderr, "create-base must run as root")
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
	opts.CacheDir = filepath.Clean(dir)

	if err := imagebuild.RunCreateBase(ctx, opts); err != nil {
		if errors.Is(err, context.Canceled) {
			fmt.Fprintln(os.Stderr, "create-base: cancelled")
		} else {
			fmt.Fprintln(os.Stderr, "create-base failed:", err)
		}
		return 1
	}
	return 0
}

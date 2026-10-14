// Package imagebuild implements the build-image command: it derives a new macOS image from one
// the provider has already cached, by booting an APFS clone of its disk headless, running a
// reviewed script in the guest over SSH, stopping the VM from the host and streaming the result
// to the registry. It runs as root and is never reachable from a Pod or the Kubernetes API.
package imagebuild

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/agoda-com/macOS-vz-kubelet/internal/buildutil"
	"github.com/agoda-com/macOS-vz-kubelet/internal/envcfg"
	vzssh "github.com/agoda-com/macOS-vz-kubelet/internal/ssh"
	"github.com/agoda-com/macOS-vz-kubelet/pkg/downloader"
	"github.com/agoda-com/macOS-vz-kubelet/pkg/oci"
	"github.com/agoda-com/macOS-vz-kubelet/pkg/resource"
	"github.com/agoda-com/macOS-vz-kubelet/pkg/resourcemanager"
	"github.com/agoda-com/macOS-vz-kubelet/pkg/vm"
	"github.com/agoda-com/macOS-vz-kubelet/pkg/vm/config"

	"github.com/virtual-kubelet/virtual-kubelet/log"
	"golang.org/x/crypto/ssh"
	"golang.org/x/sys/unix"
)

const (
	maxScriptSize = 1 << 20
	maxCredsSize  = 64 << 10
	maxConfigSize = 1 << 20
	// stopGrace lets the guest's page cache reach the virtual disk after `sync`.
	stopGrace = 3 * time.Second
)

// Options are the validated inputs of one build.
type Options struct {
	From, To   string // image references, both name:tag and under an allowed prefix
	ScriptPath string // absolute path of the provisioning script
	CredsPath  string // absolute path of the root-only registry credentials JSON
	CacheDir   string // provider cache root (holds blobs/ and build/)

	Prefixes       []string // VZ_ALLOWED_IMAGE_PREFIXES
	MinFreeBytes   uint64   // VZ_MIN_FREE_BYTES floor, 0 disables
	ExpectedGrowth uint64   // bytes the clone is expected to grow by
	OwnerUID       uint32   // required owner of the script, credentials and cached files (0 in production)

	CPU              uint
	MemoryBytes      uint64
	NetworkInterface string
	ScriptTimeout    time.Duration
}

// Seams replaced in tests.
var (
	// cloneFile makes a copy-on-write copy; src is not followed if it is a symlink.
	cloneFile = func(src, dst string) error { return unix.Clonefile(src, dst, unix.CLONE_NOFOLLOW) }
	// countVMProcesses counts the running Virtualization.framework VM processes on the host.
	countVMProcesses = countVirtualizationProcesses
)

// Run performs the build. The build directory (the clone) is always deleted on return.
func Run(ctx context.Context, o Options) (err error) {
	logger := log.G(ctx)
	if err := buildutil.CheckRefs(o.From, o.To, o.Prefixes, envcfg.ImageAllowed); err != nil {
		return err
	}
	if _, err := vm.ValidateCPUCount(o.CPU); err != nil {
		return err
	}
	if _, err := vm.ValidateMemorySize(o.MemoryBytes); err != nil {
		return err
	}

	script, err := buildutil.ReadFile(o.ScriptPath, buildutil.FilePolicy{MaxSize: maxScriptSize, OwnerUID: o.OwnerUID, ForbidBit: 0o022})
	if err != nil {
		return fmt.Errorf("script: %w", err)
	}
	credsRaw, err := buildutil.ReadFile(o.CredsPath, buildutil.FilePolicy{MaxSize: maxCredsSize, OwnerUID: o.OwnerUID, ForbidBit: 0o077})
	if err != nil {
		return fmt.Errorf("credentials file: %w", err)
	}
	creds, err := buildutil.ParseCredentials(credsRaw)
	if err != nil {
		return err
	}
	sum := sha256.Sum256(script)
	scriptSHA := hex.EncodeToString(sum[:])

	// Concurrency with the provider: Virtualization.framework allows 2 VMs on the whole host and
	// the provider has no endpoint to reserve a slot from another process. The simplest safe rule
	// is to require that no VM is running at all, so both slots are free for this build.
	if n, err := countVMProcesses(); err != nil {
		return fmt.Errorf("could not count running virtual machines: %w", err)
	} else if n > 0 {
		return fmt.Errorf("%d virtual machine(s) are running on this host; stop or cordon them first (the host allows 2 and the build needs one)", n)
	}

	free, err := downloader.FreeBytes(o.CacheDir)
	if err != nil {
		return fmt.Errorf("failed to read free disk space: %w", err)
	}
	if !downloader.Fits(free, o.ExpectedGrowth, o.MinFreeBytes) {
		return fmt.Errorf("%w: %d bytes free, build expects %d of growth, floor %d", downloader.ErrInsufficientSpace, free, o.ExpectedGrowth, o.MinFreeBytes)
	}

	img, err := downloader.VerifyCached(ctx, o.CacheDir, o.From, resource.RegistryCredentials{
		Username: creds.Username, Password: creds.Password, IdentityToken: creds.IdentityToken,
	})
	if err != nil {
		return err
	}
	logger.Infof("Base image %s is cached and verified (manifest %s)", o.From, img.ManifestDigest)

	bd, err := buildutil.NewBuildDir(filepath.Join(o.CacheDir, "build"))
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, bd.Close()) }() // runs last: after the VM is stopped

	// Abort and clean up if free space crosses the floor at any point (clone growth, push).
	ctx, stopWatch := downloader.WatchFreeSpace(ctx, o.CacheDir, o.MinFreeBytes)
	defer stopWatch()
	defer func() {
		if cause := context.Cause(ctx); err != nil && errors.Is(cause, downloader.ErrInsufficientSpace) {
			err = errors.Join(err, cause)
		}
	}()

	if err := cloneInputs(img.Dir, bd, o.OwnerUID); err != nil {
		return err
	}
	diskPath, _ := bd.Path("disk.img")
	auxPath, _ := bd.Path("aux.img")
	cfgPath, _ := bd.Path("config.json")

	cfgBytes, err := os.ReadFile(cfgPath)
	if err != nil {
		return err
	}
	var imgCfg oci.Config
	if err := json.Unmarshal(cfgBytes, &imgCfg); err != nil {
		return fmt.Errorf("base config.json: %w", err)
	}

	instance, err := bootClone(ctx, o, config.MacPlatformConfigurationOptions{
		BlockStoragePath:      diskPath,
		AuxiliaryStoragePath:  auxPath,
		HardwareModelData:     imgCfg.HardwareModelData,
		MachineIdentifierData: imgCfg.MachineIdData,
	})
	if err != nil {
		return err
	}
	// Always stop from the host: a guest shutdown leaks a Virtualization.framework VM slot on
	// macOS 26.5. The context is detached so cleanup still happens when ctx was cancelled.
	stopped := false
	defer func() {
		if !stopped {
			_ = instance.Stop(context.WithoutCancel(ctx))
		}
	}()

	if err := provision(ctx, instance.IPAddress, script, o.ScriptTimeout); err != nil {
		return err
	}
	time.Sleep(stopGrace)
	if err := instance.Stop(context.WithoutCancel(ctx)); err != nil {
		return fmt.Errorf("failed to stop the build VM: %w", err)
	}
	stopped = true
	logger.Info("Build VM stopped from the host; pushing")

	var baseDiskDigest string
	for _, l := range img.Layers {
		if l.MediaType == string(oci.MediaTypeDiskImage) {
			baseDiskDigest = l.Annotations[oci.AnnotationUncompressedDigest]
		}
	}
	res, err := buildutil.Push(ctx, buildutil.PushOptions{
		Ref:    o.To,
		Creds:  creds,
		Disk:   diskPath,
		Aux:    auxPath,
		Config: cfgPath,
		Annotations: map[string]string{
			"com.agoda.macosvz.build.base-ref":             o.From,
			"com.agoda.macosvz.build.base-manifest-digest": img.ManifestDigest,
			"com.agoda.macosvz.build.base-disk-digest":     baseDiskDigest,
			"com.agoda.macosvz.build.script-sha256":        scriptSHA,
			"com.agoda.macosvz.build.machine-identifier":   "shared with the base image",
		},
	})
	if err != nil {
		return err
	}
	logger.Infof("Pushed %s (manifest %s)", o.To, res.ManifestDigest)
	return nil
}

// cloneInputs APFS-clones disk.img and aux.img from the cached image into the build
// directory and copies config.json. File names are fixed; the sources are the cache's own
// files, opened without following symlinks and required to be regular files owned by ownerUID.
func cloneInputs(imageDir string, bd *buildutil.BuildDir, ownerUID uint32) error {
	for _, name := range []string{"disk.img", "aux.img"} {
		src := filepath.Join(imageDir, name)
		fi, err := os.Lstat(src)
		if err != nil {
			return err
		}
		if !fi.Mode().IsRegular() {
			return fmt.Errorf("cached %s is not a regular file", src)
		}
		dst, err := bd.Path(name)
		if err != nil {
			return err
		}
		if err := cloneFile(src, dst); err != nil {
			return fmt.Errorf("failed to clone %s (the build dir must be on the cache volume): %w", name, err)
		}
	}
	cfg, err := buildutil.ReadFile(filepath.Join(imageDir, "config.json"), buildutil.FilePolicy{MaxSize: maxConfigSize, OwnerUID: ownerUID, ForbidBit: 0o022})
	if err != nil {
		return fmt.Errorf("cached config.json: %w", err)
	}
	dst, _ := bd.Path("config.json")
	return os.WriteFile(dst, cfg, 0o600)
}

// bootClone starts a headless VM from the cloned disk (no overlay: the clone is the disk).
func bootClone(ctx context.Context, o Options, cfg config.MacPlatformConfigurationOptions) (*vm.VirtualMachineInstance, error) {
	platform, err := config.NewPlatformConfiguration(ctx, cfg, false, "build-image")
	if err != nil {
		return nil, fmt.Errorf("failed to create platform configuration: %w", err)
	}
	vmCfg, err := config.NewVirtualMachineConfiguration(ctx, platform, o.CPU, o.MemoryBytes, o.NetworkInterface, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create virtual machine configuration: %w", err)
	}
	instance, err := vm.NewVirtualMachineInstance(ctx, vmCfg)
	if err != nil {
		return nil, err
	}
	if err := instance.Start(ctx); err != nil {
		_ = instance.Stop(context.WithoutCancel(ctx))
		return nil, err
	}
	return instance, nil
}

// provision waits for sshd, copies the script into the guest, runs it as the SSH user and
// syncs. A non-zero script exit is an error, so nothing is pushed.
func provision(ctx context.Context, ip string, script []byte, timeout time.Duration) error {
	sshCfg, err := resourcemanager.SSHClientConfig()
	if err != nil {
		return err
	}
	client, err := waitForSSH(ctx, ip, sshCfg, envcfg.SSHReadinessTimeout())
	if err != nil {
		return err
	}
	defer client.Close()

	if err := runRemote(ctx, client, `umask 077 && mkdir -p "$HOME/.build" && cat > "$HOME/.build/script.sh"`, bytes.NewReader(script), nil, time.Minute); err != nil {
		return fmt.Errorf("failed to copy the script into the guest: %w", err)
	}
	log.G(ctx).Info("Running the provisioning script in the guest")
	if err := runRemote(ctx, client, `/bin/bash "$HOME/.build/script.sh"`, nil, os.Stderr, timeout); err != nil {
		return fmt.Errorf("provisioning script: %w", err)
	}
	// Remove the script from the image, then flush guest writes to the virtual disk.
	if err := runRemote(ctx, client, `rm -rf "$HOME/.build"; sync`, nil, os.Stderr, 5*time.Minute); err != nil {
		return fmt.Errorf("failed to sync the guest: %w", err)
	}
	return nil
}

func waitForSSH(ctx context.Context, ip string, cfg *ssh.ClientConfig, budget time.Duration) (*ssh.Client, error) {
	deadline := time.Now().Add(budget)
	var last error
	for {
		c, err := vzssh.DialContext(ctx, "tcp", ip+":22", cfg)
		if err == nil {
			return c, nil
		}
		last = err
		if strings.Contains(err.Error(), "unable to authenticate") {
			return nil, err // permanent
		}
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("sshd not reachable after %s: %w", budget, last)
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(2 * time.Second):
		}
	}
}

// runRemote runs cmd in a new session with a deadline; cancelling closes the session.
func runRemote(ctx context.Context, client *ssh.Client, cmd string, stdin io.Reader, out io.Writer, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	sess, err := client.NewSession()
	if err != nil {
		return err
	}
	defer sess.Close()
	sess.Stdin = stdin
	sess.Stdout, sess.Stderr = out, out
	stop := context.AfterFunc(ctx, func() { _ = sess.Close() })
	defer stop()

	err = sess.Run(cmd)
	if ctx.Err() != nil {
		return ctx.Err()
	}
	var exit *ssh.ExitError
	if errors.As(err, &exit) {
		return fmt.Errorf("exit status %d", exit.ExitStatus())
	}
	return err
}

// countVirtualizationProcesses counts Virtualization.framework VM processes host-wide. The
// 2-VM limit is system-wide, so this includes VMs of any provider or tool.
func countVirtualizationProcesses() (int, error) {
	out, err := exec.Command("/usr/bin/pgrep", "-f", "com.apple.Virtualization.VirtualMachine").Output()
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) && ee.ExitCode() == 1 {
			return 0, nil // no match
		}
		return 0, err
	}
	return len(strings.Fields(string(out))), nil
}

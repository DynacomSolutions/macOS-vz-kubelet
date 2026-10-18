package imagebuild

// create-base --recovery-sip-off: turn SIP and authenticated-root off before the first normal boot.
//
// Mechanism, and why. The guest has no sshd in macOS Recovery, so ssh (create-base's usual way in)
// is out, and the seeded data volume cannot help: csrutil changes the boot policy, which only
// Recovery may do. The remaining way in is the keyboard. Virtualization.framework's public API
// injects keys only through a VZVirtualMachineView, which needs a window server session that a
// root process started over ssh does not have. So the VM is started with
// VZMacOSVirtualMachineStartOptions.startUpFromMacOSRecovery (Code-Hex/vz WithStartUpFromMacOSRecovery),
// the private _VZVNCServer is attached to it (internal/vzvnc, the same server tart exposes), and a
// minimal RFB client (internal/rfb) plays a blind keystroke script (internal/recoverykeys). The
// server has a random password per run. Nothing reads the screen, so the script's waits are
// guesses: replace them with --recovery-script after watching a run.
//
// Known limits, untested on hardware: csrutil on Apple silicon asks for a user that owns the
// machine (secure token). The seed in buildutil.SeedDataVolume writes a plain dslocal user, so
// that login may be refused; the script then types the credentials in vain and the later
// verification (csrutil status in the guest, see verifySIPOff) fails the build instead of pushing.

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/agoda-com/macOS-vz-kubelet/internal/buildutil"
	"github.com/agoda-com/macOS-vz-kubelet/internal/recoverykeys"
	"github.com/agoda-com/macOS-vz-kubelet/internal/rfb"
	"github.com/agoda-com/macOS-vz-kubelet/internal/vzvnc"
	"github.com/agoda-com/macOS-vz-kubelet/pkg/vm"
	"github.com/agoda-com/macOS-vz-kubelet/pkg/vm/config"

	"github.com/Code-Hex/vz/v3"
	"github.com/virtual-kubelet/virtual-kubelet/log"
)

// loadRecoverySteps parses --recovery-script, or the built-in script.
func loadRecoverySteps(o BaseOptions) ([]recoverykeys.Step, error) {
	text := recoverykeys.DefaultScript
	if o.RecoveryScript != "" {
		b, err := buildutil.ReadFile(o.RecoveryScript, buildutil.FilePolicy{MaxSize: maxScriptSize, OwnerUID: o.OwnerUID, ForbidBit: 0o022})
		if err != nil {
			return nil, fmt.Errorf("recovery script: %w", err)
		}
		text = string(b)
	}
	return recoverykeys.Parse(text)
}

// disableSIPInRecovery starts the guest in macOS Recovery, plays steps and force-stops the VM
// from the host (a guest-initiated shutdown would leak a VM slot, see vm.handleStateChanges).
func disableSIPInRecovery(ctx context.Context, o BaseOptions, p config.MacPlatformConfigurationOptions, steps []recoverykeys.Step, guestPassword string) (err error) {
	platform, err := config.NewPlatformConfiguration(ctx, p, false, "create-base")
	if err != nil {
		return err
	}
	vmCfg, err := config.NewVirtualMachineConfiguration(ctx, platform, o.CPU, o.MemoryBytes, o.NetworkInterface, nil, nil)
	if err != nil {
		return err
	}
	instance, err := vm.NewVirtualMachineInstance(ctx, vmCfg)
	if err != nil {
		return err
	}
	instance.SkipIPLookup = true
	defer func() { err = errors.Join(err, instance.Stop(context.WithoutCancel(ctx))) }()

	vnc, err := vzvnc.Start(instance.VirtualMachine)
	if err != nil {
		return err
	}
	defer vnc.Stop()

	log.G(ctx).Info("Starting the guest in macOS Recovery")
	if err := instance.Start(ctx, vz.WithStartUpFromMacOSRecovery(true)); err != nil {
		return err
	}
	port, err := vnc.WaitPort(ctx)
	if err != nil {
		return err
	}
	var cl *rfb.Client
	for try := 0; ; try++ {
		if cl, err = rfb.Dial(net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), vnc.Password); err == nil {
			break
		}
		if try == 9 {
			return fmt.Errorf("connecting to the VNC server on port %d failed after 10 tries: %w", port, err)
		}
		if err := recoverykeys.Sleep(ctx, 2*time.Second); err != nil {
			return err
		}
	}
	defer cl.Close()

	logger := log.G(ctx)
	logger.Infof("RFB server %q: desktop %dx%d, pixel format %s", cl.Name, cl.Width, cl.Height, cl.Format)
	shots, err := newShotDir(o)
	if err != nil {
		return err
	}
	snap := func(label string) {
		img, err := cl.Screenshot()
		if err != nil {
			logger.WithError(err).Warnf("Recovery screenshot %s failed", label)
			return
		}
		p := filepath.Join(shots, label+".png")
		if err := rfb.WritePNG(p, img); err != nil {
			logger.WithError(err).Warnf("Recovery screenshot %s not saved", label)
			return
		}
		logger.Infof("Recovery screenshot: %s", p)
	}
	snap("00-connected")

	secrets := map[string]string{"guest_password": guestPassword}
	if err := recoverykeys.Run(ctx, cl, steps, recoverykeys.Options{
		Secrets: secrets,
		Snap:    snap,
		Logf:    func(f string, a ...any) { logger.Infof("recovery: "+f, a...) },
	}); err != nil {
		snap("99-failed")
		return err
	}
	snap("99-before-stop")
	log.G(ctx).Info("Recovery keystrokes done; stopping the guest")
	return nil
}

// newShotDir creates <RecoveryShotsDir or <cache>/recovery-shots>/<UTC timestamp>, root-only. The
// screenshots are kept after the run: they are the only record of what Recovery showed.
func newShotDir(o BaseOptions) (string, error) {
	base := o.RecoveryShotsDir
	if base == "" {
		base = filepath.Join(o.CacheDir, "recovery-shots")
	}
	dir := filepath.Join(base, time.Now().UTC().Format("20060102T150405Z"))
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	return dir, nil
}

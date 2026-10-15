package imagebuild

// create-base builds a vanilla macOS base image from an Apple IPSW, with no tart and no GUI.
//
// Getting into the fresh guest. A freshly installed macOS stops at Setup Assistant: no user, no
// sshd. Two ways in were weighed:
//
//  1. Drive Setup Assistant over VNC with keystrokes (the packer-plugin-tart way). Virtualization's
//     VNC server is private API (_VZVNCServer) that Code-Hex/vz does not expose, the public API has
//     no way to inject keys without a VZVirtualMachineView (which needs a window server session a
//     LaunchDaemon does not have), and the keystroke timing is blind (no OCR). Rejected.
//  2. After the install, attach the raw disk on the host and pre-seed the guest's DATA volume
//     (chosen). On macOS 26 the system volume is sealed (SSV) and cannot be changed, but everything
//     that matters lives on the writable data volume: the local user record in
//     /var/db/dslocal, /var/db/.AppleSetupDone (skips Setup Assistant), launchd's disabled.plist
//     (turns sshd on) and ~admin/.ssh/authorized_keys. See buildutil.SeedDataVolume.
//
// The same seed also adds the user to the admin group (sudo needs it), writes the passwordless
// sudoers.d entry and a key-only sshd drop-in, so sshd is key-only from the first boot and the
// password never crosses SSH. The first boot only verifies the result; FileVault is off by default
// and is verified too.
//
// Untested on real hardware: the host mount of the guest volumes and the first boot of the seeded
// guest. Both fail closed with an error.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/agoda-com/macOS-vz-kubelet/internal/buildutil"
	"github.com/agoda-com/macOS-vz-kubelet/pkg/downloader"
	"github.com/agoda-com/macOS-vz-kubelet/pkg/oci"
	"github.com/agoda-com/macOS-vz-kubelet/pkg/resourcemanager"
	"github.com/agoda-com/macOS-vz-kubelet/pkg/vm"
	"github.com/agoda-com/macOS-vz-kubelet/pkg/vm/config"

	"github.com/Code-Hex/vz/v3"
	"github.com/virtual-kubelet/virtual-kubelet/log"
)

const (
	guestUser = "admin"
	guestUID  = 501
	guestGID  = 20
	// baseExpectedGrowth is the disk space one create-base needs on top of the floor: the IPSW
	// (about 20 GiB) and the written part of the guest disk.
	baseExpectedGrowth = 60 << 30
	// firstBootSSHBudget covers the first boot of a freshly installed macOS, which is slow.
	firstBootSSHBudget = 15 * time.Minute
	// firstBootIPBudget bounds the wait for the guest's DHCP lease on that first boot.
	firstBootIPBudget = 10 * time.Minute
)

// BaseOptions are the validated inputs of one create-base run.
type BaseOptions struct {
	IPSWURL, IPSWSHA256 string
	To                  string // registry.s.dynacom.dev/macos-vz/<name>:<tag>
	ScriptPath          string
	CredsPath           string // root-only JSON: username, password, guest_password
	CacheDir            string // holds build/ (the VM files) and create-base/ (the verified IPSW cache)

	MinFreeBytes uint64
	OwnerUID     uint32

	CPU              uint
	MemoryBytes      uint64
	DiskBytes        uint64
	NetworkInterface string
	ScriptTimeout    time.Duration
	CountVMUsers     []string
}

// Check validates the arguments that need no host access (CPU and memory are checked against the
// host's limits in RunCreateBase).
func (o BaseOptions) Check() error {
	return buildutil.CheckBaseArgs(o.IPSWURL, o.IPSWSHA256, o.To, o.DiskBytes)
}

// RunCreateBase installs macOS from the IPSW, makes the guest reachable, runs the script and
// pushes the result. The build directory is always deleted on return.
func RunCreateBase(ctx context.Context, o BaseOptions) (err error) {
	logger := log.G(ctx)
	if err := o.Check(); err != nil {
		return err
	}
	if os.Getenv("VZ_SSH_USER") != guestUser {
		return fmt.Errorf("VZ_SSH_USER must be %q: create-base seeds that user", guestUser)
	}
	// Our client must offer the key only: no password or keyboard-interactive login, ever.
	if os.Getenv("VZ_SSH_PASSWORD") != "" {
		return errors.New("VZ_SSH_PASSWORD must not be set for create-base: the guest accepts keys only")
	}
	authorizedKey, err := resourcemanager.SSHAuthorizedKey()
	if err != nil {
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
	creds, err := buildutil.ParseBaseCredentials(credsRaw)
	if err != nil {
		return err
	}
	scriptSHA := sha256Hex(script)

	// Same rule as build-image: no macOS guest may be running, so both VM slots are free.
	if n, err := countVMProcesses(o.CountVMUsers); err != nil {
		return fmt.Errorf("could not count running virtual machines: %w", err)
	} else if n > 0 {
		return fmt.Errorf("%d macOS virtual machine(s) are running on this host; stop or cordon them first", n)
	}

	if _, err := vm.ValidateCPUCount(o.CPU); err != nil {
		return err
	}
	if _, err := vm.ValidateMemorySize(o.MemoryBytes); err != nil {
		return err
	}

	free, err := downloader.FreeBytes(o.CacheDir)
	if err != nil {
		return fmt.Errorf("failed to read free disk space: %w", err)
	}
	if !downloader.Fits(free, baseExpectedGrowth, o.MinFreeBytes) {
		return fmt.Errorf("%w: %d bytes free, create-base expects %d of growth, floor %d", downloader.ErrInsufficientSpace, free, uint64(baseExpectedGrowth), o.MinFreeBytes)
	}

	bd, err := buildutil.NewBuildDir(filepath.Join(o.CacheDir, "build")) // also the one-at-a-time lock
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, bd.Close()) }()

	ctx, stopWatch := downloader.WatchFreeSpace(ctx, o.CacheDir, o.MinFreeBytes)
	defer stopWatch()
	defer func() {
		if cause := context.Cause(ctx); err != nil && errors.Is(cause, downloader.ErrInsufficientSpace) {
			err = errors.Join(err, cause)
		}
	}()

	ipsw, err := fetchIPSW(ctx, o)
	if err != nil {
		return err
	}

	image, err := vz.LoadMacOSRestoreImageFromPath(ipsw)
	if err != nil {
		return fmt.Errorf("failed to load the restore image: %w", err)
	}
	req := image.MostFeaturefulSupportedConfiguration()
	// A nil configuration reads as zeros; check before touching the hardware model.
	if req == nil || (req.MinimumSupportedCPUCount() == 0 && req.MinimumSupportedMemorySize() == 0) {
		return errors.New("the restore image has no configuration supported by this host")
	}
	if uint64(o.CPU) < req.MinimumSupportedCPUCount() || o.MemoryBytes < req.MinimumSupportedMemorySize() {
		return fmt.Errorf("the restore image needs at least %d CPUs and %d bytes of memory", req.MinimumSupportedCPUCount(), req.MinimumSupportedMemorySize())
	}
	hw := req.HardwareModel()
	if hw == nil || !hw.Supported() {
		return errors.New("the restore image's hardware model is not supported by this host")
	}
	mid, err := vz.NewMacMachineIdentifier()
	if err != nil {
		return err
	}
	logger.Infof("Installing macOS %s (build %s)", image.OperatingSystemVersion().String(), image.BuildVersion())

	diskPath, _ := bd.Path("disk.img")
	auxPath, _ := bd.Path("aux.img")
	cfgPath, _ := bd.Path("config.json")
	f, err := os.OpenFile(diskPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if err := f.Truncate(int64(o.DiskBytes)); err != nil { // sparse
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if _, err := vz.NewMacAuxiliaryStorage(auxPath, vz.WithCreatingMacAuxiliaryStorage(hw)); err != nil {
		return fmt.Errorf("failed to create the auxiliary storage: %w", err)
	}
	platformOpts := config.MacPlatformConfigurationOptions{
		BlockStoragePath:      diskPath,
		AuxiliaryStoragePath:  auxPath,
		HardwareModelData:     base64.StdEncoding.EncodeToString(hw.DataRepresentation()),
		MachineIdentifierData: base64.StdEncoding.EncodeToString(mid.DataRepresentation()),
	}
	imgCfg := oci.NewMacOSConfig(platformOpts.HardwareModelData, platformOpts.MachineIdentifierData)
	cfgBytes, err := json.Marshal(&imgCfg)
	if err != nil {
		return err
	}
	if err := os.WriteFile(cfgPath, cfgBytes, 0o600); err != nil {
		return err
	}

	if err := installMacOS(ctx, o, platformOpts, ipsw); err != nil {
		return err
	}

	if err := seedGuest(ctx, bd.Dir(), diskPath, buildutil.SeedSpec{
		User: guestUser, Password: creds.GuestPassword, UID: guestUID, GID: guestGID, AuthorizedKey: authorizedKey,
	}); err != nil {
		return fmt.Errorf("failed to prepare the installed guest: %w", err)
	}

	instance, err := bootClone(ctx, Options{CPU: o.CPU, MemoryBytes: o.MemoryBytes, NetworkInterface: o.NetworkInterface, IPLookupTimeout: firstBootIPBudget}, platformOpts, nil)
	if err != nil {
		return err
	}
	stopped := false
	defer func() {
		if !stopped {
			_ = instance.Stop(context.WithoutCancel(ctx))
		}
	}()

	if err := verifyGuest(ctx, instance.IPAddress); err != nil {
		return err
	}
	if err := provision(ctx, instance.IPAddress, script, o.ScriptTimeout, 0); err != nil {
		return err
	}
	time.Sleep(stopGrace)
	if err := instance.Stop(context.WithoutCancel(ctx)); err != nil {
		return fmt.Errorf("failed to stop the build VM: %w", err)
	}
	stopped = true
	logger.Info("Build VM stopped from the host; pushing")

	res, err := buildutil.Push(ctx, buildutil.PushOptions{
		Ref:    o.To,
		Creds:  creds.Credentials,
		Disk:   diskPath,
		Aux:    auxPath,
		Config: cfgPath,
		Annotations: map[string]string{
			"com.agoda.macosvz.build.ipsw-sha256":      o.IPSWSHA256,
			"com.agoda.macosvz.build.macos-version":    image.OperatingSystemVersion().String(),
			"com.agoda.macosvz.build.macos-build":      image.BuildVersion(),
			"com.agoda.macosvz.build.script-sha256":    scriptSHA,
			"com.agoda.macosvz.build.machine-identity": "created by create-base",
		},
	})
	if err != nil {
		return err
	}
	logger.Infof("Pushed %s (manifest %s)", o.To, res.ManifestDigest)
	return nil
}

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// fetchIPSW returns the path of the verified IPSW in <cache>/create-base, downloading it if needed.
func fetchIPSW(ctx context.Context, o BaseOptions) (string, error) {
	dir := filepath.Join(o.CacheDir, "create-base")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	if fi, err := os.Lstat(dir); err != nil || !fi.IsDir() {
		return "", fmt.Errorf("%q must be a real directory", dir)
	}
	dst := filepath.Join(dir, o.IPSWSHA256+".ipsw")
	cached, err := buildutil.FetchVerified(ctx, &http.Client{}, o.IPSWURL, dst, o.IPSWSHA256)
	if err != nil {
		return "", err
	}
	if cached {
		log.G(ctx).Info("Using the verified cached IPSW")
	} else {
		log.G(ctx).Info("Downloaded and verified the IPSW")
	}
	return dst, nil
}

// installMacOS runs VZMacOSInstaller on a stopped VM built from the platform options.
func installMacOS(ctx context.Context, o BaseOptions, p config.MacPlatformConfigurationOptions, ipsw string) error {
	platform, err := config.NewPlatformConfiguration(ctx, p, false, "create-base")
	if err != nil {
		return fmt.Errorf("failed to create platform configuration: %w", err)
	}
	vmCfg, err := config.NewVirtualMachineConfiguration(ctx, platform, o.CPU, o.MemoryBytes, o.NetworkInterface, nil, nil)
	if err != nil {
		return fmt.Errorf("failed to create virtual machine configuration: %w", err)
	}
	instance, err := vm.NewVirtualMachineInstance(ctx, vmCfg)
	if err != nil {
		return err
	}
	defer func() { _ = instance.Stop(context.WithoutCancel(ctx)) }() // no-op when already stopped
	installer, err := vz.NewMacOSInstaller(instance.VirtualMachine, ipsw)
	if err != nil {
		return err
	}
	go func() {
		t := time.NewTicker(30 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-installer.Done():
				return
			case <-ctx.Done():
				return
			case <-t.C:
				log.G(ctx).Infof("Installing macOS: %.0f%%", installer.FractionCompleted()*100)
			}
		}
	}()
	if err := installer.Install(ctx); err != nil {
		return fmt.Errorf("macOS installation failed: %w", err)
	}
	log.G(ctx).Info("macOS installed")
	return nil
}

const plistBuddy = "/usr/libexec/PlistBuddy"

// run executes a host tool; only the tail of its output is kept in the error.
func run(ctx context.Context, stdin []byte, name string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(errb.String())
		if len(msg) > 300 {
			msg = msg[len(msg)-300:]
		}
		return nil, fmt.Errorf("%s %s: %w: %s", filepath.Base(name), args[0], err, msg)
	}
	return out.Bytes(), nil
}

// seedGuest attaches the raw guest disk on the host, mounts the guest's data volume (and, when
// the data volume has no directory node yet, the system volume read-only for its template) and
// seeds it. Everything is unmounted and detached again on return.
func seedGuest(ctx context.Context, tmpRoot, diskPath string, spec buildutil.SeedSpec) (err error) {
	var dev string
	var cleanup []error // unmount failures; joined after the detach, which runs last
	// Registered before anything can fail: if the attach output is unusable the device is found
	// again by image path.
	defer func() {
		ctx := context.WithoutCancel(ctx)
		if dev == "" {
			if js, jerr := hdiutilJSON(ctx, "info", "-plist"); jerr == nil {
				real, _ := filepath.EvalSymlinks(diskPath)
				dev, _ = buildutil.FindImageDevice(js, diskPath, real)
			}
		}
		var derr error
		if dev != "" {
			_, derr = run(ctx, nil, "/usr/bin/hdiutil", "detach", "-force", dev)
		}
		err = errors.Join(append([]error{err, derr}, cleanup...)...)
	}()
	js, err := hdiutilJSON(ctx, "attach", "-plist", "-nomount", "-nobrowse", "-noverify",
		"-imagekey", "diskimage-class=CRawDiskImage", diskPath)
	if err != nil {
		return err
	}
	if dev, err = buildutil.ParseAttach(js); err != nil {
		dev = ""
		return err
	}

	ids, err := guestVolumes(ctx, filepath.Base(dev))
	if err != nil {
		return err
	}
	mount := func(id, opts string) (string, func(), error) {
		dir, merr := os.MkdirTemp(tmpRoot, "mnt-")
		if merr != nil {
			return "", nil, merr
		}
		if _, merr := run(ctx, nil, "/sbin/mount_apfs", "-o", opts, "/dev/"+id, dir); merr != nil {
			_ = os.Remove(dir)
			return "", nil, merr
		}
		return dir, func() {
			_, uerr := run(context.WithoutCancel(ctx), nil, "/sbin/umount", dir)
			if uerr == nil {
				_ = os.Remove(dir)
			} else {
				cleanup = append(cleanup, uerr)
			}
		}, nil
	}

	dataDir, unmountData, err := mount(ids["Data"], "nobrowse,nosuid,nodev")
	if err != nil {
		return err
	}
	defer unmountData()
	if sys, ok := ids["System"]; ok {
		if dir, unmountSys, serr := mount(sys, "nobrowse,rdonly,nosuid,nodev"); serr == nil {
			defer unmountSys()
			spec.SystemRoot = dir
			t := filepath.Join(dir, "System/Library/DirectoryServices/DefaultLocalDB/Default")
			if fi, e := os.Stat(t); e == nil && fi.IsDir() {
				spec.TemplateDir = t
			}
		} else {
			log.G(ctx).WithError(serr).Warn("Could not mount the guest system volume; no directory template available")
		}
	}

	hooks := buildutil.SeedHooks{
		Chown: os.Lchown,
		EnableService: func(file, label string) error {
			// PlistBuddy paths use ':', so the dots in the label are not a key path (plutil -replace reads them as one).
			if _, err := run(ctx, nil, plistBuddy, "-c", "Set :"+label+" false", file); err != nil {
				_, err = run(ctx, nil, plistBuddy, "-c", "Add :"+label+" bool false", file)
				return err
			}
			return nil
		},
		AppendToArray: func(file, key, value string) error {
			if _, err := run(ctx, nil, plistBuddy, "-c", "Print :"+key, file); err != nil {
				if _, err := run(ctx, nil, plistBuddy, "-c", "Add :"+key+" array", file); err != nil {
					return err
				}
			}
			_, err := run(ctx, nil, plistBuddy, "-c", "Add :"+key+": string "+value, file)
			return err
		},
		BinaryPlist: func(x []byte) ([]byte, error) {
			return run(ctx, x, "/usr/bin/plutil", "-convert", "binary1", "-o", "-", "-")
		},
	}
	if err := buildutil.SeedDataVolume(dataDir, spec, hooks); err != nil {
		return err
	}
	// The seed is useless if the volume ignored ownership: fail closed.
	fi, err := os.Stat(filepath.Join(dataDir, "Users", spec.User, ".ssh/authorized_keys"))
	if err != nil {
		return err
	}
	if st, ok := fi.Sys().(*syscall.Stat_t); !ok || int(st.Uid) != spec.UID {
		return errors.New("the guest data volume ignores file ownership on this host")
	}
	return nil
}

// hdiutilJSON runs hdiutil with a -plist verb and returns its output converted to JSON.
func hdiutilJSON(ctx context.Context, args ...string) ([]byte, error) {
	out, err := run(ctx, nil, "/usr/bin/hdiutil", args...)
	if err != nil {
		return nil, err
	}
	return run(ctx, out, "/usr/bin/plutil", "-convert", "json", "-o", "-", "-")
}

// guestVolumes returns the device identifiers of the Data (and System) volumes of the APFS
// containers that live on the attached disk (for example "disk4").
func guestVolumes(ctx context.Context, disk string) (map[string]string, error) {
	plist, err := run(ctx, nil, "/usr/sbin/diskutil", "apfs", "list", "-plist")
	if err != nil {
		return nil, err
	}
	js, err := run(ctx, plist, "/usr/bin/plutil", "-convert", "json", "-o", "-", "-")
	if err != nil {
		return nil, err
	}
	return pickGuestVolumes(js, disk)
}

// pickGuestVolumes is the parsing half of guestVolumes (JSON converted from `diskutil apfs list -plist`).
func pickGuestVolumes(js []byte, disk string) (map[string]string, error) {
	var list struct {
		Containers []struct {
			DesignatedPhysicalStore string
			PhysicalStores          []struct{ DeviceIdentifier string }
			Volumes                 []struct {
				DeviceIdentifier string
				Roles            []string
			}
		}
	}
	if err := json.Unmarshal(js, &list); err != nil {
		return nil, fmt.Errorf("diskutil apfs list: %w", err)
	}
	prefix := disk + "s"
	ids := map[string]string{}
	for _, c := range list.Containers {
		on := strings.HasPrefix(c.DesignatedPhysicalStore, prefix)
		for _, s := range c.PhysicalStores {
			on = on || strings.HasPrefix(s.DeviceIdentifier, prefix)
		}
		if !on {
			continue
		}
		for _, v := range c.Volumes {
			for _, r := range v.Roles {
				if r != "Data" && r != "System" {
					continue
				}
				if _, dup := ids[r]; dup {
					return nil, fmt.Errorf("more than one %s volume on %s", r, disk)
				}
				ids[r] = v.DeviceIdentifier
			}
		}
	}
	if ids["Data"] == "" {
		return nil, fmt.Errorf("no Data volume found on %s", disk)
	}
	return ids, nil
}

// verifyGuest waits for the seeded guest's sshd (key login as the seeded user) and checks what
// the seed set up: passwordless sudo, admin group membership, key-only sshd and FileVault off.
// No password is sent.
func verifyGuest(ctx context.Context, ip string) error {
	sshCfg, err := resourcemanager.SSHClientConfig()
	if err != nil {
		return err
	}
	client, err := waitForSSH(ctx, ip, sshCfg, firstBootSSHBudget)
	if err != nil {
		return fmt.Errorf("the seeded guest did not accept the key: %w", err)
	}
	defer client.Close()

	const verify = `set -eu
sudo -n true
/usr/bin/dsmemberutil checkmembership -U admin -G admin | grep -q 'is a member'
t=$(sudo -n /usr/sbin/sshd -T)
printf '%s\n' "$t" | grep -qx 'passwordauthentication no'
printf '%s\n' "$t" | grep -qx 'kbdinteractiveauthentication no'
/usr/bin/fdesetup status | grep -q 'FileVault is Off'`
	if err := runRemote(ctx, client, verify, nil, os.Stderr, time.Minute); err != nil {
		return fmt.Errorf("guest verification failed (passwordless sudo, admin group, key-only sshd, FileVault off): %w", err)
	}
	return nil
}

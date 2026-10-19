package imagebuild

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

const baseTestTo = "registry.s.dynacom.dev/macos-vz/tahoe-base:26.5"

func goodBaseOptions() BaseOptions {
	return BaseOptions{
		IPSWURL: "https://updates.cdn-apple.com/a.ipsw", IPSWSHA256: "0000000000000000000000000000000000000000000000000000000000000000",
		To: baseTestTo, CPU: 4, MemoryBytes: 8 << 30, DiskBytes: 80 << 30,
	}
}

func TestBaseOptionsCheck(t *testing.T) {
	assert.NoError(t, goodBaseOptions().Check())
	for name, mod := range map[string]func(*BaseOptions){
		"foreign registry": func(o *BaseOptions) { o.To = "ghcr.io/x/y:1" },
		"wrong namespace":  func(o *BaseOptions) { o.To = "registry.s.dynacom.dev/other/y:1" },
		"no tag":           func(o *BaseOptions) { o.To = "registry.s.dynacom.dev/macos-vz/y" },
		"http ipsw":        func(o *BaseOptions) { o.IPSWURL = "http://example.com/a.ipsw" },
		"bad sha":          func(o *BaseOptions) { o.IPSWSHA256 = "xyz" },
		"small disk":       func(o *BaseOptions) { o.DiskBytes = 1 << 30 },
	} {
		o := goodBaseOptions()
		mod(&o)
		assert.Error(t, o.Check(), name)
	}
}

func TestRunCreateBaseRefusesWithRunningVM(t *testing.T) {
	dir := t.TempDir()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	blk, err := ssh.MarshalPrivateKey(priv, "")
	require.NoError(t, err)
	key := filepath.Join(dir, "key")
	require.NoError(t, os.WriteFile(key, pem.EncodeToMemory(blk), 0o600))
	t.Setenv("VZ_SSH_USER", "admin")
	t.Setenv("VZ_SSH_PRIVATE_KEY_PATH", key)
	t.Setenv("VZ_SSH_PRIVATE_KEY_BASE64", "")
	script := filepath.Join(dir, "s.sh")
	creds := filepath.Join(dir, "c.json")
	require.NoError(t, os.WriteFile(script, []byte("true"), 0o600))
	require.NoError(t, os.WriteFile(creds, []byte(`{"username":"u","password":"p","guest_password":"g"}`), 0o600))

	old := countVMProcesses
	t.Cleanup(func() { countVMProcesses = old })
	countVMProcesses = func([]string) (int, error) { return 1, nil }

	o := goodBaseOptions()
	o.ScriptPath, o.CredsPath, o.CacheDir, o.OwnerUID = script, creds, dir, uint32(os.Getuid())
	err = RunCreateBase(t.Context(), o)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "virtual machine(s) are running")
	assert.NotContains(t, err.Error(), "g\"")
}

func TestRunCreateBaseRefusesPasswordAuth(t *testing.T) {
	t.Setenv("VZ_SSH_USER", "admin")
	t.Setenv("VZ_SSH_PASSWORD", "x")
	err := RunCreateBase(t.Context(), goodBaseOptions())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "VZ_SSH_PASSWORD")
}

func TestPickGuestVolumes(t *testing.T) {
	js := []byte(`{"Containers":[
	 {"DesignatedPhysicalStore":"disk0s2","PhysicalStores":[{"DeviceIdentifier":"disk0s2"}],"Volumes":[{"DeviceIdentifier":"disk1s1","Roles":["Data"]}]},
	 {"DesignatedPhysicalStore":"disk4s2","PhysicalStores":[{"DeviceIdentifier":"disk4s2"}],"Volumes":[
	   {"DeviceIdentifier":"disk5s1","Roles":["System"]},{"DeviceIdentifier":"disk5s2","Roles":["Data"]},{"DeviceIdentifier":"disk5s3","Roles":["Preboot"]}]},
	 {"DesignatedPhysicalStore":"disk40s2","Volumes":[{"DeviceIdentifier":"disk41s1","Roles":["Data"]}]}]}`)
	ids, err := pickGuestVolumes(js, "disk4")
	require.NoError(t, err)
	assert.Equal(t, map[string]string{"System": "disk5s1", "Data": "disk5s2"}, ids)
	_, err = pickGuestVolumes(js, "disk9")
	assert.Error(t, err)
}

func TestBaseOptionsRecoveryScript(t *testing.T) {
	o := goodBaseOptions()
	o.RecoveryScript = "/root/r.txt"
	assert.Error(t, o.Check(), "script without --recovery-sip-off")
	o.RecoverySIPOff = true
	assert.NoError(t, o.Check())
	o.RecoveryScript = "r.txt"
	assert.Error(t, o.Check(), "relative script path")

	o.RecoveryScript = ""
	o.ThenScriptPath = "then.sh"
	assert.Error(t, o.Check(), "relative then-script")
	o.ThenScriptPath = "/root/then.sh"
	assert.NoError(t, o.Check())

	o.RecoveryShotsDir = "shots"
	assert.Error(t, o.Check(), "relative shots dir")
	o.RecoveryShotsDir = "/var/shots"
	assert.NoError(t, o.Check())

	steps, err := loadRecoverySteps(BaseOptions{RecoverySIPOff: true})
	assert.NoError(t, err)
	assert.NotEmpty(t, steps)
}

func TestKeepOnError(t *testing.T) {
	cur, next := new(int), new(int)
	got, err := keepOnError(cur, nil, errors.New("boot failed"))
	assert.Error(t, err)
	assert.Same(t, cur, got, "a failed reboot must keep the running instance")
	got, err = keepOnError(cur, next, nil)
	assert.NoError(t, err)
	assert.Same(t, next, got)
}

func TestBuildPhases(t *testing.T) {
	join := func(o BaseOptions) string { return strings.Join(buildPhases(o), ",") }
	assert.Equal(t, "seed,boot,verify,script,stop,push", join(BaseOptions{}))
	assert.Equal(t, "seed,recovery,boot,verify,verify-sip-off,script,stop,push", join(BaseOptions{RecoverySIPOff: true}))
	assert.Equal(t, "seed,boot,verify,pre-recovery-script,stop,recovery,boot,verify,verify-sip-off,script,stop,boot,then-script,stop,push",
		join(BaseOptions{RecoverySIPOff: true, PreRecoveryScriptPath: "/p", ThenScriptPath: "/t"}))

	o := goodBaseOptions()
	o.PreRecoveryScriptPath = "/root/pre.sh"
	assert.Error(t, o.Check(), "pre-recovery script without --recovery-sip-off")
	o.RecoverySIPOff = true
	assert.NoError(t, o.Check())
	o.PreRecoveryScriptPath = "pre.sh"
	assert.Error(t, o.Check(), "relative path")
}

func TestPollGuestVolumes(t *testing.T) {
	empty := []byte(`{"Containers":[]}`)
	ready := []byte(`{"Containers":[{"DesignatedPhysicalStore":"disk4s2","Volumes":[{"DeviceIdentifier":"disk5s1","Roles":["Data"]}]}]}`)
	n := 0
	ids, err := pollGuestVolumes(context.Background(), "disk4", time.Millisecond, time.Second, func() ([]byte, error) {
		n++
		if n < 3 {
			return empty, nil
		}
		return ready, nil
	})
	assert.NoError(t, err)
	assert.Equal(t, "disk5s1", ids["Data"])
	assert.Equal(t, 3, n)

	_, err = pollGuestVolumes(context.Background(), "disk4", time.Millisecond, 20*time.Millisecond, func() ([]byte, error) { return empty, nil })
	assert.ErrorIs(t, err, errNoDataVolume)
	assert.Contains(t, err.Error(), `last diskutil apfs list: {"Containers":[]}`)

	calls := 0
	_, err = pollGuestVolumes(context.Background(), "disk4", time.Millisecond, time.Second, func() ([]byte, error) { calls++; return nil, errors.New("diskutil failed") })
	assert.Error(t, err)
	assert.Equal(t, 1, calls, "a diskutil error must not be retried")
}

func TestPostScriptRecoveryWiring(t *testing.T) {
	join := func(o BaseOptions) string { return strings.Join(buildPhases(o), ",") }
	assert.Equal(t, "seed,recovery,boot,verify,verify-sip-off,script,stop,recovery-post,boot,then-script,stop,push",
		join(BaseOptions{RecoverySIPOff: true, ThenScriptPath: "/t", PostScriptRecoveryPath: "/p"}))
	assert.Equal(t, "seed,recovery,boot,verify,verify-sip-off,script,stop,boot,then-script,stop,push",
		join(BaseOptions{RecoverySIPOff: true, ThenScriptPath: "/t"}))

	o := goodBaseOptions()
	o.PostScriptRecoveryPath = "/root/post.recovery"
	assert.Error(t, o.Check(), "needs --then-script")
	o.ThenScriptPath = "/root/then.sh"
	assert.NoError(t, o.Check())
	o.PostScriptRecoveryPath = "post.recovery"
	assert.Error(t, o.Check(), "relative path")
}

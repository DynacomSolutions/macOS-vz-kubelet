package buildutil

import (
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha512"
	"encoding/base64"
	"encoding/xml"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// SeedSpec describes the first user of a freshly installed macOS guest.
type SeedSpec struct {
	User          string
	Password      string // never logged
	UID, GID      int
	AuthorizedKey string // one authorized_keys line
	// TemplateDir is the guest's DefaultLocalDB/Default directory (on its system volume). It
	// seeds the local directory node when the data volume has none yet.
	TemplateDir string
	// SystemRoot is the mounted guest system volume (optional); /etc/sudoers is also looked for there.
	SystemRoot string
}

// SeedHooks are the host-specific parts, replaced in tests.
type SeedHooks struct {
	Chown func(path string, uid, gid int) error
	// EnableService makes launchd start label: it edits an existing disabled.plist (possibly binary).
	EnableService func(disabledPlist, label string) error
	// AppendToArray appends value to the string array at top-level key of an existing plist
	// (possibly binary), creating the array when the key is missing.
	AppendToArray func(file, key, value string) error
	// BinaryPlist converts an XML plist to binary form; nil keeps XML.
	BinaryPlist func(xml []byte) ([]byte, error)
}

const pbkdf2Iterations = 100000

// SSHDDropIn is the key-only sshd configuration (000- sorts first: sshd keeps the first value).
const SSHDDropIn = "PasswordAuthentication no\nKbdInteractiveAuthentication no\n"

// checkSudoersInclude refuses a guest whose sudoers would not read sudoers.d. /etc is on the
// data volume (/private/etc); the system volume root is the fallback.
func checkSudoersInclude(dataRoot, systemRoot string) error {
	var b []byte
	var err error
	for _, r := range []string{dataRoot, systemRoot} {
		if r == "" {
			continue
		}
		if b, err = os.ReadFile(filepath.Join(r, "private/etc/sudoers")); err == nil {
			break
		}
	}
	if err != nil || b == nil {
		return errors.New("could not read the guest's /etc/sudoers to check that it includes sudoers.d")
	}
	for _, l := range strings.Split(string(b), "\n") {
		for _, d := range []string{"#includedir ", "@includedir "} { // "#includedir" is a directive, not a comment
			if dir, ok := strings.CutPrefix(strings.TrimSpace(l), d); ok {
				if dir = strings.TrimSpace(dir); dir == "/private/etc/sudoers.d" || dir == "/etc/sudoers.d" {
					return nil
				}
			}
		}
	}
	return errors.New("the guest's sudoers does not include sudoers.d")
}

// SeedDataVolume pre-seeds the mounted data volume root of a guest that has never booted, so
// that it boots past Setup Assistant to a login window with SSH on: the local user (with a
// SALTED-SHA512-PBKDF2 shadow hash), /var/db/.AppleSetupDone, sshd enabled in launchd's
// disabled.plist, the user's home with authorized_keys, membership of the admin group (sudo needs
// it), the passwordless sudoers.d entry and a key-only sshd drop-in. Nothing needs the password
// after the first boot, so it never crosses SSH. It refuses to touch an existing user.
func SeedDataVolume(root string, s SeedSpec, h SeedHooks) error {
	if s.User == "" || s.Password == "" || s.AuthorizedKey == "" || strings.ContainsAny(s.User, "/\x00") {
		return errors.New("seed needs a user name, password and authorized key")
	}
	db := filepath.Join(root, "private/var/db")
	node := filepath.Join(db, "dslocal/nodes/Default")
	if _, err := os.Stat(filepath.Join(node, "users/root.plist")); err != nil {
		if s.TemplateDir == "" {
			return errors.New("the data volume has no local directory node and the system volume offers no template")
		}
		if err := copyTree(s.TemplateDir, node, h.Chown); err != nil {
			return fmt.Errorf("seeding the local directory node: %w", err)
		}
	}
	if err := checkSudoersInclude(root, s.SystemRoot); err != nil {
		return err
	}
	userFile := filepath.Join(node, "users", s.User+".plist")
	if _, err := os.Lstat(userFile); err == nil {
		return fmt.Errorf("user %s already exists in the guest", s.User)
	}
	guid, err := newGUID()
	if err != nil {
		return err
	}
	plist, err := userPlist(s, guid, h.BinaryPlist)
	if err != nil {
		return err
	}
	if err := putFile(userFile, plist, 0o600, 0, 0, h.Chown); err != nil {
		return err
	}
	// sudo and dsmemberutil need admin group membership: by name in users, by GUID in groupmembers.
	groupFile := filepath.Join(node, "groups/admin.plist")
	if _, err := os.Stat(groupFile); err != nil {
		return fmt.Errorf("the guest has no admin group record: %w", err)
	}
	if err := h.AppendToArray(groupFile, "users", s.User); err != nil {
		return fmt.Errorf("adding %s to the admin group: %w", s.User, err)
	}
	if err := h.AppendToArray(groupFile, "groupmembers", guid); err != nil {
		return fmt.Errorf("adding %s to the admin group: %w", s.User, err)
	}
	if err := putFile(filepath.Join(db, ".AppleSetupDone"), nil, 0o644, 0, 0, h.Chown); err != nil {
		return err
	}
	if err := putFile(filepath.Join(root, "private/etc/sudoers.d/dynacom-admin"), []byte(s.User+" ALL=(ALL) NOPASSWD: ALL\n"), 0o440, 0, 0, h.Chown); err != nil {
		return err
	}
	if err := putFile(filepath.Join(root, "private/etc/ssh/sshd_config.d/000-dynacom.conf"), []byte(SSHDDropIn), 0o644, 0, 0, h.Chown); err != nil {
		return err
	}

	disabled := filepath.Join(db, "com.apple.xpc.launchd/disabled.plist")
	if _, err := os.Stat(disabled); err == nil {
		if err := h.EnableService(disabled, "com.openssh.sshd"); err != nil {
			return fmt.Errorf("enabling sshd: %w", err)
		}
	} else {
		body := `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict><key>com.openssh.sshd</key><false/></dict></plist>
`
		if err := putFile(disabled, []byte(body), 0o644, 0, 0, h.Chown); err != nil {
			return err
		}
	}

	home := filepath.Join(root, "Users", s.User)
	for _, d := range []struct {
		p    string
		mode os.FileMode
	}{{filepath.Join(root, "Users"), 0o755}, {home, 0o750}, {filepath.Join(home, ".ssh"), 0o700}} {
		uid, gid := s.UID, s.GID
		if d.p == filepath.Join(root, "Users") {
			uid, gid = 0, 0
		}
		if err := mkdirOwned(d.p, d.mode, uid, gid, h.Chown); err != nil {
			return err
		}
	}
	return putFile(filepath.Join(home, ".ssh/authorized_keys"), []byte(s.AuthorizedKey+"\n"), 0o600, s.UID, s.GID, h.Chown)
}

// userPlist renders /var/db/dslocal/nodes/Default/users/<user>.plist.
func userPlist(s SeedSpec, guid string, binary func([]byte) ([]byte, error)) ([]byte, error) {
	salt := make([]byte, 32)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	entropy, err := pbkdf2.Key(sha512.New, s.Password, salt, pbkdf2Iterations, 128)
	if err != nil {
		return nil, err
	}
	inner := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict><key>SALTED-SHA512-PBKDF2</key><dict><key>entropy</key><data>%s</data><key>iterations</key><integer>%d</integer><key>salt</key><data>%s</data></dict></dict></plist>`,
		base64.StdEncoding.EncodeToString(entropy), pbkdf2Iterations, base64.StdEncoding.EncodeToString(salt))
	innerBytes := []byte(inner)
	if binary != nil {
		if innerBytes, err = binary(innerBytes); err != nil {
			return nil, err
		}
	}

	esc := func(v string) string {
		var b strings.Builder
		_ = xml.EscapeText(&b, []byte(v))
		return b.String()
	}
	var b strings.Builder
	b.WriteString(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
`)
	for _, kv := range [][2]string{
		{"authentication_authority", ";ShadowHash;HASHLIST:<SALTED-SHA512-PBKDF2>"},
		{"generateduid", guid},
		{"gid", strconv.Itoa(s.GID)},
		{"home", "/Users/" + s.User},
		{"name", s.User},
		{"passwd", "********"},
		{"realname", s.User},
		{"shell", "/bin/zsh"},
		{"uid", strconv.Itoa(s.UID)},
	} {
		fmt.Fprintf(&b, "<key>%s</key><array><string>%s</string></array>\n", kv[0], esc(kv[1]))
	}
	fmt.Fprintf(&b, "<key>ShadowHashData</key><array><data>%s</data></array>\n</dict></plist>\n", base64.StdEncoding.EncodeToString(innerBytes))
	out := []byte(b.String())
	if binary != nil {
		return binary(out)
	}
	return out, nil
}

func putFile(path string, data []byte, mode os.FileMode, uid, gid int, chown func(string, int, int) error) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(path, data, mode); err != nil {
		return err
	}
	if err := os.Chmod(path, mode); err != nil {
		return err
	}
	return chown(path, uid, gid)
}

func mkdirOwned(path string, mode os.FileMode, uid, gid int, chown func(string, int, int) error) error {
	if err := os.MkdirAll(path, mode); err != nil {
		return err
	}
	if err := os.Chmod(path, mode); err != nil {
		return err
	}
	return chown(path, uid, gid)
}

// copyTree copies src into dst as root:wheel, keeping modes and symlinks.
func copyTree(src, dst string, chown func(string, int, int) error) error {
	return filepath.WalkDir(src, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(src, p)
		to := filepath.Join(dst, rel)
		info, err := d.Info()
		if err != nil {
			return err
		}
		switch {
		case d.IsDir():
			return mkdirOwned(to, info.Mode().Perm(), 0, 0, chown)
		case info.Mode()&os.ModeSymlink != 0:
			target, err := os.Readlink(p)
			if err != nil {
				return err
			}
			if err := os.Symlink(target, to); err != nil {
				return err
			}
			return chown(to, 0, 0)
		case info.Mode().IsRegular():
			b, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			return putFile(to, b, info.Mode().Perm(), 0, 0, chown)
		}
		return nil
	})
}

// newGUID returns a random version-4 UUID in the upper-case form of a directory GeneratedUID.
func newGUID() (string, error) {
	u := make([]byte, 16)
	if _, err := rand.Read(u); err != nil {
		return "", err
	}
	u[6] = u[6]&0x0f | 0x40
	u[8] = u[8]&0x3f | 0x80
	return fmt.Sprintf("%X-%X-%X-%X-%X", u[0:4], u[4:6], u[6:8], u[8:10], u[10:]), nil
}

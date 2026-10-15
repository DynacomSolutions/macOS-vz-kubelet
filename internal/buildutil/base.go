package buildutil

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"

	"oras.land/oras-go/v2/registry/remote"
)

// BaseRefPrefix is the only place create-base may push to.
const BaseRefPrefix = "registry.s.dynacom.dev/macos-vz/"

// CheckBaseRef validates the --to reference of create-base: a name:tag (no digest) under BaseRefPrefix.
func CheckBaseRef(to string) error {
	if !strings.HasPrefix(to, BaseRefPrefix) || len(to) == len(BaseRefPrefix) {
		return fmt.Errorf("--to %q must start with %s", to, BaseRefPrefix)
	}
	repo, err := remote.NewRepository(to)
	if err != nil {
		return fmt.Errorf("--to %q: %w", to, err)
	}
	if repo.Reference.Reference == "" || strings.Contains(to, "@") {
		return fmt.Errorf("--to %q must be name:tag, not a digest or untagged", to)
	}
	// NewRepository normalises nothing, but make sure the parsed repository is still below the prefix.
	if !strings.HasPrefix(repo.Reference.Registry+"/"+repo.Reference.Repository+"/", BaseRefPrefix) {
		return fmt.Errorf("--to %q must stay below %s", to, BaseRefPrefix)
	}
	return nil
}

// BaseCredentials are the registry credentials plus the guest admin password of create-base.
// The password is never logged: String redacts.
type BaseCredentials struct {
	Credentials
	GuestPassword string `json:"guest_password"`
}

// String redacts the secrets (also used by %v and %+v).
func (BaseCredentials) String() string { return "BaseCredentials{redacted}" }

// GoString redacts for %#v.
func (BaseCredentials) GoString() string { return "BaseCredentials{redacted}" }

// ParseBaseCredentials decodes the create-base credentials file: username and password (or
// identityToken) as for build-image, plus a required guest_password. Unknown fields are rejected.
func ParseBaseCredentials(b []byte) (BaseCredentials, error) {
	var c BaseCredentials
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		return BaseCredentials{}, errors.New("credentials file is not valid JSON with username, password, identityToken, guest_password")
	}
	if c.IdentityToken == "" && (c.Username == "" || c.Password == "") {
		return BaseCredentials{}, errors.New("credentials file needs identityToken, or username and password")
	}
	if c.GuestPassword == "" {
		return BaseCredentials{}, errors.New("credentials file needs guest_password")
	}
	return c, nil
}

var sha256Hex = regexp.MustCompile(`^[0-9a-f]{64}$`)

// CheckSHA256 requires a lower-case 64-digit hex SHA-256.
func CheckSHA256(h string) error {
	if !sha256Hex.MatchString(h) {
		return errors.New("--ipsw-sha256 must be 64 lower-case hex digits")
	}
	return nil
}

// VerifySHA256 hashes the file at path and compares it with want. Any difference is an error.
func VerifySHA256(path, want string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return verifyReader(f, want)
}

func verifyReader(r io.Reader, want string) error {
	h := sha256.New()
	if _, err := io.Copy(h, r); err != nil {
		return err
	}
	if got := hex.EncodeToString(h.Sum(nil)); got != want {
		return fmt.Errorf("sha256 mismatch: got %s, want %s", got, want)
	}
	return nil
}

// FetchVerified makes sure dst holds the file at rawURL with SHA-256 want. A cached dst that
// verifies is kept (cached is true). Otherwise the file is downloaded over HTTPS (redirects must
// stay on HTTPS) to dst+".partial", verified, and only then renamed into place; a mismatch
// deletes the download and fails.
func FetchVerified(ctx context.Context, client *http.Client, rawURL, dst, want string) (cached bool, err error) {
	if err := CheckSHA256(want); err != nil {
		return false, err
	}
	u, err := url.Parse(rawURL)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return false, errors.New("--ipsw-url must be an https URL")
	}
	if err := VerifySHA256(dst, want); err == nil {
		return true, nil
	}
	_ = os.Remove(dst) // missing, or a stale/corrupt copy

	c := *client
	c.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if req.URL.Scheme != "https" {
			return errors.New("redirect to a non-https URL refused")
		}
		if len(via) >= 10 {
			return errors.New("too many redirects")
		}
		return nil
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return false, err
	}
	resp, err := c.Do(req)
	if err != nil {
		return false, fmt.Errorf("download failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("download failed: HTTP %d", resp.StatusCode)
	}

	part := dst + ".partial"
	_ = os.Remove(part)
	f, err := os.OpenFile(part, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return false, err
	}
	defer os.Remove(part) // no-op after the rename
	h := sha256.New()
	_, err = io.Copy(io.MultiWriter(f, h), resp.Body)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return false, fmt.Errorf("download failed: %w", err)
	}
	if got := hex.EncodeToString(h.Sum(nil)); got != want {
		return false, fmt.Errorf("sha256 mismatch: got %s, want %s", got, want)
	}
	return false, os.Rename(part, dst)
}

// MinBaseDiskBytes is the smallest disk create-base accepts: macOS plus the toolchain recipes
// need room, and the disk cannot be grown in the image format.
const MinBaseDiskBytes = 64 << 30

// CheckBaseArgs validates the static arguments of create-base before anything touches the host.
func CheckBaseArgs(ipswURL, ipswSHA256, to string, diskBytes uint64) error {
	if u, err := url.Parse(ipswURL); err != nil || u.Scheme != "https" || u.Host == "" {
		return errors.New("--ipsw-url must be an https URL")
	}
	if err := CheckSHA256(ipswSHA256); err != nil {
		return err
	}
	if err := CheckBaseRef(to); err != nil {
		return err
	}
	if diskBytes < MinBaseDiskBytes {
		return fmt.Errorf("--disk-gib must be at least %d", MinBaseDiskBytes>>30)
	}
	return nil
}

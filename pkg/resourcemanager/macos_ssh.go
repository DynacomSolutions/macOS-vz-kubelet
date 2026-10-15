package resourcemanager

import (
	"context"
	"encoding/base64"
	"os"
	"strings"

	"golang.org/x/crypto/ssh"

	"github.com/agoda-com/macOS-vz-kubelet/internal/envcfg"
	vzssh "github.com/agoda-com/macOS-vz-kubelet/internal/ssh"
	"github.com/agoda-com/macOS-vz-kubelet/internal/sshconn"

	"github.com/virtual-kubelet/virtual-kubelet/errdefs"
)

// sshDialFunc returns a DialFunc that dials the VM's current IP with the
// configured auth. The sshconn.Connection owns keepalive; this starts none.
func (c *MacOSClient) sshDialFunc(namespace, name string) sshconn.DialFunc {
	return func(ctx context.Context) (*ssh.Client, error) {
		info, ok := c.vms.Load(namespace, name)
		if !ok {
			return nil, errdefs.NotFound("virtual machine not found")
		}
		ipAddr := info.Resource.IPAddress()
		if ipAddr == "" {
			return nil, errdefs.InvalidInputf("virtual machine does not have an IP address")
		}
		config, err := SSHClientConfig()
		if err != nil {
			return nil, err
		}
		return vzssh.DialContext(ctx, "tcp", ipAddr+":22", config)
	}
}

// SSHClientConfig builds the guest SSH client config from the VZ_SSH_* environment variables.
func SSHClientConfig() (*ssh.ClientConfig, error) {
	sshUser, sshAuth, err := getSSHAuthMethods()
	if err != nil {
		return nil, err
	}
	config := &ssh.ClientConfig{
		User:            sshUser,
		Auth:            sshAuth,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         envcfg.SSHDialTimeout(),
	}
	if kexList := strings.TrimSpace(os.Getenv("VZ_SSH_KEX_ALGORITHMS")); kexList != "" {
		config.KeyExchanges = strings.Split(kexList, ",")
	}
	return config, nil
}

// getSSHAuthMethods retrieves SSH auth methods from environment variables.
func getSSHAuthMethods() (string, []ssh.AuthMethod, error) {
	sshUser := os.Getenv("VZ_SSH_USER")
	if sshUser == "" {
		return "", nil, errdefs.InvalidInputf("VZ_SSH_USER env variable is required")
	}

	var auth []ssh.AuthMethod

	signer, err := privateKeySigner()
	if err != nil {
		return "", nil, err
	}
	if signer != nil {
		auth = append(auth, ssh.PublicKeys(signer))
	}

	if sshPassword := os.Getenv("VZ_SSH_PASSWORD"); sshPassword != "" {
		auth = append(auth, ssh.Password(sshPassword))
	}

	if len(auth) == 0 {
		return "", nil, errdefs.InvalidInputf("VZ_SSH_PRIVATE_KEY_BASE64, VZ_SSH_PRIVATE_KEY_PATH, or VZ_SSH_PASSWORD env variable is required")
	}

	return sshUser, auth, nil
}

// privateKeySigner loads the key named by VZ_SSH_PRIVATE_KEY_BASE64 or VZ_SSH_PRIVATE_KEY_PATH;
// it returns nil, nil when neither is set.
func privateKeySigner() (ssh.Signer, error) {
	privateKey := ""
	if keyBase64 := strings.TrimSpace(os.Getenv("VZ_SSH_PRIVATE_KEY_BASE64")); keyBase64 != "" {
		keyData, err := base64.StdEncoding.DecodeString(keyBase64)
		if err != nil {
			return nil, errdefs.InvalidInputf("failed to decode VZ_SSH_PRIVATE_KEY_BASE64: %v", err)
		}
		privateKey = string(keyData)
	} else if keyPath := strings.TrimSpace(os.Getenv("VZ_SSH_PRIVATE_KEY_PATH")); keyPath != "" {
		keyData, err := os.ReadFile(keyPath)
		if err != nil {
			return nil, errdefs.InvalidInputf("failed to read VZ_SSH_PRIVATE_KEY_PATH: %v", err)
		}
		privateKey = string(keyData)
	}
	if privateKey == "" {
		return nil, nil
	}

	var signer ssh.Signer
	var err error
	if passphrase := os.Getenv("VZ_SSH_PRIVATE_KEY_PASSPHRASE"); passphrase != "" {
		signer, err = ssh.ParsePrivateKeyWithPassphrase([]byte(privateKey), []byte(passphrase))
	} else {
		signer, err = ssh.ParsePrivateKey([]byte(privateKey))
	}
	if err != nil {
		return nil, errdefs.InvalidInputf("failed to parse VZ_SSH_PRIVATE_KEY: %v", err)
	}
	return signer, nil
}

// SSHAuthorizedKey returns the public half of the configured guest key as an authorized_keys line.
func SSHAuthorizedKey() (string, error) {
	signer, err := privateKeySigner()
	if err != nil {
		return "", err
	}
	if signer == nil {
		return "", errdefs.InvalidInputf("VZ_SSH_PRIVATE_KEY_BASE64 or VZ_SSH_PRIVATE_KEY_PATH env variable is required")
	}
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(signer.PublicKey()))), nil
}

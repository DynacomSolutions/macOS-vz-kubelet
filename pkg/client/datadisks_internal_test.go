package client

import (
	"testing"

	"github.com/agoda-com/macOS-vz-kubelet/pkg/resource"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	credentialprovider "k8s.io/kubernetes/pkg/credentialprovider"
)

func TestDataDiskParamsKeepOrderAndPerImageCredentials(t *testing.T) {
	keyring := &credentialprovider.BasicDockerKeyring{}
	keyring.Add(nil, credentialprovider.DockerConfig{
		"a.example.com": {Username: "user-a", Password: "pass-a"},
		"b.example.com": {Username: "user-b", Password: "pass-b"},
	})
	store := resource.NewRegistryCredentialStore(keyring)

	got := dataDiskParams([]string{"b.example.com/x/tools:1", "c.example.com/x/open:1", "a.example.com/x/xcode:16"}, store)
	require.Len(t, got, 3)
	assert.Equal(t, "b.example.com/x/tools:1", got[0].Ref)
	assert.Equal(t, "user-b", got[0].RegistryCreds.Username)
	assert.Equal(t, "c.example.com/x/open:1", got[1].Ref)
	assert.True(t, got[1].RegistryCreds.IsEmpty(), "no credentials for a registry without a secret")
	assert.Equal(t, "a.example.com/x/xcode:16", got[2].Ref)
	assert.Equal(t, "user-a", got[2].RegistryCreds.Username)
	assert.Empty(t, dataDiskParams(nil, store))
}

package resourcemanager

import (
	"context"
	"errors"
	"testing"

	vmdata "github.com/agoda-com/macOS-vz-kubelet/internal/data/vm"
	"github.com/agoda-com/macOS-vz-kubelet/pkg/resource"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/types"
)

// newPermitClient returns a client with two VMs, "a" and "b", each holding one of two permits.
func newPermitClient(t *testing.T) *MacOSClient {
	t.Helper()
	c := &MacOSClient{vms: vmdata.NewVirtualMachineData(), vmPermits: make(chan struct{}, 2)}
	for _, n := range []string{"a", "b"} {
		_, loaded := c.vms.LoadOrStore("ns", n, vmdata.VirtualMachineInfo{
			Resource:       resource.NewMacOSVirtualMachine(nil),
			PermitAcquired: true,
		})
		require.False(t, loaded)
		c.vmPermits <- struct{}{}
	}
	return c
}

// A pod deleted during its postStart hook must not make the late stopAfterPostStart take
// another VM's permit.
func TestStopAfterPostStartAfterDeleteKeepsOtherPermits(t *testing.T) {
	ctx := context.Background()
	c := newPermitClient(t)
	params := VirtualMachineParams{Namespace: "ns", Name: "a"}

	require.NoError(t, c.DeleteVirtualMachine(ctx, "ns", "a", 0))
	require.Len(t, c.vmPermits, 1)

	c.stopAfterPostStart(ctx, params, errors.New("ssh: connection closed")) // transport error after delete
	assert.Len(t, c.vmPermits, 1, "B still holds its permit")

	c.releasePermit(ctx, types.NamespacedName{Namespace: "ns", Name: "a"})
	assert.Len(t, c.vmPermits, 1, "releasing a permit for a missing entry never drains another")
}

// The hook error is stored with the stop, and the permit is released once.
func TestStopAfterPostStartRecordsErrorAndReleases(t *testing.T) {
	ctx := context.Background()
	c := newPermitClient(t)
	hookErr := errors.New("hook failed")

	c.stopAfterPostStart(ctx, VirtualMachineParams{Namespace: "ns", Name: "b"}, hookErr)

	info, ok := c.vms.Load("ns", "b")
	require.True(t, ok)
	assert.ErrorIs(t, info.Resource.Error(), hookErr)
	assert.Equal(t, resource.VirtualMachineStateFailed, info.Resource.State())
	assert.Len(t, c.vmPermits, 1, "only B's permit released")
}

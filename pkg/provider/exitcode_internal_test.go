package provider

import (
	"testing"

	"github.com/agoda-com/macOS-vz-kubelet/pkg/resource"

	"github.com/stretchr/testify/assert"
)

func TestTerminatedExitCode(t *testing.T) {
	vm := resource.NewMacOSVirtualMachine(nil)
	assert.Equal(t, int32(0), terminatedExitCode(&vm, 0), "no hook status recorded: fallback")
	assert.Equal(t, int32(1), terminatedExitCode(&vm, 1))

	vm.SetHookExitCode(3)
	assert.Equal(t, int32(3), terminatedExitCode(&vm, 0), "the hook's exit code wins")

	vm.SetHookExitCode(0)
	assert.Equal(t, int32(0), terminatedExitCode(&vm, 1), "a recorded zero is still the hook's code")

	assert.Equal(t, int32(7), terminatedExitCode(resource.LinuxOnlyVM{}, 7), "VMs without hook status use the fallback")
}

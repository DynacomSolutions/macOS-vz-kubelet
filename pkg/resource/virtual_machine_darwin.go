//go:build darwin

package resource

import (
	"time"

	"github.com/Code-Hex/vz/v3"
	"github.com/agoda-com/macOS-vz-kubelet/pkg/vm"
)

// Compile-time check: guestState* must stay equal to Code-Hex/vz VirtualMachineState.
// A mismatch is an invalid array index and the package does not build.
var (
	_ = [1]struct{}{}[int(vz.VirtualMachineStateStopped)-guestStateStopped]
	_ = [1]struct{}{}[int(vz.VirtualMachineStateRunning)-guestStateRunning]
	_ = [1]struct{}{}[int(vz.VirtualMachineStateStarting)-guestStateStarting]
	_ = [1]struct{}{}[int(vz.VirtualMachineStateStopping)-guestStateStopping]
)

// vzGuest adapts *vm.VirtualMachineInstance. It lives in this file so the rest of
// the package does not import the Darwin-only Virtualization bindings.
type vzGuest struct {
	vm *vm.VirtualMachineInstance
}

func (g vzGuest) state() int {
	return int(g.vm.State())
}

func (g vzGuest) ip() string {
	return g.vm.IPAddress
}

func (g vzGuest) startedAt() *time.Time {
	return g.vm.StartedAt
}

func (g vzGuest) finishedAt() *time.Time {
	return g.vm.FinishedAt
}

// Instance returns the internal VirtualMachineInstance.
func (m *MacOSVirtualMachine) Instance() *vm.VirtualMachineInstance {
	g, ok := m.guest.(vzGuest)
	if !ok {
		return nil
	}
	return g.vm
}

// SetInstance sets the internal VirtualMachineInstance.
func (m *MacOSVirtualMachine) SetInstance(instance *vm.VirtualMachineInstance) {
	if instance == nil {
		m.guest = nil
		return
	}
	m.guest = vzGuest{vm: instance}
}

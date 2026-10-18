//go:build darwin && arm64

package vzvnc

import (
	"path/filepath"
	"testing"

	"github.com/Code-Hex/vz/v3"
)

// vmPointer reads an unexported field of Code-Hex/vz, so a library update must fail here, not in a build.
func TestVMPointer(t *testing.T) {
	store, err := vz.NewEFIVariableStore(filepath.Join(t.TempDir(), "efi"), vz.WithCreatingEFIVariableStore())
	if err != nil {
		t.Skipf("no EFI variable store: %v", err)
	}
	boot, err := vz.NewEFIBootLoader(vz.WithEFIVariableStore(store))
	if err != nil {
		t.Skipf("no EFI boot loader: %v", err)
	}
	cfg, err := vz.NewVirtualMachineConfiguration(boot, 1, 4<<30)
	if err != nil {
		t.Skipf("no configuration: %v", err)
	}
	// An invalid configuration raises an Objective-C exception that kills the test binary: check first.
	if ok, verr := cfg.Validate(); verr != nil || !ok {
		t.Skipf("configuration is not valid on this host: %v", verr)
	}
	machine, err := vz.NewVirtualMachine(cfg)
	if err != nil {
		t.Skipf("no virtual machine: %v", err)
	}
	if vmPointer(machine) == nil {
		t.Fatal("vmPointer returned nil: Code-Hex/vz layout changed")
	}
}

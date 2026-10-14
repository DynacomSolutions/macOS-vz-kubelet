// Package vmcap resolves how many macOS VMs this host may run.
package vmcap

import (
	"fmt"
	"os"
	"strconv"
)

const (
	// Default is the number of macOS VMs Apple's licence and the host kernel allow.
	Default = 2

	// EnvMaxVMs overrides the cap. Values above Default also need EnvAcceptLicenceRisk.
	EnvMaxVMs = "VZ_MAX_MACOS_VMS"
	// EnvAcceptLicenceRisk must be "true" to raise the cap above Default.
	EnvAcceptLicenceRisk = "VZ_ACCEPT_APPLE_VM_LICENCE_RISK"
)

// Parse resolves the cap from the raw EnvMaxVMs and EnvAcceptLicenceRisk values.
// An empty maxVMs gives Default.
func Parse(maxVMs, acceptRisk string) (int, error) {
	if maxVMs == "" {
		return Default, nil
	}
	n, err := strconv.Atoi(maxVMs)
	if err != nil || n < 1 {
		return 0, fmt.Errorf("%s=%q is invalid: want an integer of at least 1", EnvMaxVMs, maxVMs)
	}
	if n > Default && acceptRisk != "true" {
		return 0, fmt.Errorf("%s=%d is above %d: Apple's macOS licence allows %d VMs per host, and the host kernel quota (hv_apple_isa_vm_quota) must also be raised; set %s=true to accept the licence risk",
			EnvMaxVMs, n, Default, Default, EnvAcceptLicenceRisk)
	}
	return n, nil
}

// FromEnv resolves the cap from the process environment.
func FromEnv() (int, error) {
	return Parse(os.Getenv(EnvMaxVMs), os.Getenv(EnvAcceptLicenceRisk))
}

// Configured returns the cap, or Default on a bad configuration. Startup calls FromEnv first and refuses to run on error.
func Configured() int {
	if n, err := FromEnv(); err == nil {
		return n
	}
	return Default
}

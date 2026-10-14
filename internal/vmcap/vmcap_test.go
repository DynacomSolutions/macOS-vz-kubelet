package vmcap_test

import (
	"testing"

	"github.com/agoda-com/macOS-vz-kubelet/internal/vmcap"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParse(t *testing.T) {
	tests := []struct {
		name, max, risk string
		want            int
		errContains     string
	}{
		{name: "unset gives default", want: 2},
		{name: "explicit 1", max: "1", want: 1},
		{name: "explicit 2 needs no opt-in", max: "2", want: 2},
		{name: "3 without opt-in refused", max: "3", errContains: "hv_apple_isa_vm_quota"},
		{name: "3 with false refused", max: "3", risk: "false", errContains: "licence allows 2 VMs"},
		{name: "3 with opt-in", max: "3", risk: "true", want: 3},
		{name: "zero invalid", max: "0", errContains: "invalid"},
		{name: "text invalid", max: "many", risk: "true", errContains: "invalid"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := vmcap.Parse(tc.max, tc.risk)
			if tc.errContains != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.errContains)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestConfiguredFallsBackToDefault(t *testing.T) {
	t.Setenv(vmcap.EnvMaxVMs, "5")
	t.Setenv(vmcap.EnvAcceptLicenceRisk, "")
	assert.Equal(t, vmcap.Default, vmcap.Configured())
	t.Setenv(vmcap.EnvAcceptLicenceRisk, "true")
	assert.Equal(t, 5, vmcap.Configured())
}

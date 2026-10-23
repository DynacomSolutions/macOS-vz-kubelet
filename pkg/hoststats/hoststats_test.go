package hoststats_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/agoda-com/macOS-vz-kubelet/pkg/hoststats"
)

func TestTicksToNanoSecondsNoOverflow(t *testing.T) {
	assert.Equal(t, uint64(1_500_000_000), hoststats.TicksToNanoSeconds(150, 100))
	assert.Equal(t, uint64(0), hoststats.TicksToNanoSeconds(5, 0))
	// 10 cores for 10 years at 100 Hz: ticks*1e9 alone would exceed 2^64.
	ticks := uint64(10 * 10 * 365 * 24 * 3600 * 100)
	assert.Equal(t, ticks/100*1_000_000_000, hoststats.TicksToNanoSeconds(ticks, 100))
}

func TestNanoCores(t *testing.T) {
	// 200 ticks at 100 Hz = 2 core-seconds over 4s = 0.5 core.
	assert.Equal(t, uint64(500_000_000), hoststats.NanoCores(200, 100, 4*time.Second))
	assert.Equal(t, uint64(0), hoststats.NanoCores(200, 100, 0))
}

func TestMemoryBytes(t *testing.T) {
	r := hoststats.Raw{PageSize: 16384, Active: 10, Inactive: 5, Wired: 3, Compress: 2, TotalMem: 100 * 16384}
	usage, ws, avail := hoststats.MemoryBytes(r)
	assert.Equal(t, uint64(20*16384), usage)
	assert.Equal(t, uint64(15*16384), ws)
	assert.Equal(t, uint64(85*16384), avail)

	r.TotalMem = 1
	_, _, avail = hoststats.MemoryBytes(r)
	assert.Equal(t, uint64(0), avail, "available floors at zero")
}

func TestSamplerCumulativeRateAndWrap(t *testing.T) {
	boot := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	clock := time.Date(2026, 10, 24, 0, 0, 0, 0, time.UTC)
	raw := hoststats.Raw{BusyTicks: 0xFFFFFF00, ClkTck: 100, PageSize: 4096, Active: 1, TotalMem: 1 << 20, BootTime: boot}
	s := hoststats.NewWithSource(func() (hoststats.Raw, error) { return raw, nil }, func() time.Time { return clock })

	n, err := s.NodeStats()
	require.NoError(t, err)
	assert.Nil(t, n.CPU.UsageNanoCores, "no rate on the first read")
	assert.Equal(t, hoststats.TicksToNanoSeconds(0xFFFFFF00, 100), *n.CPU.UsageCoreNanoSeconds)
	assert.True(t, n.StartTime.Time.Equal(boot))
	assert.Equal(t, uint64(4096), *n.Memory.WorkingSetBytes)

	// Counter wraps: 0xFFFFFF00 -> 0x00000100 is +512 ticks over 10s.
	raw.BusyTicks = 0x100
	clock = clock.Add(10 * time.Second)
	n, err = s.NodeStats()
	require.NoError(t, err)
	assert.Equal(t, hoststats.TicksToNanoSeconds(0xFFFFFF00+512, 100), *n.CPU.UsageCoreNanoSeconds)
	require.NotNil(t, n.CPU.UsageNanoCores)
	assert.Equal(t, hoststats.NanoCores(512, 100, 10*time.Second), *n.CPU.UsageNanoCores)

	// A read under the minimum window keeps the previous rate and still advances the counter.
	raw.BusyTicks += 100
	clock = clock.Add(100 * time.Millisecond)
	n2, err := s.NodeStats()
	require.NoError(t, err)
	assert.Equal(t, *n.CPU.UsageNanoCores, *n2.CPU.UsageNanoCores)
	assert.Greater(t, *n2.CPU.UsageCoreNanoSeconds, *n.CPU.UsageCoreNanoSeconds)
}

// Package hoststats reports CPU and memory use of the macOS host the kubelet runs on, in the
// kubelet stats/summary NodeStats shape, so metrics-server and Headlamp can show node usage.
//
// The platform reader (host_darwin.go) only collects raw counters; all conversion lives here so
// it can be unit tested on any OS. Counters follow the same definitions the guest stats script
// in pkg/resourcemanager/macos_stats.go uses: CPU busy = user+system+nice ticks, memory usage =
// active+inactive+wired+compressor pages, working set = active+wired+compressor pages.
package hoststats

import (
	"errors"
	"sync"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	stats "k8s.io/kubelet/pkg/apis/stats/v1alpha1"
)

// ErrUnsupported is returned on platforms without a host reader.
var ErrUnsupported = errors.New("host stats are only available on darwin")

// minRateWindow is the shortest gap between two reads that yields a usageNanoCores rate; closer
// reads reuse the previous rate, since a few ticks over a few milliseconds is mostly rounding.
const minRateWindow = time.Second

// Raw is one reading of the host counters.
type Raw struct {
	BusyTicks uint32 // user+system+nice, aggregate over all cores, wraps at 2^32
	ClkTck    uint64 // ticks per second
	PageSize  uint64
	Active    uint64 // pages
	Inactive  uint64
	Wired     uint64
	Compress  uint64
	TotalMem  uint64 // bytes
	BootTime  time.Time
}

// Source reads the raw host counters.
type Source func() (Raw, error)

// Sampler turns raw readings into NodeStats. Safe for concurrent use.
type Sampler struct {
	src Source
	now func() time.Time

	mu       sync.Mutex
	primed   bool
	lastRaw  uint32
	cumTicks uint64 // monotonic busy ticks: first reading (since boot) plus wrap-safe deltas
	lastAt   time.Time
	lastCum  uint64
	rate     *uint64
}

// New returns a Sampler reading the real host.
func New() *Sampler { return NewWithSource(readHost, time.Now) }

// NewWithSource returns a Sampler over src; now supplies the clock.
func NewWithSource(src Source, now func() time.Time) *Sampler {
	return &Sampler{src: src, now: now}
}

// NodeStats reads the host and returns cpu, memory and startTime filled in. NodeName is left to
// the caller.
func (s *Sampler) NodeStats() (stats.NodeStats, error) {
	raw, err := s.src()
	if err != nil {
		return stats.NodeStats{}, err
	}
	at := s.now()

	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.primed {
		s.cumTicks = uint64(raw.BusyTicks)
		s.lastAt, s.lastCum, s.primed = at, s.cumTicks, true
	} else {
		s.cumTicks += uint64(raw.BusyTicks - s.lastRaw) // uint32 subtraction handles the wrap
		if win := at.Sub(s.lastAt); win >= minRateWindow {
			r := NanoCores(s.cumTicks-s.lastCum, raw.ClkTck, win)
			s.rate = &r
			s.lastAt, s.lastCum = at, s.cumTicks
		}
	}
	s.lastRaw = raw.BusyTicks

	t := metav1.NewTime(at)
	cum := TicksToNanoSeconds(s.cumTicks, raw.ClkTck)
	var rate *uint64
	if s.rate != nil {
		v := *s.rate
		rate = &v
	}
	usage, ws, avail := MemoryBytes(raw)
	return stats.NodeStats{
		StartTime: metav1.NewTime(raw.BootTime),
		CPU:       &stats.CPUStats{Time: t, UsageNanoCores: rate, UsageCoreNanoSeconds: &cum},
		Memory:    &stats.MemoryStats{Time: t, UsageBytes: &usage, WorkingSetBytes: &ws, AvailableBytes: &avail},
	}, nil
}

// TicksToNanoSeconds converts clock ticks to nanoseconds without overflowing uint64 on large
// counters (ticks*1e9 would overflow after about 5 core-years at 100 Hz).
func TicksToNanoSeconds(ticks, clkTck uint64) uint64 {
	if clkTck == 0 {
		return 0
	}
	const ns = uint64(time.Second)
	return ticks/clkTck*ns + ticks%clkTck*ns/clkTck
}

// NanoCores returns the average CPU use, in nanocores, of delta ticks over window.
func NanoCores(deltaTicks, clkTck uint64, window time.Duration) uint64 {
	if window <= 0 {
		return 0
	}
	return uint64(float64(TicksToNanoSeconds(deltaTicks, clkTck)) / window.Seconds())
}

// MemoryBytes returns usage, working set and available bytes. Available is total minus working
// set, as the kubelet defines it, floored at zero.
func MemoryBytes(r Raw) (usage, workingSet, available uint64) {
	usage = (r.Active + r.Inactive + r.Wired + r.Compress) * r.PageSize
	workingSet = (r.Active + r.Wired + r.Compress) * r.PageSize
	if r.TotalMem > workingSet {
		available = r.TotalMem - workingSet
	}
	return usage, workingSet, available
}

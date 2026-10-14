package envcfg

import (
	"os"
	"strconv"
	"strings"
)

// DefaultMinFreeBytes is the free-space floor the image cache must leave on the
// host volume (15 GiB).
const DefaultMinFreeBytes uint64 = 15 << 30

// MinFreeBytes returns the free-space floor for macOS image pulls, overridable
// via VZ_MIN_FREE_BYTES (a decimal byte count; 0 disables the guard). An empty,
// blank, unparseable, or negative value falls back to the default.
func MinFreeBytes() uint64 {
	return ResolveMinFreeBytes(os.Getenv("VZ_MIN_FREE_BYTES"))
}

// ResolveMinFreeBytes parses the raw VZ_MIN_FREE_BYTES value; see MinFreeBytes.
func ResolveMinFreeBytes(envValue string) uint64 {
	v, err := strconv.ParseUint(strings.TrimSpace(envValue), 10, 64)
	if err != nil {
		return DefaultMinFreeBytes
	}
	return v
}

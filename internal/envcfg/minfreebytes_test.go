package envcfg

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestResolveMinFreeBytes(t *testing.T) {
	t.Parallel()

	tests := []struct {
		in   string
		want uint64
	}{
		{"", DefaultMinFreeBytes},
		{"  ", DefaultMinFreeBytes},
		{"junk", DefaultMinFreeBytes},
		{"-5", DefaultMinFreeBytes},
		{"0", 0},
		{" 1048576 ", 1048576},
	}
	for _, tt := range tests {
		assert.Equal(t, tt.want, ResolveMinFreeBytes(tt.in), "input %q", tt.in)
	}
	assert.Equal(t, uint64(15*1024*1024*1024), DefaultMinFreeBytes)
}

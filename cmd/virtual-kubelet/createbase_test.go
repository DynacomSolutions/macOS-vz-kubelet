package main

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

const (
	cbSHA = "0000000000000000000000000000000000000000000000000000000000000000"
	cbURL = "https://updates.cdn-apple.com/a.ipsw"
	cbTo  = "registry.s.dynacom.dev/macos-vz/tahoe-base:26.5"
)

func TestCreateBaseMainArguments(t *testing.T) {
	base := []string{"--ipsw-url", cbURL, "--ipsw-sha256", cbSHA, "--to", cbTo, "--script", "/s.sh", "--creds", "/c.json"}
	with := func(flag, val string) []string {
		out := append([]string{}, base...)
		for i := range out {
			if out[i] == flag {
				out[i+1] = val
			}
		}
		return out
	}
	assert.Equal(t, 2, createBaseMain(nil), "missing flags")
	assert.Equal(t, 2, createBaseMain(with("--to", "ghcr.io/x/y:1")), "foreign registry")
	assert.Equal(t, 2, createBaseMain(with("--to", "registry.s.dynacom.dev/other/y:1")), "wrong namespace")
	assert.Equal(t, 2, createBaseMain(with("--ipsw-sha256", "abc")), "bad sha")
	assert.Equal(t, 2, createBaseMain(with("--ipsw-url", "http://example.com/a.ipsw")), "plain http")
	if os.Geteuid() != 0 {
		assert.Equal(t, 1, createBaseMain(base), "not root")
	}
}

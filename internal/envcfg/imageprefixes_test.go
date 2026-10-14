package envcfg

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseImagePrefixes(t *testing.T) {
	assert.Empty(t, ParseImagePrefixes(""))
	assert.Empty(t, ParseImagePrefixes(" , ,"))
	assert.Equal(t, []string{"a/", "b/c/"}, ParseImagePrefixes(" a/ , b/c/,"))
}

func TestImageAllowed(t *testing.T) {
	p := ParseImagePrefixes("registry.s.dynacom.dev/macos-vz/")
	assert.True(t, ImageAllowed(p, "registry.s.dynacom.dev/macos-vz/tahoe-xcode:26"))
	assert.False(t, ImageAllowed(p, "registry.s.dynacom.dev.evil.com/macos-vz/x:1"))
	assert.False(t, ImageAllowed(p, "registry.s.dynacom.dev/macos-vz-evil/x:1"))
	assert.False(t, ImageAllowed(p, "registry.s.dynacom.dev/other/x:1"))
	assert.False(t, ImageAllowed(p, "alpine:3"))
	assert.False(t, ImageAllowed(p, ""))
	assert.True(t, ImageAllowed(nil, "anything"), "empty list keeps upstream behaviour")
	assert.True(t, ImageAllowed(ParseImagePrefixes("x/,registry.s.dynacom.dev/macos-vz/"), "registry.s.dynacom.dev/macos-vz/a"))
}

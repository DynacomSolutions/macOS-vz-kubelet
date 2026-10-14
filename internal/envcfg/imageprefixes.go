package envcfg

import (
	"os"
	"strings"
)

// AllowedImagePrefixes returns the image prefixes macOS Pods may use, from the
// comma-separated VZ_ALLOWED_IMAGE_PREFIXES. Empty means no restriction.
func AllowedImagePrefixes() []string {
	return ParseImagePrefixes(os.Getenv("VZ_ALLOWED_IMAGE_PREFIXES"))
}

// ParseImagePrefixes splits a comma-separated prefix list, trimming blanks.
func ParseImagePrefixes(envValue string) (prefixes []string) {
	for _, p := range strings.Split(envValue, ",") {
		if p = strings.TrimSpace(p); p != "" {
			prefixes = append(prefixes, p)
		}
	}
	return prefixes
}

// ImageAllowed reports whether image starts with one of prefixes, compared literally
// (so "host/ns/" does not match "host.evil/ns/x"). No prefixes allows everything.
func ImageAllowed(prefixes []string, image string) bool {
	if len(prefixes) == 0 {
		return true
	}
	for _, p := range prefixes {
		if strings.HasPrefix(image, p) {
			return true
		}
	}
	return false
}

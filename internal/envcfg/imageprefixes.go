package envcfg

import (
	"fmt"
	"os"
	"strings"
)

// AllowedImagePrefixes returns the image prefixes macOS Pods may use, from the
// comma-separated VZ_ALLOWED_IMAGE_PREFIXES. Empty means no restriction.
// It returns an error for an invalid list; call it at startup so a bad value stops the provider.
func AllowedImagePrefixes() ([]string, error) {
	return ParseImagePrefixes(os.Getenv("VZ_ALLOWED_IMAGE_PREFIXES"))
}

// ParseImagePrefixes splits a comma-separated prefix list, trimming blanks. Every
// entry must end in "/": a bare "host/ns" would also match "host/ns-evil/x".
func ParseImagePrefixes(envValue string) (prefixes []string, err error) {
	for _, p := range strings.Split(envValue, ",") {
		if p = strings.TrimSpace(p); p == "" {
			continue
		}
		if !strings.HasSuffix(p, "/") {
			return nil, fmt.Errorf("VZ_ALLOWED_IMAGE_PREFIXES entry %q must end in \"/\"", p)
		}
		prefixes = append(prefixes, p)
	}
	return prefixes, nil
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

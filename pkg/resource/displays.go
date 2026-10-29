package resource

import (
	"fmt"
	"strconv"
	"strings"

	corev1 "k8s.io/api/core/v1"
)

// DisplaysAnnotation lists the macOS VM's displays as comma-separated WIDTHxHEIGHT,
// with an optional @PPI (for example "1920x1200,1920x1080" or "1920x1200@80,1920x1080@80").
// The first entry is the main display. The framebuffer size is fixed at boot, so a
// topology change needs a new Pod.
const DisplaysAnnotation = "dynacom.dev/displays"

// MaxDisplays is the most displays one Pod may attach.
const MaxDisplays = 4

// Default display used when DisplaysAnnotation is absent. This is the size
// createGraphicsDeviceConfiguration used before the annotation existed.
const (
	DefaultDisplayWidth  int64 = 1920
	DefaultDisplayHeight int64 = 1200
	DefaultDisplayPPI    int64 = 80
)

const (
	minDisplayEdge int64 = 640
	maxDisplayEdge int64 = 7680
	minDisplayPPI  int64 = 50
	maxDisplayPPI  int64 = 300
)

// Display is one Mac graphics display. Width and Height are pixels. PPI is
// pixels per inch. The first display in a list is the main display.
type Display struct {
	Width  int64
	Height int64
	PPI    int64
}

// DefaultDisplay is the single display used when DisplaysAnnotation is absent.
func DefaultDisplay() Display {
	return Display{Width: DefaultDisplayWidth, Height: DefaultDisplayHeight, PPI: DefaultDisplayPPI}
}

// Displays returns the pod's displays. A missing annotation is one default display
// (1920x1200 at 80 ppi). An empty annotation, an empty entry, a bad token, a value
// outside the allowed range, or more than MaxDisplays is an error that names
// DisplaysAnnotation. Identical sizes are allowed (two 1920x1080 monitors is a
// valid topology). Order is preserved. Callers must not replace an error with
// the default display.
func Displays(pod *corev1.Pod) ([]Display, error) {
	v, ok := pod.Annotations[DisplaysAnnotation]
	if !ok {
		return []Display{DefaultDisplay()}, nil
	}
	v = strings.TrimSpace(v)
	if v == "" {
		return nil, fmt.Errorf("annotation %s is empty", DisplaysAnnotation)
	}
	parts := strings.Split(v, ",")
	if len(parts) > MaxDisplays {
		return nil, fmt.Errorf("annotation %s lists %d displays, the maximum is %d", DisplaysAnnotation, len(parts), MaxDisplays)
	}
	out := make([]Display, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			return nil, fmt.Errorf("annotation %s has an empty entry", DisplaysAnnotation)
		}
		d, err := parseDisplay(p)
		if err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, nil
}

func parseDisplay(token string) (Display, error) {
	if strings.Count(token, "@") > 1 {
		return Display{}, invalidDisplay(token)
	}
	body := token
	ppi := DefaultDisplayPPI
	if before, ppiRaw, ok := strings.Cut(token, "@"); ok {
		n, good := parseDecimal(ppiRaw)
		if !good {
			return Display{}, invalidDisplay(token)
		}
		body = before
		ppi = n
	}
	if strings.Count(body, "x") != 1 {
		return Display{}, invalidDisplay(token)
	}
	wRaw, hRaw, _ := strings.Cut(body, "x")
	width, okW := parseDecimal(wRaw)
	height, okH := parseDecimal(hRaw)
	if !okW || !okH {
		return Display{}, invalidDisplay(token)
	}
	if width < minDisplayEdge || width > maxDisplayEdge {
		return Display{}, outOfRange(token, "width", width, minDisplayEdge, maxDisplayEdge)
	}
	if height < minDisplayEdge || height > maxDisplayEdge {
		return Display{}, outOfRange(token, "height", height, minDisplayEdge, maxDisplayEdge)
	}
	if ppi < minDisplayPPI || ppi > maxDisplayPPI {
		return Display{}, outOfRange(token, "ppi", ppi, minDisplayPPI, maxDisplayPPI)
	}
	return Display{Width: width, Height: height, PPI: ppi}, nil
}

// parseDecimal accepts a base-10 integer with no sign and no leading or trailing junk.
func parseDecimal(s string) (int64, bool) {
	if s == "" {
		return 0, false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, false
		}
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return 0, false
	}
	return n, true
}

func invalidDisplay(token string) error {
	return fmt.Errorf("annotation %s has invalid display %q", DisplaysAnnotation, token)
}

func outOfRange(token, what string, n, lo, hi int64) error {
	return fmt.Errorf("annotation %s display %q has %s %d out of range %d-%d", DisplaysAnnotation, token, what, n, lo, hi)
}

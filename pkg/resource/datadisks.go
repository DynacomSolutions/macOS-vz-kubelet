package resource

import (
	"fmt"
	"strings"

	corev1 "k8s.io/api/core/v1"
)

// DataDisksAnnotation lists the data disk images to attach to the macOS VM as read-only virtio
// block devices, after the boot disk and in the listed order: "<ref>,<ref>". A data disk is an
// image pushed by build-image --data-disk-gib.
const DataDisksAnnotation = "dynacom.dev/data-disks"

// MaxDataDisks is the most data disks one Pod may attach.
const MaxDataDisks = 4

// DataDisks returns the image references of the pod's data disks, or nil without the annotation.
// It rejects an empty entry, a duplicate and more than MaxDataDisks; whether each reference is
// pullable and allowed on this node is for the caller to check.
func DataDisks(pod *corev1.Pod) ([]string, error) {
	v, ok := pod.Annotations[DataDisksAnnotation]
	if !ok {
		return nil, nil
	}
	refs := strings.Split(v, ",")
	if len(refs) > MaxDataDisks {
		return nil, fmt.Errorf("annotation %s lists %d data disks, the maximum is %d", DataDisksAnnotation, len(refs), MaxDataDisks)
	}
	seen := make(map[string]bool, len(refs))
	for i, r := range refs {
		r = strings.TrimSpace(r)
		if r == "" {
			return nil, fmt.Errorf("annotation %s has an empty entry", DataDisksAnnotation)
		}
		if seen[r] {
			return nil, fmt.Errorf("annotation %s lists %q twice", DataDisksAnnotation, r)
		}
		seen[r] = true
		refs[i] = r
	}
	return refs, nil
}

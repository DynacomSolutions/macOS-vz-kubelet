package oci

import (
	"errors"
	"fmt"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"k8s.io/apimachinery/pkg/util/sets"
)

// MediaType represents a media type.
type MediaType string

const (
	// MediaTypeDiskImage specifies the media type for a disk image.
	MediaTypeDiskImage MediaType = "application/vnd.agoda.macosvz.disk.image.v1"

	// MediaTypeAuxImage specifies the media type for an auxiliary (nvram) image.
	MediaTypeAuxImage MediaType = "application/vnd.agoda.macosvz.aux.image.v1"

	// MediaTypeConfigV1 specifies the media type for a configuration.
	// Internal use only.
	MediaTypeConfigV1 MediaType = "application/vnd.agoda.macosvz.config.v1+json"
)

// mediaTypeToTitle maps media types to their titles.
var mediaTypeToTitle = map[MediaType]string{
	MediaTypeConfigV1:  "config.json",
	MediaTypeDiskImage: "disk.img",
	MediaTypeAuxImage:  "aux.img",
}

// Title returns the title of the media type.
func (mt MediaType) Title() string {
	return mediaTypeToTitle[mt]
}

// supportedMediaTypes contains the supported media types.
var supportedMediaTypes = sets.NewString(
	string(MediaTypeConfigV1),
	string(MediaTypeDiskImage),
	string(MediaTypeAuxImage),
)

// IsMediaTypeSupported checks if the media type is supported.
func IsMediaTypeSupported(mediaType string) bool {
	return supportedMediaTypes.Has(mediaType)
}

// ErrInvalidTitle is returned when a layer title is not the fixed file name of its media type.
var ErrInvalidTitle = errors.New("invalid layer title")

// ValidateTitle checks the title of a layer descriptor. The title becomes a file name
// under the cache directory, and a registry controls it, so it must be exactly the
// fixed name of the layer's media type (no separators, no traversal). An empty title is
// valid: such content never reaches the disk.
func ValidateTitle(d ocispec.Descriptor) error {
	name := d.Annotations[ocispec.AnnotationTitle]
	if name == "" {
		return nil
	}
	if want := MediaType(d.MediaType).Title(); want == "" || name != want {
		return fmt.Errorf("%w: %q for media type %s", ErrInvalidTitle, name, d.MediaType)
	}
	return nil
}

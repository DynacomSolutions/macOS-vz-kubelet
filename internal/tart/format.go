// Package tart imports Cirrus Labs Tart disk-v2 images without Virtualization.framework.
package tart

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math"
	"strconv"

	"github.com/agoda-com/macOS-vz-kubelet/pkg/oci"
	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

const (
	ConfigMediaType    = "application/vnd.cirruslabs.tart.config.v1"
	DiskMediaType      = "application/vnd.cirruslabs.tart.disk.v2"
	NVRAMMediaType     = "application/vnd.cirruslabs.tart.nvram.v1"
	SizeAnnotation     = "org.cirruslabs.tart.uncompressed-size"
	DigestAnnotation   = "org.cirruslabs.tart.uncompressed-content-digest"
	DiskSizeAnnotation = "org.cirruslabs.tart.uncompressed-disk-size"
	maxChunkSize       = 512 << 20
	maxMetadataSize    = 4 << 20
)

type Manifest struct {
	Config, NVRAM ocispec.Descriptor
	Disks         []ocispec.Descriptor
	DiskSize      int64
}

func chunkInfo(d ocispec.Descriptor) (int64, digest.Digest, error) {
	n, err := strconv.ParseInt(d.Annotations[SizeAnnotation], 10, 64)
	if err != nil || n <= 0 || n > maxChunkSize {
		return 0, "", fmt.Errorf("invalid Tart chunk size")
	}
	h := digest.Digest(d.Annotations[DigestAnnotation])
	if err := h.Validate(); err != nil {
		return 0, "", fmt.Errorf("invalid uncompressed digest: %w", err)
	}
	return n, h, nil
}

func ParseManifest(b []byte) (Manifest, error) {
	var raw ocispec.Manifest
	var m Manifest
	if err := json.Unmarshal(b, &raw); err != nil {
		return m, err
	}
	if raw.SchemaVersion != 2 || raw.MediaType != ocispec.MediaTypeImageManifest || raw.Config.MediaType != ocispec.MediaTypeImageConfig {
		return m, fmt.Errorf("expected Tart OCI image manifest")
	}
	for _, d := range raw.Layers {
		if err := d.Digest.Validate(); err != nil {
			return m, err
		}
		if d.Size <= 0 {
			return m, fmt.Errorf("invalid layer size")
		}
		switch d.MediaType {
		case ConfigMediaType:
			if m.Config.Size != 0 || d.Size > maxMetadataSize {
				return m, fmt.Errorf("duplicate or oversized Tart config")
			}
			m.Config = d
		case NVRAMMediaType:
			if m.NVRAM.Size != 0 || d.Size > 64<<20 {
				return m, fmt.Errorf("duplicate or oversized NVRAM")
			}
			m.NVRAM = d
		case DiskMediaType:
			n, _, err := chunkInfo(d)
			if err != nil {
				return m, err
			}
			if m.DiskSize > math.MaxInt64-n {
				return m, fmt.Errorf("disk size overflow")
			}
			m.DiskSize += n
			m.Disks = append(m.Disks, d)
		default:
			return m, fmt.Errorf("unsupported Tart layer %q", d.MediaType)
		}
	}
	if m.Config.Size == 0 || m.NVRAM.Size == 0 || len(m.Disks) == 0 {
		return m, fmt.Errorf("missing config, NVRAM or disk layers")
	}
	n, err := strconv.ParseInt(raw.Annotations[DiskSizeAnnotation], 10, 64)
	if err != nil || n != m.DiskSize {
		return m, fmt.Errorf("disk size annotation does not match chunks")
	}
	return m, nil
}

// ConvertConfig preserves the VZ data representations, both of which Tart stores as base64.
// See Sources/tart/VMConfig.swift and Sources/tart/Platform/Darwin.swift upstream.
func ConvertConfig(b []byte) (oci.Config, error) {
	var c struct {
		Version       int    `json:"version"`
		OS            string `json:"os"`
		Arch          string `json:"arch"`
		DiskFormat    string `json:"diskFormat"`
		HardwareModel string `json:"hardwareModel"`
		ECID          string `json:"ecid"`
	}
	if err := json.Unmarshal(b, &c); err != nil {
		return oci.Config{}, err
	}
	if c.Version != 1 || (c.OS != "" && c.OS != "darwin") || (c.Arch != "" && c.Arch != "arm64") || (c.DiskFormat != "" && c.DiskFormat != "raw") {
		return oci.Config{}, fmt.Errorf("only version 1 raw arm64 macOS Tart VMs are supported")
	}
	values := []*string{&c.HardwareModel, &c.ECID}
	for _, v := range values {
		decoded, err := base64.StdEncoding.Strict().DecodeString(*v)
		if err != nil || len(decoded) == 0 {
			return oci.Config{}, fmt.Errorf("invalid base64 hardwareModel or ecid")
		}
		*v = base64.StdEncoding.EncodeToString(decoded)
	}
	return oci.NewMacOSConfig(c.HardwareModel, c.ECID), nil
}

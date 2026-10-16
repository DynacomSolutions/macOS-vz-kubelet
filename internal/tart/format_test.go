package tart

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/agoda-com/macOS-vz-kubelet/pkg/oci"
	"github.com/opencontainers/go-digest"
	"github.com/opencontainers/image-spec/specs-go"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/stretchr/testify/require"
)

func TestConvertConfig(t *testing.T) {
	b, err := os.ReadFile("testdata/config.json")
	require.NoError(t, err)
	c, err := ConvertConfig(b)
	require.NoError(t, err)
	require.Equal(t, oci.NewMacOSConfig("aGFyZHdhcmUtbW9kZWw=", "bWFjaGluZS1pZGVudGlmaWVy"), c)
	encoded, err := json.Marshal(&c)
	require.NoError(t, err)
	var roundtrip oci.Config
	require.NoError(t, json.Unmarshal(encoded, &roundtrip))
	require.Equal(t, c, roundtrip)
	for _, change := range []map[string]any{{"ecid": "!"}, {"hardwareModel": ""}, {"os": "linux"}, {"arch": "amd64"}, {"diskFormat": "asif"}, {"version": 2}} {
		var obj map[string]any
		require.NoError(t, json.Unmarshal(b, &obj))
		for k, v := range change {
			obj[k] = v
		}
		bad, err := json.Marshal(obj)
		require.NoError(t, err)
		_, err = ConvertConfig(bad)
		require.Error(t, err)
	}
}

func fixtureManifest() ocispec.Manifest {
	desc := func(mt string) ocispec.Descriptor {
		return ocispec.Descriptor{MediaType: mt, Size: 10, Digest: digest.FromString(mt)}
	}
	disk := desc(DiskMediaType)
	disk.Annotations = map[string]string{SizeAnnotation: "512", DigestAnnotation: digest.FromString("disk").String()}
	return ocispec.Manifest{Versioned: specs.Versioned{SchemaVersion: 2}, MediaType: ocispec.MediaTypeImageManifest, Config: desc(ocispec.MediaTypeImageConfig), Layers: []ocispec.Descriptor{desc(ConfigMediaType), disk, desc(NVRAMMediaType)}, Annotations: map[string]string{DiskSizeAnnotation: "512"}}
}
func TestParseManifest(t *testing.T) {
	raw := fixtureManifest()
	b, err := json.Marshal(raw)
	require.NoError(t, err)
	m, err := ParseManifest(b)
	require.NoError(t, err)
	require.EqualValues(t, 512, m.DiskSize)
	require.Len(t, m.Disks, 1)
	for name, mutate := range map[string]func(*ocispec.Manifest){
		"missing":      func(m *ocispec.Manifest) { m.Layers = m.Layers[:2] },
		"duplicate":    func(m *ocispec.Manifest) { m.Layers = append(m.Layers, m.Layers[0]) },
		"unknown":      func(m *ocispec.Manifest) { m.Layers[1].MediaType = "disk.v1" },
		"size":         func(m *ocispec.Manifest) { m.Annotations[DiskSizeAnnotation] = "513" },
		"chunk-size":   func(m *ocispec.Manifest) { m.Layers[1].Annotations[SizeAnnotation] = "-1" },
		"chunk-digest": func(m *ocispec.Manifest) { delete(m.Layers[1].Annotations, DigestAnnotation) },
		"layer-digest": func(m *ocispec.Manifest) { m.Layers[1].Digest = "bad" },
		"schema":       func(m *ocispec.Manifest) { m.SchemaVersion = 1 },
	} {
		t.Run(name, func(t *testing.T) {
			m := fixtureManifest()
			mutate(&m)
			b, err := json.Marshal(m)
			require.NoError(t, err)
			_, err = ParseManifest(b)
			require.Error(t, err)
		})
	}
}

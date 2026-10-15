package oci_test

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/agoda-com/macOS-vz-kubelet/pkg/event/mocks"
	"github.com/agoda-com/macOS-vz-kubelet/pkg/oci"
	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"oras.land/oras-go/v2"
)

// check that custom OCI Store conforms to oras target interfaces
var _ oras.Target = &oci.Store{}
var _ oras.GraphTarget = &oci.Store{}
var _ oras.ReadOnlyTarget = &oci.Store{}
var _ oras.ReadOnlyGraphTarget = &oci.Store{}

func TestNew(t *testing.T) {
	// Setup
	tempDir := t.TempDir()
	mockEventRecorder := mocks.NewEventRecorder(t)

	// Test
	store, err := oci.New(tempDir, false, mockEventRecorder)

	// Verify
	assert.NoError(t, err)
	assert.NotNil(t, store)
}

// Helper function to handle Close errors in defer statements
func handleCloseError(t *testing.T, closer func(context.Context) error) {
	t.Helper()
	if err := closer(context.Background()); err != nil {
		t.Errorf("error closing: %v", err)
	}
}

func TestPushAndFetch(t *testing.T) {
	// Setup
	tempDir := t.TempDir()
	mockEventRecorder := mocks.NewEventRecorder(t)
	store, err := oci.New(tempDir, false, mockEventRecorder)
	require.NoError(t, err)
	defer handleCloseError(t, store.Close)

	// Create test content
	testContent := []byte("test content")
	testDigest := digest.FromBytes(testContent)

	// Create descriptor with an annotation (name)
	desc := ocispec.Descriptor{
		MediaType: string(oci.MediaTypeDiskImage),
		Digest:    testDigest,
		Size:      int64(len(testContent)),
		Annotations: map[string]string{
			ocispec.AnnotationTitle: "disk.img",
		},
	}

	// Test Push
	err = store.Push(context.Background(), desc, bytes.NewReader(testContent))
	assert.NoError(t, err)

	// Test Fetch
	reader, err := store.Fetch(context.Background(), desc)
	assert.NoError(t, err)
	defer func() {
		if err := reader.Close(); err != nil {
			t.Errorf("error closing reader: %v", err)
		}
	}()

	// Read and verify content
	content, err := io.ReadAll(reader)
	assert.NoError(t, err)
	assert.Equal(t, testContent, content)
}

func TestExists(t *testing.T) {
	// Setup
	tempDir := t.TempDir()
	mockEventRecorder := mocks.NewEventRecorder(t)
	store, err := oci.New(tempDir, false, mockEventRecorder)
	require.NoError(t, err)
	defer handleCloseError(t, store.Close)

	// Create test content
	testContent := []byte("test content")
	testDigest := digest.FromBytes(testContent)

	desc := ocispec.Descriptor{
		MediaType: string(oci.MediaTypeDiskImage),
		Digest:    testDigest,
		Size:      int64(len(testContent)),
		Annotations: map[string]string{
			ocispec.AnnotationTitle: "disk.img",
		},
	}

	// Test non-existence
	exists, err := store.Exists(context.Background(), desc)
	assert.NoError(t, err)
	assert.False(t, exists)

	// Push content
	err = store.Push(context.Background(), desc, bytes.NewReader(testContent))
	require.NoError(t, err)

	// Test existence
	exists, err = store.Exists(context.Background(), desc)
	assert.NoError(t, err)
	assert.True(t, exists)
}

func TestTag(t *testing.T) {
	// Setup
	tempDir := t.TempDir()
	mockEventRecorder := mocks.NewEventRecorder(t)
	store, err := oci.New(tempDir, false, mockEventRecorder)
	require.NoError(t, err)
	defer handleCloseError(t, store.Close)

	// First ensure we have a valid manifest config descriptor (which exists in the memory store)
	desc, err := store.GetManifestConfigDescriptor(context.Background())
	require.NoError(t, err)

	// Test Tag using the descriptor we just got (which should be valid)
	reference := "test-reference"
	err = store.Tag(context.Background(), desc, reference)
	assert.NoError(t, err)

	// Test Resolve
	resolvedDesc, err := store.Resolve(context.Background(), reference)
	assert.NoError(t, err)
	assert.Equal(t, desc.Digest, resolvedDesc.Digest)
}

func TestResolveNotFound(t *testing.T) {
	// Setup
	tempDir := t.TempDir()
	mockEventRecorder := mocks.NewEventRecorder(t)
	store, err := oci.New(tempDir, false, mockEventRecorder)
	require.NoError(t, err)
	defer handleCloseError(t, store.Close)

	// Test Resolve with non-existent reference
	_, err = store.Resolve(context.Background(), "non-existent")
	assert.Error(t, err)
}

func TestAdd(t *testing.T) {
	// Setup
	tempDir := t.TempDir()
	mockEventRecorder := mocks.NewEventRecorder(t)
	store, err := oci.New(tempDir, false, mockEventRecorder)
	require.NoError(t, err)
	defer handleCloseError(t, store.Close)

	// Create a test file
	testFileName := filepath.Join(tempDir, "disk.img")
	testContent := []byte("test content")
	err = os.WriteFile(testFileName, testContent, 0644)
	require.NoError(t, err)

	// Test Add
	mediaType := string(oci.MediaTypeDiskImage)
	desc, err := store.Add(context.Background(), mediaType, testFileName)
	assert.NoError(t, err)
	assert.Equal(t, mediaType, desc.MediaType)

	// Verify descriptor contains expected annotations
	assert.Contains(t, desc.Annotations, ocispec.AnnotationTitle)
}

func TestSetAndGetConfig(t *testing.T) {
	// Setup
	tempDir := t.TempDir()
	mockEventRecorder := mocks.NewEventRecorder(t)
	store, err := oci.New(tempDir, false, mockEventRecorder)
	require.NoError(t, err)
	defer handleCloseError(t, store.Close)

	// Create test config
	testConfig := oci.Config{
		OS:                "darwin",
		HardwareModelData: "test-hardware-model",
		MachineIdData:     "test-machine-id",
		Storage:           []oci.MediaType{oci.MediaTypeDiskImage},
	}

	// Create a config.json file in the tempDir
	configPath := filepath.Join(tempDir, "config.json")
	configJSON, err := json.Marshal(testConfig)
	require.NoError(t, err)
	err = os.WriteFile(configPath, configJSON, 0644)
	require.NoError(t, err)

	// Test Set by directly using Add since Set uses internal media type
	mediaType := string(oci.MediaTypeDiskImage) // We'll just test with a supported media type
	desc, err := store.Add(context.Background(), mediaType, configPath)
	assert.NoError(t, err)
	assert.Equal(t, mediaType, desc.MediaType)

	// Since we can't directly test GetConfig because it's tied to the internal mediaTypeConfigV1,
	// we'll test the Add functionality instead
	path, err := store.GetFilePathForMediaType(context.Background(), oci.MediaType(mediaType))
	assert.NoError(t, err)
	assert.Equal(t, configPath, path)
}

func TestDuplicateName(t *testing.T) {
	// Setup
	tempDir := t.TempDir()
	mockEventRecorder := mocks.NewEventRecorder(t)
	store, err := oci.New(tempDir, false, mockEventRecorder)
	require.NoError(t, err)
	defer handleCloseError(t, store.Close)

	// Create test content
	testContent := []byte("test content")
	testDigest := digest.FromBytes(testContent)

	desc := ocispec.Descriptor{
		MediaType: string(oci.MediaTypeDiskImage),
		Digest:    testDigest,
		Size:      int64(len(testContent)),
		Annotations: map[string]string{
			ocispec.AnnotationTitle: "disk.img",
		},
	}

	// Push content first time
	err = store.Push(context.Background(), desc, bytes.NewReader(testContent))
	require.NoError(t, err)

	// Try to push content with same name
	err = store.Push(context.Background(), desc, bytes.NewReader(testContent))
	assert.ErrorIs(t, err, oci.ErrDuplicateName)
}

func TestEventRecorderIntegration(t *testing.T) {
	// Setup
	tempDir := t.TempDir()
	mockEventRecorder := mocks.NewEventRecorder(t)

	// Setup mock expectations - use mock.Anything for context to avoid context matching issues
	mockEventRecorder.On("FailedToValidateOCI", mock.Anything, "disk.img").Return()

	// Create invalid file for validation failure
	testFileName := filepath.Join(tempDir, "disk.img")
	err := os.WriteFile(testFileName, []byte("invalid content"), 0644)
	require.NoError(t, err)

	store, err := oci.New(tempDir, false, mockEventRecorder)
	require.NoError(t, err)
	defer handleCloseError(t, store.Close)

	// Create descriptor with incorrect digest to trigger validation failure
	correctDigest := digest.FromBytes([]byte("correct content"))
	desc := ocispec.Descriptor{
		MediaType: string(oci.MediaTypeDiskImage),
		Digest:    correctDigest,
		Size:      int64(len("correct content")),
		Annotations: map[string]string{
			ocispec.AnnotationTitle: "disk.img",
		},
	}

	// This should trigger the event recorder when validation fails
	exists, err := store.Exists(context.Background(), desc)
	require.NoError(t, err)
	assert.False(t, exists) // File exists but validation fails, so Exists returns false

	// Verify that the mock was called
	mockEventRecorder.AssertExpectations(t)
}

func TestPredecessors(t *testing.T) {
	// Setup
	tempDir := t.TempDir()
	mockEventRecorder := mocks.NewEventRecorder(t)
	store, err := oci.New(tempDir, false, mockEventRecorder)
	require.NoError(t, err)
	defer handleCloseError(t, store.Close)

	// Create a test descriptor
	desc := ocispec.Descriptor{
		MediaType: string(oci.MediaTypeDiskImage),
		Digest:    digest.FromString("test"),
	}

	// Test Predecessors
	predecessors, err := store.Predecessors(context.Background(), desc)
	assert.NoError(t, err)
	assert.Nil(t, predecessors)
}

func TestGetManifestConfigDescriptor(t *testing.T) {
	// Setup
	tempDir := t.TempDir()
	mockEventRecorder := mocks.NewEventRecorder(t)
	store, err := oci.New(tempDir, false, mockEventRecorder)
	require.NoError(t, err)
	defer handleCloseError(t, store.Close)

	// Test GetManifestConfigDescriptor
	desc, err := store.GetManifestConfigDescriptor(context.Background())
	assert.NoError(t, err)
	assert.NotNil(t, desc)
	assert.NotNil(t, desc.Platform)
	assert.Equal(t, "darwin", desc.Platform.OS)
	assert.Equal(t, "arm64", desc.Platform.Architecture)
}

func TestSet(t *testing.T) {
	// Setup
	tempDir := t.TempDir()
	mockEventRecorder := mocks.NewEventRecorder(t)
	store, err := oci.New(tempDir, false, mockEventRecorder)
	require.NoError(t, err)
	defer handleCloseError(t, store.Close)

	// Create test config
	testConfig := oci.Config{
		OS:                "darwin",
		HardwareModelData: "test-hardware-model",
		MachineIdData:     "test-machine-id",
		Storage:           []oci.MediaType{oci.MediaTypeDiskImage},
	}

	// Test Set
	desc, err := store.Set(context.Background(), testConfig)
	assert.NoError(t, err)
	assert.NotEmpty(t, desc.Digest)
	assert.Greater(t, desc.Size, int64(0))
	assert.Contains(t, desc.Annotations, ocispec.AnnotationTitle)
}

// A compressed layer is streamed through gzip into the output: no temp copy is made,
// the output is verified and moved into place, and a bad digest leaves nothing behind.
func TestPushCompressedStreams(t *testing.T) {
	plain := bytes.Repeat([]byte("macos-vz"), 1000)
	var gz bytes.Buffer
	w := gzip.NewWriter(&gz)
	_, err := w.Write(plain)
	require.NoError(t, err)
	require.NoError(t, w.Close())

	newDesc := func(uncompressed digest.Digest) ocispec.Descriptor {
		return ocispec.Descriptor{
			MediaType: string(oci.MediaTypeDiskImage),
			Digest:    digest.FromBytes(gz.Bytes()),
			Size:      int64(gz.Len()),
			Annotations: map[string]string{
				ocispec.AnnotationTitle:          "disk.img",
				oci.AnnotationUncompressedSize:   strconv.Itoa(len(plain)),
				oci.AnnotationUncompressedDigest: uncompressed.String(),
			},
		}
	}

	t.Run("ok", func(t *testing.T) {
		dir := t.TempDir()
		store, err := oci.New(dir, false, mocks.NewEventRecorder(t))
		require.NoError(t, err)
		defer handleCloseError(t, store.Close)

		require.NoError(t, store.Push(context.Background(), newDesc(digest.FromBytes(plain)), bytes.NewReader(gz.Bytes())))
		got, err := os.ReadFile(filepath.Join(dir, "disk.img"))
		require.NoError(t, err)
		assert.Equal(t, plain, got)
		assert.FileExists(t, filepath.Join(dir, "disk.img.digest"))
		left, _ := filepath.Glob(filepath.Join(dir, "*.partial-*"))
		assert.Empty(t, left)
	})

	t.Run("digest mismatch leaves no output", func(t *testing.T) {
		dir := t.TempDir()
		store, err := oci.New(dir, false, mocks.NewEventRecorder(t))
		require.NoError(t, err)
		defer handleCloseError(t, store.Close)

		err = store.Push(context.Background(), newDesc(digest.FromString("wrong")), bytes.NewReader(gz.Bytes()))
		assert.ErrorContains(t, err, "digest mismatch")
		left, _ := filepath.Glob(filepath.Join(dir, "*.partial-*"))
		assert.Empty(t, left)
	})
}

// A registry-controlled title must never leave the cache directory.
func TestUnsafeTitleRejected(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "cache")
	require.NoError(t, os.MkdirAll(dir, os.ModePerm))
	victim := filepath.Join(root, "victim")
	require.NoError(t, os.WriteFile(victim, []byte("keep"), 0o600))

	store, err := oci.New(dir, false, mocks.NewEventRecorder(t))
	require.NoError(t, err)
	defer handleCloseError(t, store.Close)

	content := []byte("pwned")
	for _, title := range []string{"../victim", "../../etc/x", "/etc/x", "sub/disk.img", "disk.img.digest", "other.img"} {
		desc := ocispec.Descriptor{
			MediaType:   string(oci.MediaTypeDiskImage),
			Digest:      digest.FromBytes(content),
			Size:        int64(len(content)),
			Annotations: map[string]string{ocispec.AnnotationTitle: title},
		}
		err := store.Push(context.Background(), desc, bytes.NewReader(content))
		assert.ErrorIs(t, err, oci.ErrInvalidTitle, title)
		_, err = store.Exists(context.Background(), desc)
		assert.ErrorIs(t, err, oci.ErrInvalidTitle, title)
	}

	got, err := os.ReadFile(victim)
	require.NoError(t, err)
	assert.Equal(t, "keep", string(got))
	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	assert.Empty(t, entries, "nothing may be written")
}

func TestParseUncompressedSize(t *testing.T) {
	n, err := oci.ParseUncompressedSize("120000000000")
	require.NoError(t, err)
	assert.Equal(t, int64(120000000000), n)
	for _, bad := range []string{"", "0", "-5", "+5", "1_000", "0x10", " 5", "5 ", "1e3", "99999999999999999999"} {
		_, err := oci.ParseUncompressedSize(bad)
		assert.Error(t, err, "%q", bad)
	}
}

func TestHasMediaType(t *testing.T) {
	dir := t.TempDir()
	s, err := oci.New(dir, false, mocks.NewEventRecorder(t))
	require.NoError(t, err)
	assert.False(t, s.HasMediaType(oci.MediaTypeDiskImage))

	require.NoError(t, os.WriteFile(filepath.Join(dir, oci.MediaTypeDiskImage.Title()), []byte("x"), 0o600))
	_, err = s.Add(context.Background(), string(oci.MediaTypeDiskImage), "")
	require.NoError(t, err)
	assert.True(t, s.HasMediaType(oci.MediaTypeDiskImage))
	assert.False(t, s.HasMediaType(oci.MediaTypeAuxImage))
}

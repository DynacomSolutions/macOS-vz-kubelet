package tart

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/pierrec/lz4/v4"
	"github.com/stretchr/testify/require"
)

func block(t *testing.T, raw []byte, compressed bool) []byte {
	t.Helper()
	var b bytes.Buffer
	if compressed {
		packed := make([]byte, lz4.CompressBlockBound(len(raw)))
		var c lz4.Compressor
		n, err := c.CompressBlock(raw, packed)
		require.NoError(t, err)
		require.Positive(t, n)
		b.WriteString("bv41")
		require.NoError(t, binary.Write(&b, binary.LittleEndian, uint32(len(raw))))
		require.NoError(t, binary.Write(&b, binary.LittleEndian, uint32(n)))
		b.Write(packed[:n])
	} else {
		b.WriteString("bv4-")
		require.NoError(t, binary.Write(&b, binary.LittleEndian, uint32(len(raw))))
		b.Write(raw)
	}
	return b.Bytes()
}

func TestDecodeChunk(t *testing.T) {
	for _, zeros := range []bool{false, true} {
		raw := bytes.Repeat([]byte("Tart disk data\x00"), 10000)
		if zeros {
			raw = make([]byte, 4<<20)
		}
		encoded := append(block(t, raw, true), []byte("bv4$")...)
		f, err := os.Create(filepath.Join(t.TempDir(), "disk.img"))
		require.NoError(t, err)
		defer f.Close()
		require.NoError(t, decodeChunk(context.Background(), bytes.NewReader(encoded), f, int64(len(raw)), digest.FromBytes(raw)))
		offset, err := f.Seek(0, io.SeekCurrent)
		require.NoError(t, err)
		require.EqualValues(t, len(raw), offset)
		require.NoError(t, f.Truncate(offset))
		got, err := os.ReadFile(f.Name())
		require.NoError(t, err)
		require.Equal(t, raw, got)
		if zeros {
			info, err := f.Stat()
			require.NoError(t, err)
			require.Zero(t, info.Sys().(*syscall.Stat_t).Blocks, "all-zero layer must remain a hole")
		}
	}
}

func TestDictionaryAndStoredBlocks(t *testing.T) {
	// Second block starts with an eight-byte match referring to the previous block,
	// then ends with five literals. A standard independent block decoder fails here.
	first := []byte("abcdefgh")
	var encoded bytes.Buffer
	encoded.Write(block(t, first, false))
	encoded.WriteString("bv41")
	require.NoError(t, binary.Write(&encoded, binary.LittleEndian, uint32(13)))
	packed := []byte{0x04, 8, 0, 0x50, '1', '2', '3', '4', '5'}
	require.NoError(t, binary.Write(&encoded, binary.LittleEndian, uint32(len(packed))))
	encoded.Write(packed)
	encoded.WriteString("bv4$")
	raw := []byte("abcdefghabcdefgh12345")
	f, err := os.Create(filepath.Join(t.TempDir(), "disk"))
	require.NoError(t, err)
	defer f.Close()
	require.NoError(t, decodeChunk(context.Background(), &encoded, f, int64(len(raw)), digest.FromBytes(raw)))
	got, err := os.ReadFile(f.Name())
	require.NoError(t, err)
	require.Equal(t, raw, got)
}

func TestRejectCorruptChunks(t *testing.T) {
	raw := bytes.Repeat([]byte("disk"), 100)
	valid := append(block(t, raw, true), []byte("bv4$")...)
	for _, tc := range []struct {
		name string
		data []byte
		size int64
		hash digest.Digest
	}{
		{"digest", valid, int64(len(raw)), digest.FromString("wrong")},
		{"size", valid, int64(len(raw) + 1), digest.FromBytes(raw)},
		{"overflow", valid, 1, digest.FromBytes(raw)},
		{"truncated", valid[:len(valid)-1], int64(len(raw)), digest.FromBytes(raw)},
		{"trailing", append(bytes.Clone(valid), 0), int64(len(raw)), digest.FromBytes(raw)},
		{"standard-frame", []byte{4, 34, 77, 24}, int64(len(raw)), digest.FromBytes(raw)},
		{"huge-block", []byte{'b', 'v', '4', '-', 255, 255, 255, 255}, int64(len(raw)), digest.FromBytes(raw)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f, err := os.Create(filepath.Join(t.TempDir(), "disk"))
			require.NoError(t, err)
			defer f.Close()
			require.Error(t, decodeChunk(context.Background(), bytes.NewReader(tc.data), f, tc.size, tc.hash))
		})
	}
}

func TestVerifiedCopy(t *testing.T) {
	data := []byte("blob")
	d := ocispec.Descriptor{Size: int64(len(data)), Digest: digest.FromBytes(data)}
	consume := func(r io.Reader) error { _, err := io.Copy(io.Discard, r); return err }
	require.NoError(t, verifiedCopy(bytes.NewReader(data), d, consume))
	require.Error(t, verifiedCopy(bytes.NewReader([]byte("bad!")), d, consume))
	require.Error(t, verifiedCopy(bytes.NewReader(data[:3]), d, consume))
	require.Error(t, verifiedCopy(bytes.NewReader(append(data, 0)), d, consume))
}

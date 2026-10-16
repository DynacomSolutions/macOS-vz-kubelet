package tart

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"

	"github.com/opencontainers/go-digest"
	"github.com/pierrec/lz4/v4"
)

// decodeChunk handles Apple's COMPRESSION_LZ4 framing, not the standard LZ4 frame.
// https://developer.apple.com/documentation/compression/compression_lz4
// Each Tart disk-v2 layer is a separate stream; dictionary state resets per layer.
// dst must be a new, empty sparse file positioned at the next chunk offset.
func decodeChunk(ctx context.Context, src io.Reader, dst io.WriteSeeker, size int64, want digest.Digest) error {
	if err := want.Validate(); err != nil {
		return err
	}
	h := want.Algorithm().Hash()
	var total int64
	var dict []byte
	// Apple's encoder emits small blocks. Bound individual allocations independently of
	// the 512 MiB layer to reject corrupt headers without exhausting memory.
	const maxBlock = 4 << 20
	zero := make([]byte, maxBlock)
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		var magic [4]byte
		if _, err := io.ReadFull(src, magic[:]); err != nil {
			return err
		}
		if string(magic[:]) == "bv4$" {
			break
		}
		if string(magic[:]) != "bv41" && string(magic[:]) != "bv4-" {
			return fmt.Errorf("invalid Apple LZ4 block header %q", magic)
		}
		var decoded uint32
		if err := binary.Read(src, binary.LittleEndian, &decoded); err != nil {
			return err
		}
		if decoded == 0 || decoded > maxBlock || int64(decoded) > size-total {
			return fmt.Errorf("invalid Apple LZ4 decoded size %d", decoded)
		}
		out := make([]byte, int(decoded))
		if string(magic[:]) == "bv41" {
			var encoded uint32
			if err := binary.Read(src, binary.LittleEndian, &encoded); err != nil {
				return err
			}
			if encoded == 0 || uint64(encoded) > uint64(lz4.CompressBlockBound(int(decoded))) {
				return fmt.Errorf("invalid Apple LZ4 encoded size")
			}
			in := make([]byte, int(encoded))
			if _, err := io.ReadFull(src, in); err != nil {
				return err
			}
			n, err := lz4.UncompressBlockWithDict(in, out, dict)
			if err != nil {
				return err
			}
			if n != len(out) {
				return fmt.Errorf("LZ4 block size mismatch")
			}
		} else if _, err := io.ReadFull(src, out); err != nil {
			return err
		}
		_, _ = h.Write(out)
		if bytes.Equal(out, zero[:len(out)]) {
			if _, err := dst.Seek(int64(len(out)), io.SeekCurrent); err != nil {
				return err
			}
		} else {
			if n, err := dst.Write(out); err != nil {
				return err
			} else if n != len(out) {
				return io.ErrShortWrite
			}
		}
		total += int64(len(out))
		dict = append(dict, out...)
		if len(dict) > 65536 {
			dict = dict[len(dict)-65536:]
		}
		// Copy to avoid retaining a whole block through the dictionary slice.
		dict = bytes.Clone(dict)
	}
	var extra [1]byte
	if n, err := io.ReadFull(src, extra[:]); n != 0 || err != io.EOF {
		return fmt.Errorf("trailing data or read error after LZ4 end (bytes %d, error %v)", n, err)
	}
	if total != size {
		return fmt.Errorf("uncompressed size %d, expected %d", total, size)
	}
	if digest.NewDigest(want.Algorithm(), h) != want {
		return fmt.Errorf("uncompressed digest mismatch")
	}
	return nil
}

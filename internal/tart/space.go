package tart

import (
	"io"

	"github.com/opencontainers/go-digest"
)

type zeroReader struct{}

func (zeroReader) Read(p []byte) (int, error) { clear(p); return len(p), nil }

// requiredSpace counts only chunks whose uncompressed digest is not all zeroes.
// The streaming decoder still verifies every chunk, including all-zero chunks.
func requiredSpace(m Manifest) (uint64, error) {
	needed := uint64(m.NVRAM.Size) + maxMetadataSize + (1 << 30)
	type key struct {
		size      int64
		algorithm digest.Algorithm
	}
	zeros := make(map[key]digest.Digest)
	for _, d := range m.Disks {
		n, h, err := chunkInfo(d)
		if err != nil {
			return 0, err
		}
		k := key{n, h.Algorithm()}
		z, ok := zeros[k]
		if !ok {
			digester := h.Algorithm().Digester()
			if _, err := io.CopyN(digester.Hash(), zeroReader{}, n); err != nil {
				return 0, err
			}
			z = digester.Digest()
			zeros[k] = z
		}
		if h != z {
			needed += uint64(n)
		}
	}
	return needed, nil
}

package tart

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strconv"
	"testing"
	"time"

	"github.com/agoda-com/macOS-vz-kubelet/internal/diskguard"
	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/stretchr/testify/require"
)

func TestSparseImportFitsTargetMac(t *testing.T) {
	const logical = int64(140_000_000_000)
	h := digest.SHA256.Digester()
	_, err := io.CopyN(h.Hash(), zeroReader{}, maxChunkSize)
	require.NoError(t, err)
	m := Manifest{DiskSize: logical, NVRAM: ocispec.Descriptor{Size: 1 << 20}}
	for i := 0; i < 261; i++ {
		size := int64(maxChunkSize)
		if i == 260 {
			size = logical - 260*maxChunkSize
		}
		d := digest.FromString("non-zero")
		if i < 118 {
			d = h.Digest()
		}
		m.Disks = append(m.Disks, ocispec.Descriptor{Annotations: map[string]string{SizeAnnotation: strconv.FormatInt(size, 10), DigestAnnotation: d.String()}})
	}
	needed, err := requiredSpace(m)
	require.NoError(t, err)
	require.Equal(t, uint64(logical-118*maxChunkSize+(1<<20)+maxMetadataSize+(1<<30)), needed)
	require.True(t, diskguard.Fits(129<<30, needed, 15<<30))
	require.False(t, diskguard.Fits(129<<30, uint64(logical), 15<<30))
	require.False(t, diskguard.Fits(needed, needed, 15<<30), "floor remains additional")
}

type failingBlobSource struct {
	calls      int
	ranged     bool
	offsets    []int64
	failOpen   bool
	alwaysFail bool
}

func (s *failingBlobSource) Fetch(context.Context, ocispec.Descriptor) (io.ReadCloser, error) {
	s.calls++
	if s.alwaysFail || (s.failOpen && s.calls == 1) {
		return nil, errors.New("connection failed")
	}
	if s.calls == 1 {
		return &brokenBody{Reader: bytes.NewReader([]byte("abc"))}, nil
	}
	r := &seekBody{Reader: bytes.NewReader([]byte("abcdef")), source: s}
	if s.ranged {
		return r, nil
	}
	return io.NopCloser(r.Reader), nil
}

type brokenBody struct{ *bytes.Reader }

func (r *brokenBody) Close() error { return nil }
func (r *brokenBody) Read(p []byte) (int, error) {
	n, err := r.Reader.Read(p)
	if err == io.EOF {
		err = io.ErrUnexpectedEOF
	}
	return n, err
}

type seekBody struct {
	*bytes.Reader
	source *failingBlobSource
}

func (r *seekBody) Close() error { return nil }
func (r *seekBody) Seek(n int64, w int) (int64, error) {
	r.source.offsets = append(r.source.offsets, n)
	return r.Reader.Seek(n, w)
}
func TestBlobRetryPreservesConsumer(t *testing.T) {
	for _, ranged := range []bool{false, true} {
		s := &failingBlobSource{ranged: ranged}
		d := ocispec.Descriptor{Size: 6, Digest: digest.FromString("abcdef")}
		r := &retryReader{ctx: context.Background(), source: s, desc: d, delay: time.Nanosecond}
		var out bytes.Buffer
		require.NoError(t, verifiedCopy(r, d, func(r io.Reader) error { _, err := io.Copy(&out, r); return err }))
		require.NoError(t, r.Close())
		require.Equal(t, "abcdef", out.String())
		require.Equal(t, 2, s.calls)
		if ranged {
			require.Equal(t, []int64{3}, s.offsets)
		}
	}
}
func TestFetchRetriesOpenFailure(t *testing.T) {
	s := &failingBlobSource{failOpen: true}
	var out bytes.Buffer
	require.NoError(t, fetch(context.Background(), s, ocispec.Descriptor{Size: 6, Digest: digest.FromString("abcdef")}, func(r io.Reader) error { _, err := io.Copy(&out, r); return err }))
	require.Equal(t, "abcdef", out.String())
	require.Equal(t, 2, s.calls)
}
func TestBlobRetryLimitAndCancellation(t *testing.T) {
	s := &failingBlobSource{alwaysFail: true}
	r := &retryReader{ctx: context.Background(), source: s, delay: time.Nanosecond}
	_, err := io.ReadAll(r)
	require.ErrorContains(t, err, "five attempts")
	require.Equal(t, 5, s.calls)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r = &retryReader{ctx: ctx, source: s}
	_, err = io.ReadAll(r)
	require.ErrorIs(t, err, context.Canceled)
	require.Equal(t, 5, s.calls)
}

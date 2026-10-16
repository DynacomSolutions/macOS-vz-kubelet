package tart

import (
	"context"
	"fmt"
	"io"
	"time"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

// retryReader keeps the decoder and digest verifier alive across interrupted
// downloads. ORAS returns an io.Seeker when the registry advertises byte ranges;
// other sources are reopened and their already-consumed prefix is discarded.
type retryReader struct {
	ctx      context.Context
	source   blobSource
	desc     ocispec.Descriptor
	body     io.ReadCloser
	offset   int64
	attempts int
	lastErr  error
	delay    time.Duration
}

func (r *retryReader) Close() error {
	if r.body != nil {
		return r.body.Close()
	}
	return nil
}

func (r *retryReader) Read(p []byte) (int, error) {
	for {
		if err := r.ctx.Err(); err != nil {
			return 0, err
		}
		if r.body == nil {
			if r.attempts == 5 {
				return 0, fmt.Errorf("blob %s failed after five attempts: %w", r.desc.Digest, r.lastErr)
			}
			if r.attempts > 0 {
				delay := r.delay
				if delay == 0 {
					delay = time.Second
				}
				timer := time.NewTimer(delay << (r.attempts - 1))
				select {
				case <-r.ctx.Done():
					timer.Stop()
					return 0, r.ctx.Err()
				case <-timer.C:
				}
			}
			r.attempts++
			body, err := r.source.Fetch(r.ctx, r.desc)
			if err == nil && r.offset > 0 {
				if seeker, ok := body.(io.Seeker); ok {
					var offset int64
					offset, err = seeker.Seek(r.offset, io.SeekStart)
					if err == nil && offset != r.offset {
						err = fmt.Errorf("incorrect resume offset %d", offset)
					}
				} else {
					_, err = io.CopyN(io.Discard, body, r.offset)
				}
			}
			if err != nil {
				if body != nil {
					body.Close()
				}
				r.lastErr = err
				continue
			}
			r.body = body
		}
		n, err := r.body.Read(p)
		r.offset += int64(n)
		if err != nil && !(err == io.EOF && r.offset >= r.desc.Size) {
			r.lastErr = err
			r.body.Close()
			r.body = nil
			// Deliver bytes exactly once, retaining the error for the next retry.
			if n > 0 {
				return n, nil
			}
			continue
		}
		return n, err
	}
}

package disk

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"

	"github.com/klauspost/pgzip"
	"github.com/opencontainers/go-digest"
	"github.com/virtual-kubelet/virtual-kubelet/trace"
)

const (
	DefaultBlockSize = 100000
)

// CompressionResult contains the output file path, size, and digests of the compressed and uncompressed content.
type CompressionResult struct {
	OutputFilePath     string
	CompressedSize     int64
	UncompressedSize   int64
	GzDigest           digest.Digest
	UncompressedDigest digest.Digest
}

// CompressFileWithPath compresses the file at the given path and writes the compressed content to the output file.
func CompressFileWithPath(ctx context.Context, inputFilePath string, outputFile *os.File) (r CompressionResult, err error) {
	_, span := trace.StartSpan(ctx, "OCI.CompressFileWithPath")
	defer func() {
		span.SetStatus(err)
		span.End()
	}()

	inputFile, err := os.Open(inputFilePath)
	if err != nil {
		return CompressionResult{}, err
	}
	defer func() {
		err = errors.Join(err, inputFile.Close())
	}()

	gzDigester := digest.Canonical.Digester()
	uncompressedDigester := digest.Canonical.Digester()

	multiWriter := io.MultiWriter(outputFile, gzDigester.Hash())
	teeReader := io.TeeReader(inputFile, uncompressedDigester.Hash())

	w, err := pgzip.NewWriterLevel(multiWriter, pgzip.DefaultCompression)
	if err != nil {
		return CompressionResult{}, err
	}
	err = w.SetConcurrency(DefaultBlockSize, runtime.NumCPU()*2)
	if err != nil {
		return CompressionResult{}, err
	}

	// Copy from the teeReader, which both reads inputFile and writes to uncompressedDigester
	_, err = io.Copy(w, teeReader)
	if err != nil {
		return CompressionResult{}, err
	}

	// flush all
	if err := w.Close(); err != nil {
		return CompressionResult{}, err
	}
	if err := outputFile.Sync(); err != nil {
		return CompressionResult{}, err
	}

	fi, err := outputFile.Stat()
	if err != nil {
		return CompressionResult{}, err
	}

	return CompressionResult{
		OutputFilePath:     outputFile.Name(),
		CompressedSize:     fi.Size(),
		UncompressedSize:   int64(w.UncompressedSize()),
		GzDigest:           gzDigester.Digest(),
		UncompressedDigest: uncompressedDigester.Digest(),
	}, nil
}

// DecompressFileWithPath uncompresses the file at the given path and writes the uncompressed content to the output file.
// It uses gzip for uncompression and writes the content in chunks to the output file by skipping zero chunks.
func DecompressFileWithPath(ctx context.Context, inputFilePath, outputFilePath string, uncompressedSize int64) (d digest.Digest, err error) {
	ctx, span := trace.StartSpan(ctx, "OCI.DecompressFileWithPath")
	defer func() {
		span.SetStatus(err)
		span.End()
	}()

	inputFile, err := os.Open(inputFilePath)
	if err != nil {
		return "", err
	}
	defer func() {
		err = errors.Join(err, inputFile.Close())
	}()

	d, err = DecompressReader(ctx, inputFile, outputFilePath, uncompressedSize)
	if err != nil {
		return "", err
	}

	// Write the digest to a file as a cache
	if err = WriteDigestFile(outputFilePath, d); err != nil {
		return "", err
	}
	return d, nil
}

// WriteDigestFile records d as the digest of the file at filePath, marking it validated.
func WriteDigestFile(filePath string, d digest.Digest) error {
	return writeDigestFile(filePath, d)
}

// DecompressReader streams gzip data from r into the output file, skipping zero chunks
// so the file stays sparse, and returns the digest of the uncompressed content.
func DecompressReader(ctx context.Context, r io.Reader, outputFilePath string, uncompressedSize int64) (d digest.Digest, err error) {
	// Create the output file for writing
	outputFile, err := os.Create(outputFilePath)
	if err != nil {
		return "", err
	}
	defer func() {
		err = errors.Join(err, outputFile.Close())
	}()

	err = outputFile.Truncate(uncompressedSize)
	if err != nil {
		return "", err
	}

	gz, err := pgzip.NewReader(r)
	if err != nil {
		return "", err
	}

	digester := digest.Canonical.Digester()
	h := digester.Hash()

	buf := make([]byte, 4<<20)
	sparseBlockSize := 64 << 10
	zeroChunk := make([]byte, sparseBlockSize)
	var offset int64

	for {
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		default:
		}

		// Read a chunk
		n, err := gz.Read(buf)
		if err == io.EOF {
			break // End of file
		}
		if err != nil {
			return "", err
		}

		for i := 0; i < n; {
			end := i + sparseBlockSize
			if end > n {
				end = n
			}
			chunk := buf[i:end]
			i = end

			h.Write(chunk) // Write chunk to the hash writer

			if !bytes.Equal(chunk, zeroChunk) {
				if _, err = outputFile.Seek(offset, io.SeekStart); err != nil {
					return "", fmt.Errorf("failed to seek in output file: %w", err)
				}
				if _, err = outputFile.Write(chunk); err != nil {
					return "", fmt.Errorf("failed to write to output file: %w", err)
				}
			}

			offset += int64(len(chunk))
		}
	}

	return digester.Digest(), nil
}

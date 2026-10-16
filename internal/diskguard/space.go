// Package diskguard provides the portable free-space checks shared by downloads
// and offline image imports.
package diskguard

import (
	"context"
	"errors"
	"fmt"
	"syscall"
	"time"
)

var ErrInsufficientSpace = errors.New("insufficient free disk space")

// FreeBytes reports bytes available to unprivileged writers on path's volume.
func FreeBytes(path string) (uint64, error) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil {
		return 0, err
	}
	return uint64(st.Bsize) * uint64(st.Bavail), nil // nolint: gosec
}

// Fits avoids overflow when checking the required space and remaining floor.
func Fits(free, needed, floor uint64) bool { return free >= needed && free-needed >= floor }

// WatchFreeSpace cancels with ErrInsufficientSpace when free space falls below
// floor. A zero floor disables polling. Call stop to release the watcher.
func WatchFreeSpace(ctx context.Context, path string, floor uint64) (context.Context, func()) {
	ctx, cancel := context.WithCancelCause(ctx)
	if floor == 0 {
		return ctx, func() { cancel(nil) }
	}
	go func() {
		t := time.NewTicker(time.Second)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				if free, err := FreeBytes(path); err == nil && free < floor {
					cancel(fmt.Errorf("%w: %d bytes free, floor %d; transfer aborted", ErrInsufficientSpace, free, floor))
					return
				}
			}
		}
	}()
	return ctx, func() { cancel(nil) }
}

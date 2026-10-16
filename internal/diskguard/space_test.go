package diskguard

import (
	"context"
	"math"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestFits(t *testing.T) {
	require.True(t, Fits(100, 80, 20))
	require.False(t, Fits(100, 81, 20))
	require.False(t, Fits(1, math.MaxUint64, 2))
	require.False(t, Fits(math.MaxUint64, math.MaxUint64, 1))
}
func TestWatchFreeSpace(t *testing.T) {
	dir := t.TempDir()
	_, err := FreeBytes(dir)
	require.NoError(t, err)
	_, err = FreeBytes(dir + "/missing")
	require.Error(t, err)
	ctx, stop := WatchFreeSpace(context.Background(), dir, math.MaxUint64)
	defer stop()
	select {
	case <-ctx.Done():
		require.ErrorIs(t, context.Cause(ctx), ErrInsufficientSpace)
	case <-time.After(5 * time.Second):
		t.Fatal("watcher did not cancel")
	}
	disabled, stopDisabled := WatchFreeSpace(context.Background(), dir, 0)
	require.NoError(t, disabled.Err())
	stopDisabled()
	stopDisabled()
	require.ErrorIs(t, disabled.Err(), context.Canceled)
}

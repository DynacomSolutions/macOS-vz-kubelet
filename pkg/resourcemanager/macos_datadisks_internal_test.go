package resourcemanager

import (
	"context"
	"path/filepath"
	"testing"

	vmdata "github.com/agoda-com/macOS-vz-kubelet/internal/data/vm"
	"github.com/agoda-com/macOS-vz-kubelet/pkg/event"
	"github.com/agoda-com/macOS-vz-kubelet/pkg/resource"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The cache must never evict the data disks of a VM on this node: the real in-use source
// registered by NewMacOSClient has to list them next to the image.
func TestInUseDirsIncludeDataDisksOfRegisteredVMs(t *testing.T) {
	cache := t.TempDir()
	c := NewMacOSClient(context.Background(), event.LogEventRecorder{}, "", cache)

	_, loaded := c.vms.LoadOrStore("ns", "vm", vmdata.VirtualMachineInfo{
		Ref:          "r.io/macos-vz/base:1",
		DataDiskRefs: []string{"r.io/macos-vz/xcode:16", "r.io/macos-vz/tools:3"},
		Resource:     resource.NewMacOSVirtualMachine(nil),
	})
	require.False(t, loaded)

	dir := func(rel string) string { return filepath.Join(cache, "blobs", rel) }
	assert.ElementsMatch(t, []string{
		dir("r.io/macos-vz/base/1"),
		dir("r.io/macos-vz/xcode/16"),
		dir("r.io/macos-vz/tools/3"),
	}, c.downloadManager.InUseDirs())
}

func TestDataDiskRefs(t *testing.T) {
	assert.Nil(t, dataDiskRefs(nil))
	assert.Equal(t, []string{"a:1", "b:2"}, dataDiskRefs([]DataDisk{{Ref: "a:1"}, {Ref: "b:2"}}))
}

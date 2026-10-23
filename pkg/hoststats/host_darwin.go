//go:build darwin

package hoststats

/*
#include <stdint.h>
#include <unistd.h>
#include <mach/mach.h>
#include <mach/mach_host.h>

// Thin wrappers keep the Mach macros and struct layouts on the C side.
static int hs_cpu(uint32_t *user, uint32_t *system, uint32_t *nice) {
	host_cpu_load_info_data_t info;
	mach_msg_type_number_t count = HOST_CPU_LOAD_INFO_COUNT;
	kern_return_t kr = host_statistics(mach_host_self(), HOST_CPU_LOAD_INFO, (host_info_t)&info, &count);
	if (kr != KERN_SUCCESS) return (int)kr;
	*user = info.cpu_ticks[CPU_STATE_USER];
	*system = info.cpu_ticks[CPU_STATE_SYSTEM];
	*nice = info.cpu_ticks[CPU_STATE_NICE];
	return 0;
}

static int hs_vm(uint64_t *page, uint64_t *active, uint64_t *inactive, uint64_t *wired, uint64_t *compressor) {
	vm_size_t ps = 0;
	if (host_page_size(mach_host_self(), &ps) != KERN_SUCCESS) return -1;
	vm_statistics64_data_t vm;
	mach_msg_type_number_t count = HOST_VM_INFO64_COUNT;
	kern_return_t kr = host_statistics64(mach_host_self(), HOST_VM_INFO64, (host_info64_t)&vm, &count);
	if (kr != KERN_SUCCESS) return (int)kr;
	*page = ps;
	*active = vm.active_count;
	*inactive = vm.inactive_count;
	*wired = vm.wire_count;
	*compressor = vm.compressor_page_count;
	return 0;
}
*/
import "C"

import (
	"fmt"
	"time"

	"golang.org/x/sys/unix"
)

// readHost reads the Mach host counters, the same source top and Activity Monitor use.
func readHost() (Raw, error) {
	var user, system, nice C.uint32_t
	if rc := C.hs_cpu(&user, &system, &nice); rc != 0 {
		return Raw{}, fmt.Errorf("host_statistics(HOST_CPU_LOAD_INFO): kern_return_t %d", int(rc))
	}
	var page, active, inactive, wired, compressor C.uint64_t
	if rc := C.hs_vm(&page, &active, &inactive, &wired, &compressor); rc != 0 {
		return Raw{}, fmt.Errorf("host_statistics64(HOST_VM_INFO64): kern_return_t %d", int(rc))
	}
	total, err := unix.SysctlUint64("hw.memsize")
	if err != nil {
		return Raw{}, fmt.Errorf("sysctl hw.memsize: %w", err)
	}
	boot, err := unix.SysctlTimeval("kern.boottime")
	if err != nil {
		return Raw{}, fmt.Errorf("sysctl kern.boottime: %w", err)
	}
	return Raw{
		BusyTicks: uint32(user) + uint32(system) + uint32(nice),
		ClkTck:    uint64(C.sysconf(C._SC_CLK_TCK)),
		PageSize:  uint64(page),
		Active:    uint64(active),
		Inactive:  uint64(inactive),
		Wired:     uint64(wired),
		Compress:  uint64(compressor),
		TotalMem:  total,
		BootTime:  time.Unix(int64(boot.Sec), int64(boot.Usec)*1000),
	}, nil
}

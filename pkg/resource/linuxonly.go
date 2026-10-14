package resource

import (
	"time"

	corev1 "k8s.io/api/core/v1"
)

// LinuxOnlyAnnotation marks a pod whose containers are ALL Docker containers (no macOS VM).
// An image reference cannot tell a macOS VM image from a Linux one, so the pod must say so.
const LinuxOnlyAnnotation = "dynacom.dev/linux-only"

// IsLinuxOnly reports whether the pod has no macOS VM as container 0.
func IsLinuxOnly(pod *corev1.Pod) bool { return pod.Annotations[LinuxOnlyAnnotation] == "true" }

// StopWhenPostStartExitsAnnotation makes the provider stop the macOS VM from the host when the
// postStart hook exits, and report the container as terminated with the hook's exit code. It
// replaces a guest power-off in the hook, which leaks a Virtualization.framework VM slot on
// macOS 26.5 (the framework's active-VM counter is only decremented by a host-side stop).
const StopWhenPostStartExitsAnnotation = "dynacom.dev/stop-when-poststart-exits"

// StopsWhenPostStartExits reports whether the pod asks for the host-side stop described above.
func StopsWhenPostStartExits(pod *corev1.Pod) bool {
	return pod.Annotations[StopWhenPostStartExitsAnnotation] == "true"
}

// LinuxOnlyVM stands in for the absent macOS VM so the pod-status code sees a "running VM" with
// the node IP (Docker container IPs live inside the Colima VM and are not routable from the cluster).
type LinuxOnlyVM struct{ IP string }

func (LinuxOnlyVM) Env() []corev1.EnvVar            { return nil }
func (LinuxOnlyVM) State() VirtualMachineState      { return VirtualMachineStateRunning }
func (LinuxOnlyVM) Error() error                    { return nil }
func (LinuxOnlyVM) SetError(error)                  {}
func (v LinuxOnlyVM) IPAddress() string             { return v.IP }
func (LinuxOnlyVM) StartedAt() *time.Time           { return nil }
func (LinuxOnlyVM) FinishedAt() *time.Time          { return nil }
func (LinuxOnlyVM) PostStartFinishedAt() *time.Time { return nil }

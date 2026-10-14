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

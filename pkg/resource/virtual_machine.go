package resource

import (
	"time"

	corev1 "k8s.io/api/core/v1"
)

// guestState* are the Code-Hex/vz VirtualMachineState values this package maps.
// virtual_machine_darwin.go fails the build if those numbers move.
const (
	guestStateStopped  = 0
	guestStateRunning  = 1
	guestStateStarting = 4
	guestStateStopping = 7
)

// guest is the running Virtualization.framework machine. The adapter lives in
// virtual_machine_darwin.go so this file does not import pkg/vm or Code-Hex/vz.
// Those packages do not build on Linux, and the display-annotation tests here must.
type guest interface {
	state() int
	ip() string
	startedAt() *time.Time
	finishedAt() *time.Time
}

// VirtualMachineState represents the state of a macOS virtual machine.
type VirtualMachineState int

const (
	// VM is preparing.
	VirtualMachineStatePreparing VirtualMachineState = iota

	// VM is starting.
	VirtualMachineStateStarting

	// VM is running.
	VirtualMachineStateRunning

	// VM is terminating.
	VirtualMachineStateTerminating

	// VM has terminated.
	VirtualMachineStateTerminated

	// VM has failed.
	VirtualMachineStateFailed
)

type VirtualMachine interface {
	// Env returns the environment variables for the virtual machine.
	Env() []corev1.EnvVar

	// State returns the current state of the virtual machine.
	State() VirtualMachineState

	// Error returns the error state of the virtual machine.
	Error() error

	// SetError sets the error state of the virtual machine.
	SetError(err error)

	// IPAddress returns the IP address of the virtual machine.
	IPAddress() string

	// StartedAt returns the start time of the virtual machine.
	StartedAt() *time.Time

	// FinishedAt returns the finish time of the virtual machine.
	FinishedAt() *time.Time

	// PostStartFinishedAt returns the postStart hook success time, or nil if not finished
	// (no hook, still running, or failed).
	PostStartFinishedAt() *time.Time
}

// MacOSVirtualMachine represents a macOS virtual machine instance along with its error state.
type MacOSVirtualMachine struct {
	env                 []corev1.EnvVar // Environment variables for the virtual machine.
	guest               guest           // The underlying virtual machine instance, or nil while preparing.
	err                 error           // Error state of the virtual machine.
	postStartFinishedAt time.Time       // set once postStart hook succeeds; zero = not finished
	hookExitCode        *int            // exit status of the postStart hook, when it exited with one
}

// NewMacOSVirtualMachine creates a new instance of MacOSVirtualMachine.
func NewMacOSVirtualMachine(env []corev1.EnvVar) MacOSVirtualMachine {
	return MacOSVirtualMachine{
		env: env,
	}
}

// Environment returns the environment variables for the macOS virtual machine.
func (m *MacOSVirtualMachine) Env() []corev1.EnvVar {
	return m.env
}

// State returns the current state of the macOS virtual machine.
func (m *MacOSVirtualMachine) State() VirtualMachineState {
	if m.err != nil {
		return VirtualMachineStateFailed
	}

	if m.guest == nil {
		return VirtualMachineStatePreparing
	}

	switch m.guest.state() {
	case guestStateStarting:
		return VirtualMachineStateStarting
	case guestStateRunning:
		return VirtualMachineStateRunning
	case guestStateStopping:
		return VirtualMachineStateTerminating
	case guestStateStopped:
		return VirtualMachineStateTerminated
	default: // consider all other states as failed
	}

	return VirtualMachineStateFailed
}

// Error returns the error state of the macOS virtual machine.
func (m *MacOSVirtualMachine) Error() error {
	return m.err
}

// SetError sets the error state of the macOS virtual machine.
func (m *MacOSVirtualMachine) SetError(err error) {
	m.err = err
}

// IPAddress returns the IP address of the macOS virtual machine.
func (m *MacOSVirtualMachine) IPAddress() string {
	if m.guest == nil {
		return ""
	}

	return m.guest.ip()
}

// StartedAt returns the start time of the macOS virtual machine.
func (m *MacOSVirtualMachine) StartedAt() *time.Time {
	if m.guest == nil {
		return nil
	}

	return m.guest.startedAt()
}

// FinishedAt returns the finish time of the macOS virtual machine.
func (m *MacOSVirtualMachine) FinishedAt() *time.Time {
	if m.guest == nil {
		return nil
	}

	return m.guest.finishedAt()
}

// PostStartFinishedAt returns the post-start success time (the SSH readiness probe,
// plus the exec hook when one exists), or nil if not finished (still running or failed).
func (m *MacOSVirtualMachine) PostStartFinishedAt() *time.Time {
	if m.postStartFinishedAt.IsZero() {
		return nil
	}
	return &m.postStartFinishedAt
}

// SetPostStartFinishedAt records successful post-start completion (the SSH readiness
// probe, plus the exec hook when one exists).
func (m *MacOSVirtualMachine) SetPostStartFinishedAt(t time.Time) {
	m.postStartFinishedAt = t
}

// HookExitCode returns the postStart hook's exit status, or nil if it did not exit with one.
func (m *MacOSVirtualMachine) HookExitCode() *int {
	return m.hookExitCode
}

// SetHookExitCode records the postStart hook's exit status.
func (m *MacOSVirtualMachine) SetHookExitCode(code int) {
	m.hookExitCode = &code
}

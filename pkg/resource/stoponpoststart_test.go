package resource

import (
	"testing"

	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestStopsWhenPostStartExits(t *testing.T) {
	pod := func(a map[string]string) *corev1.Pod {
		return &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Annotations: a}}
	}
	assert.False(t, StopsWhenPostStartExits(pod(nil)))
	assert.False(t, StopsWhenPostStartExits(pod(map[string]string{StopWhenPostStartExitsAnnotation: "false"})))
	assert.True(t, StopsWhenPostStartExits(pod(map[string]string{StopWhenPostStartExitsAnnotation: "true"})))
}

func TestHookExitCode(t *testing.T) {
	vm := NewMacOSVirtualMachine(nil)
	assert.Nil(t, vm.HookExitCode())
	vm.SetHookExitCode(0)
	if assert.NotNil(t, vm.HookExitCode()) {
		assert.Equal(t, 0, *vm.HookExitCode())
	}
}

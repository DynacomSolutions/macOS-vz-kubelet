package nodehealth_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/agoda-com/macOS-vz-kubelet/internal/nodehealth"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	corev1 "k8s.io/api/core/v1"
)

func ready(t *testing.T, n *corev1.Node) corev1.NodeCondition {
	t.Helper()
	for _, c := range n.Status.Conditions {
		if c.Type == corev1.NodeReady {
			return c
		}
	}
	t.Fatal("no Ready condition")
	return corev1.NodeCondition{}
}

func baseNode() *corev1.Node {
	return &corev1.Node{Status: corev1.NodeStatus{Conditions: []corev1.NodeCondition{
		{Type: corev1.NodeReady, Status: corev1.ConditionTrue, Reason: "KubeletReady"},
		{Type: corev1.NodeMemoryPressure, Status: corev1.ConditionFalse},
	}}}
}

func TestEvaluateTracksDaemonState(t *testing.T) {
	var daemonErr error
	p := nodehealth.New(baseNode(), func(context.Context) error { return daemonErr }, time.Second)
	ctx := context.Background()

	assert.Nil(t, p.Evaluate(ctx), "healthy at start: no update")

	daemonErr = errors.New("Cannot connect to the Docker daemon at unix:///colima.sock")
	n := p.Evaluate(ctx)
	require.NotNil(t, n)
	c := ready(t, n)
	assert.Equal(t, corev1.ConditionFalse, c.Status)
	assert.Equal(t, nodehealth.ReasonDockerUnreachable, c.Reason)
	assert.Contains(t, c.Message, "Cannot connect")
	assert.Len(t, n.Status.Conditions, 2, "other conditions are kept")

	assert.Nil(t, p.Evaluate(ctx), "still down: no repeat update")

	daemonErr = nil
	n = p.Evaluate(ctx)
	require.NotNil(t, n)
	assert.Equal(t, corev1.ConditionTrue, ready(t, n).Status)
}

func TestNotifyNodeStatusReportsStoppedDaemon(t *testing.T) {
	p := nodehealth.New(baseNode(), func(context.Context) error { return errors.New("stopped") }, 10*time.Millisecond)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	got := make(chan *corev1.Node, 1)
	p.NotifyNodeStatus(ctx, func(n *corev1.Node) {
		select {
		case got <- n:
		default:
		}
	})
	select {
	case n := <-got:
		assert.Equal(t, corev1.ConditionFalse, ready(t, n).Status)
	case <-time.After(2 * time.Second):
		t.Fatal("no node update")
	}
}

func TestPingStaysAliveWhileDaemonDown(t *testing.T) {
	p := nodehealth.New(baseNode(), func(context.Context) error { return errors.New("down") }, time.Second)
	assert.NoError(t, p.Ping(context.Background()))
}

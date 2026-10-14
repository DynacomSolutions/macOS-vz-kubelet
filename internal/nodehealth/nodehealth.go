// Package nodehealth reports Node readiness from the health of the Docker side-car daemon.
package nodehealth

import (
	"context"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	// ReasonDockerUnreachable is the Ready=False reason while the daemon cannot be reached.
	ReasonDockerUnreachable = "DockerUnreachable"
	// DefaultInterval is how often the daemon is checked.
	DefaultInterval = 15 * time.Second
	checkTimeout    = 5 * time.Second
)

// Provider implements node.NodeProvider (Ping and NotifyNodeStatus). It re-checks the
// daemon periodically and pushes a node status update whenever Ready flips.
type Provider struct {
	base     *corev1.Node
	check    func(context.Context) error
	interval time.Duration

	mu      sync.Mutex
	healthy bool
}

// New returns a Provider. base is the node the status is derived from; check returns
// nil while the Docker daemon is reachable.
func New(base *corev1.Node, check func(context.Context) error, interval time.Duration) *Provider {
	if interval <= 0 {
		interval = DefaultInterval
	}
	return &Provider{base: base, check: check, interval: interval, healthy: true}
}

// Ping keeps the node heartbeat alive: NotReady is reported through the Ready condition, not by going silent.
func (p *Provider) Ping(ctx context.Context) error { return ctx.Err() }

// NotifyNodeStatus starts the periodic check. It does not block.
func (p *Provider) NotifyNodeStatus(ctx context.Context, cb func(*corev1.Node)) {
	go func() {
		t := time.NewTicker(p.interval)
		defer t.Stop()
		for {
			if n := p.Evaluate(ctx); n != nil {
				cb(n)
			}
			select {
			case <-ctx.Done():
				return
			case <-t.C:
			}
		}
	}()
}

// Evaluate runs one check. It returns an updated node when Ready changed since the last call
// (the first call reports a failure at once, but stays silent while healthy), otherwise nil.
func (p *Provider) Evaluate(ctx context.Context) *corev1.Node {
	cctx, cancel := context.WithTimeout(ctx, checkTimeout)
	defer cancel()
	err := p.check(cctx)

	p.mu.Lock()
	defer p.mu.Unlock()
	if (err == nil) == p.healthy {
		return nil
	}
	p.healthy = err == nil

	n := p.base.DeepCopy()
	now := metav1.Now()
	cond := corev1.NodeCondition{
		Type:               corev1.NodeReady,
		Status:             corev1.ConditionTrue,
		LastHeartbeatTime:  now,
		LastTransitionTime: now,
		Reason:             "KubeletReady",
		Message:            "kubelet is ready.",
	}
	if err != nil {
		cond.Status = corev1.ConditionFalse
		cond.Reason = ReasonDockerUnreachable
		cond.Message = "Docker side-car daemon is unreachable: " + err.Error()
	}
	for i := range n.Status.Conditions {
		if n.Status.Conditions[i].Type == corev1.NodeReady {
			n.Status.Conditions[i] = cond
			return n
		}
	}
	n.Status.Conditions = append(n.Status.Conditions, cond)
	return n
}

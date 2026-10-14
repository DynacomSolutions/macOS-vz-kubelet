// Package nodeauth provides pieces of the virtual-kubelet node bootstrap that work under the
// Kubernetes Node authorizer. A node identity may not list or watch Secrets and ConfigMaps
// cluster-wide; like the real kubelet it may only GET the ones that Pods bound to it reference.
package nodeauth

import (
	"context"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	corev1informers "k8s.io/client-go/informers/core/v1"
	"k8s.io/client-go/kubernetes"
	corev1listers "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"
)

// DefaultTTL is how long a fetched Secret or ConfigMap is reused.
const DefaultTTL = 30 * time.Second

type cached[T any] struct {
	obj     T
	fetched time.Time
}

// getter is a namespaced GET with a small TTL cache. Errors (including NotFound) are not cached.
type getter[T any] struct {
	fetch func(ctx context.Context, ns, name string) (T, error)
	ttl   time.Duration
	now   func() time.Time

	mu    sync.Mutex
	items map[string]cached[T]
}

func newGetter[T any](ttl time.Duration, fetch func(context.Context, string, string) (T, error)) *getter[T] {
	return &getter[T]{fetch: fetch, ttl: ttl, now: time.Now, items: map[string]cached[T]{}}
}

func (g *getter[T]) get(ns, name string) (T, error) {
	key := ns + "/" + name
	g.mu.Lock()
	c, ok := g.items[key]
	g.mu.Unlock()
	if ok && g.now().Sub(c.fetched) < g.ttl {
		return c.obj, nil
	}
	obj, err := g.fetch(context.Background(), ns, name)
	if err != nil {
		var zero T
		return zero, err
	}
	g.mu.Lock()
	g.items[key] = cached[T]{obj: obj, fetched: g.now()}
	g.mu.Unlock()
	return obj, nil
}

// SecretLister serves Secrets by namespaced GET. Cluster-wide and namespace-wide List return nothing.
type SecretLister struct{ g *getter[*corev1.Secret] }

// NewSecretLister returns a lister backed by GET calls with the given cache TTL.
func NewSecretLister(c kubernetes.Interface, ttl time.Duration) *SecretLister {
	return &SecretLister{newGetter(ttl, func(ctx context.Context, ns, name string) (*corev1.Secret, error) {
		return c.CoreV1().Secrets(ns).Get(ctx, name, metav1.GetOptions{})
	})}
}

func (l *SecretLister) List(labels.Selector) ([]*corev1.Secret, error) { return nil, nil }

func (l *SecretLister) Secrets(ns string) corev1listers.SecretNamespaceLister {
	return secretNS{l.g, ns}
}

type secretNS struct {
	g  *getter[*corev1.Secret]
	ns string
}

func (s secretNS) List(labels.Selector) ([]*corev1.Secret, error) { return nil, nil }
func (s secretNS) Get(name string) (*corev1.Secret, error)        { return s.g.get(s.ns, name) }

// ConfigMapLister serves ConfigMaps by namespaced GET. List returns nothing.
type ConfigMapLister struct{ g *getter[*corev1.ConfigMap] }

// NewConfigMapLister returns a lister backed by GET calls with the given cache TTL.
func NewConfigMapLister(c kubernetes.Interface, ttl time.Duration) *ConfigMapLister {
	return &ConfigMapLister{newGetter(ttl, func(ctx context.Context, ns, name string) (*corev1.ConfigMap, error) {
		return c.CoreV1().ConfigMaps(ns).Get(ctx, name, metav1.GetOptions{})
	})}
}

func (l *ConfigMapLister) List(labels.Selector) ([]*corev1.ConfigMap, error) { return nil, nil }

func (l *ConfigMapLister) ConfigMaps(ns string) corev1listers.ConfigMapNamespaceLister {
	return configMapNS{l.g, ns}
}

type configMapNS struct {
	g  *getter[*corev1.ConfigMap]
	ns string
}

func (s configMapNS) List(labels.Selector) ([]*corev1.ConfigMap, error) { return nil, nil }
func (s configMapNS) Get(name string) (*corev1.ConfigMap, error)        { return s.g.get(s.ns, name) }

// SecretInformer adapts SecretLister to the informer interface the pod controller wants.
// The pod controller only reads the Lister; there is no informer, so nothing lists or watches.
type SecretInformer struct{ L *SecretLister }

var _ corev1informers.SecretInformer = SecretInformer{}

func (SecretInformer) Informer() cache.SharedIndexInformer  { return nil }
func (i SecretInformer) Lister() corev1listers.SecretLister { return i.L }

// ConfigMapInformer adapts ConfigMapLister the same way.
type ConfigMapInformer struct{ L *ConfigMapLister }

var _ corev1informers.ConfigMapInformer = ConfigMapInformer{}

func (ConfigMapInformer) Informer() cache.SharedIndexInformer     { return nil }
func (i ConfigMapInformer) Lister() corev1listers.ConfigMapLister { return i.L }

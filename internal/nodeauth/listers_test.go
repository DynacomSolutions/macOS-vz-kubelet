package nodeauth

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"
)

func TestSecretListerGetsNamespacedWithTTL(t *testing.T) {
	c := fake.NewClientset(&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: "a", Name: "s"}})
	l := NewSecretLister(c, time.Minute)
	now := time.Now()
	l.g.now = func() time.Time { return now }

	for i := 0; i < 2; i++ {
		s, err := l.Secrets("a").Get("s")
		require.NoError(t, err)
		assert.Equal(t, "s", s.Name)
	}
	gets := 0
	for _, a := range c.Actions() {
		assert.Equal(t, "get", a.GetVerb(), "only namespaced GETs, never list or watch")
		gets++
	}
	assert.Equal(t, 1, gets, "second read served from cache")

	now = now.Add(2 * time.Minute)
	_, err := l.Secrets("a").Get("s")
	require.NoError(t, err)
	assert.Len(t, c.Actions(), 2, "expired entry refetched")
}

func TestSecretListerNotFoundPassesThroughUncached(t *testing.T) {
	c := fake.NewClientset()
	l := NewSecretLister(c, time.Minute)
	_, err := l.Secrets("a").Get("missing")
	assert.True(t, apierrors.IsNotFound(err))

	c.PrependReactor("get", "secrets", func(ktesting.Action) (bool, runtime.Object, error) {
		return true, &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: "a", Name: "missing"}}, nil
	})
	_, err = l.Secrets("a").Get("missing")
	assert.NoError(t, err, "a NotFound is not cached")
}

func TestConfigMapListerAndNoClusterWideCalls(t *testing.T) {
	c := fake.NewClientset(&corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: "a", Name: "c"}})
	l := NewConfigMapLister(c, time.Minute)
	cm, err := ConfigMapInformer{l}.Lister().ConfigMaps("a").Get("c")
	require.NoError(t, err)
	assert.Equal(t, "c", cm.Name)
	all, err := l.List(nil)
	assert.NoError(t, err)
	assert.Empty(t, all)
}

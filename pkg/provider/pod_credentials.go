package provider

import (
	"context"

	authv1 "k8s.io/api/authentication/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"
)

// defaultTokenExpirationSeconds is the kubelet default for projected tokens.
const defaultTokenExpirationSeconds = 3607

// extractPodCredentials extracts the service account token, config maps and secrets required for the Pod's volumes.
func (p *MacOSVZProvider) extractPodCredentials(ctx context.Context, pod *corev1.Pod) (map[string]*corev1.ConfigMap, map[string]*corev1.Secret, string, error) {
	var serviceAccountToken string
	configMaps := map[string]*corev1.ConfigMap{}
	secrets := map[string]*corev1.Secret{}

	cmRefs, secretRefs := findObjectRefs(pod)
	// Per-object GETs only: the Node authorizer allows these for objects referenced by the Pod.
	for name, optional := range cmRefs {
		cm, err := p.k8sClient.CoreV1().ConfigMaps(pod.Namespace).Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			if optional && apierrors.IsNotFound(err) {
				continue
			}
			return nil, nil, "", err
		}
		configMaps[name] = cm
	}
	for name, optional := range secretRefs {
		sec, err := p.k8sClient.CoreV1().Secrets(pod.Namespace).Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			if optional && apierrors.IsNotFound(err) {
				continue
			}
			return nil, nil, "", err
		}
		secrets[name] = sec
	}

	if pod.Spec.AutomountServiceAccountToken == nil || *pod.Spec.AutomountServiceAccountToken {
		if svcProj, _ := findProjections(pod); svcProj != nil {
			token, err := p.createServiceAccountToken(ctx, pod, svcProj)
			if err != nil {
				return nil, nil, "", err
			}
			serviceAccountToken = token
		}
	}

	return configMaps, secrets, serviceAccountToken, nil
}

// findObjectRefs returns the config maps and secrets named by plain and projected volumes,
// mapped to whether every reference to them is optional.
func findObjectRefs(pod *corev1.Pod) (cms, secrets map[string]bool) {
	cms, secrets = map[string]bool{}, map[string]bool{}
	add := func(m map[string]bool, name string, optional *bool) {
		opt := optional != nil && *optional
		if prev, ok := m[name]; ok {
			opt = opt && prev
		}
		m[name] = opt
	}
	for _, vol := range pod.Spec.Volumes {
		if vol.ConfigMap != nil {
			add(cms, vol.ConfigMap.Name, vol.ConfigMap.Optional)
		}
		if vol.Secret != nil {
			add(secrets, vol.Secret.SecretName, vol.Secret.Optional)
		}
		if vol.Projected != nil {
			for _, src := range vol.Projected.Sources {
				if src.ConfigMap != nil {
					add(cms, src.ConfigMap.Name, src.ConfigMap.Optional)
				}
				if src.Secret != nil {
					add(secrets, src.Secret.Name, src.Secret.Optional)
				}
			}
		}
	}
	return cms, secrets
}

// createServiceAccountToken creates a token for the service account.
// The request is bound to the Pod, as kubelet does; the Node authorizer rejects unbound requests.
func (p *MacOSVZProvider) createServiceAccountToken(ctx context.Context, pod *corev1.Pod, svcProj *corev1.ServiceAccountTokenProjection) (string, error) {
	var audiences []string
	if svcProj.Audience != "" {
		audiences = []string{svcProj.Audience}
	}
	expiry := svcProj.ExpirationSeconds
	if expiry == nil {
		expiry = ptr.To(int64(defaultTokenExpirationSeconds))
	}
	tokenReq := &authv1.TokenRequest{
		Spec: authv1.TokenRequestSpec{
			Audiences:         audiences,
			ExpirationSeconds: expiry,
			BoundObjectRef: &authv1.BoundObjectReference{
				APIVersion: "v1",
				Kind:       "Pod",
				Name:       pod.Name,
				UID:        pod.UID,
			},
		},
	}
	req, err := p.k8sClient.CoreV1().ServiceAccounts(pod.Namespace).CreateToken(ctx, pod.Spec.ServiceAccountName, tokenReq, metav1.CreateOptions{})
	if err != nil {
		return "", err
	}
	// TODO: ideally implement token rotation
	return req.Status.Token, nil
}

// findProjections finds the service account and config map projections from the Pod's volumes.
func findProjections(pod *corev1.Pod) (*corev1.ServiceAccountTokenProjection, *corev1.ConfigMapProjection) {
	var svcProj *corev1.ServiceAccountTokenProjection
	var cmProj *corev1.ConfigMapProjection
	for _, vol := range pod.Spec.Volumes {
		if vol.Projected != nil {
			for _, source := range vol.Projected.Sources {
				if source.ServiceAccountToken != nil {
					svcProj = source.ServiceAccountToken
				}
				if source.ConfigMap != nil {
					cmProj = source.ConfigMap
				}
				if svcProj != nil && cmProj != nil {
					break
				}
			}
		}
	}
	return svcProj, cmProj
}

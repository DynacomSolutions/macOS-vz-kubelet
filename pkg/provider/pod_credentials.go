package provider

import (
	"context"

	authv1 "k8s.io/api/authentication/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"
)

// defaultTokenExpirationSeconds is the kubelet default for projected tokens.
const defaultTokenExpirationSeconds = 3607

// extractPodCredentials extracts the service account token and config maps required for the Pod.
func (p *MacOSVZProvider) extractPodCredentials(ctx context.Context, pod *corev1.Pod) (map[string]*corev1.ConfigMap, string, error) {
	var serviceAccountToken string
	configMaps := map[string]*corev1.ConfigMap{}

	if pod.Spec.AutomountServiceAccountToken == nil || *pod.Spec.AutomountServiceAccountToken {
		svcProj, cmProj := findProjections(pod)
		if err := p.populateConfigMaps(ctx, pod.Namespace, cmProj, configMaps); err != nil {
			return nil, "", err
		}

		if svcProj != nil {
			token, err := p.createServiceAccountToken(ctx, pod, svcProj)
			if err != nil {
				return nil, "", err
			}
			serviceAccountToken = token
		}
	}

	return configMaps, serviceAccountToken, nil
}

// populateConfigMaps fetches and populates the config maps based on the ConfigMapProjection.
func (p *MacOSVZProvider) populateConfigMaps(ctx context.Context, namespace string, cmProj *corev1.ConfigMapProjection, configMaps map[string]*corev1.ConfigMap) error {
	if cmProj != nil {
		// use core client directly instead of lister due to better nature of caching
		configMap, err := p.k8sClient.CoreV1().ConfigMaps(namespace).Get(ctx, cmProj.Name, metav1.GetOptions{})
		if err != nil {
			return err
		}
		configMaps[cmProj.Name] = configMap
	}
	return nil
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

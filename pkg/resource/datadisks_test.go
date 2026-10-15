package resource_test

import (
	"testing"

	"github.com/agoda-com/macOS-vz-kubelet/pkg/resource"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestDataDisks(t *testing.T) {
	for name, tc := range map[string]struct {
		annotations map[string]string
		want        []string
		wantErr     string
	}{
		"no annotation":        {annotations: nil, want: nil},
		"one":                  {annotations: map[string]string{resource.DataDisksAnnotation: "r.io/a/x:1"}, want: []string{"r.io/a/x:1"}},
		"order and whitespace": {annotations: map[string]string{resource.DataDisksAnnotation: " r.io/a/y:1 , r.io/a/x:1"}, want: []string{"r.io/a/y:1", "r.io/a/x:1"}},
		"four":                 {annotations: map[string]string{resource.DataDisksAnnotation: "a/1:1,a/2:1,a/3:1,a/4:1"}, want: []string{"a/1:1", "a/2:1", "a/3:1", "a/4:1"}},
		"five":                 {annotations: map[string]string{resource.DataDisksAnnotation: "a/1:1,a/2:1,a/3:1,a/4:1,a/5:1"}, wantErr: "maximum is 4"},
		"empty annotation":     {annotations: map[string]string{resource.DataDisksAnnotation: ""}, wantErr: "empty entry"},
		"empty entry":          {annotations: map[string]string{resource.DataDisksAnnotation: "a/1:1,,a/2:1"}, wantErr: "empty entry"},
		"trailing comma":       {annotations: map[string]string{resource.DataDisksAnnotation: "a/1:1,"}, wantErr: "empty entry"},
		"blank entry":          {annotations: map[string]string{resource.DataDisksAnnotation: "a/1:1, "}, wantErr: "empty entry"},
		"duplicate":            {annotations: map[string]string{resource.DataDisksAnnotation: "a/1:1, a/1:1"}, wantErr: "twice"},
	} {
		t.Run(name, func(t *testing.T) {
			got, err := resource.DataDisks(&corev1.Pod{ObjectMeta: metav1.ObjectMeta{Annotations: tc.annotations}})
			if tc.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.wantErr)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}

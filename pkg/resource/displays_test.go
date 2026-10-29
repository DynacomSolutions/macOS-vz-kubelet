package resource_test

import (
	"testing"

	"github.com/agoda-com/macOS-vz-kubelet/pkg/resource"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestDisplays(t *testing.T) {
	oneDefault := []resource.Display{{Width: 1920, Height: 1200, PPI: 80}}
	for name, tc := range map[string]struct {
		annotations map[string]string
		want        []resource.Display
		wantErr     string
	}{
		"missing annotation": {annotations: nil, want: oneDefault},
		"other annotations":  {annotations: map[string]string{"foo": "bar"}, want: oneDefault},
		"example": {annotations: map[string]string{resource.DisplaysAnnotation: "1920x1200,1920x1080"}, want: []resource.Display{
			{Width: 1920, Height: 1200, PPI: 80},
			{Width: 1920, Height: 1080, PPI: 80},
		}},
		"example with ppi": {annotations: map[string]string{resource.DisplaysAnnotation: "1920x1200@80,1920x1080@80"}, want: []resource.Display{
			{Width: 1920, Height: 1200, PPI: 80},
			{Width: 1920, Height: 1080, PPI: 80},
		}},
		"default ppi": {annotations: map[string]string{resource.DisplaysAnnotation: "1280x800"}, want: []resource.Display{
			{Width: 1280, Height: 800, PPI: resource.DefaultDisplayPPI},
		}},
		"order and whitespace": {annotations: map[string]string{resource.DisplaysAnnotation: " 1280x800@100 , 1920x1200 "}, want: []resource.Display{
			{Width: 1280, Height: 800, PPI: 100},
			{Width: 1920, Height: 1200, PPI: 80},
		}},
		"bounds": {annotations: map[string]string{resource.DisplaysAnnotation: "640x640@50,7680x7680@300"}, want: []resource.Display{
			{Width: 640, Height: 640, PPI: 50},
			{Width: 7680, Height: 7680, PPI: 300},
		}},
		"four": {annotations: map[string]string{resource.DisplaysAnnotation: "640x640,800x800,1024x768,1280x800"}, want: []resource.Display{
			{Width: 640, Height: 640, PPI: 80},
			{Width: 800, Height: 800, PPI: 80},
			{Width: 1024, Height: 768, PPI: 80},
			{Width: 1280, Height: 800, PPI: 80},
		}},
		"same size different ppi": {annotations: map[string]string{resource.DisplaysAnnotation: "1920x1200@80,1920x1200@100"}, want: []resource.Display{
			{Width: 1920, Height: 1200, PPI: 80},
			{Width: 1920, Height: 1200, PPI: 100},
		}},
		"five":             {annotations: map[string]string{resource.DisplaysAnnotation: "640x640,800x800,1024x768,1280x800,1920x1080"}, wantErr: "maximum is 4"},
		"empty annotation": {annotations: map[string]string{resource.DisplaysAnnotation: ""}, wantErr: "empty"},
		"blank annotation": {annotations: map[string]string{resource.DisplaysAnnotation: "   "}, wantErr: "empty"},
		"empty entry":      {annotations: map[string]string{resource.DisplaysAnnotation: "1920x1200,,1920x1080"}, wantErr: "empty entry"},
		"trailing comma":   {annotations: map[string]string{resource.DisplaysAnnotation: "1920x1200,"}, wantErr: "empty entry"},
		"blank entry":      {annotations: map[string]string{resource.DisplaysAnnotation: "1920x1200, "}, wantErr: "empty entry"},
		"bad token":        {annotations: map[string]string{resource.DisplaysAnnotation: "nope"}, wantErr: "invalid display"},
		"missing height":   {annotations: map[string]string{resource.DisplaysAnnotation: "1920x"}, wantErr: "invalid display"},
		"missing ppi":      {annotations: map[string]string{resource.DisplaysAnnotation: "1920x1200@"}, wantErr: "invalid display"},
		"ppi word":         {annotations: map[string]string{resource.DisplaysAnnotation: "1920x1200@abc"}, wantErr: "invalid display"},
		"capital x":        {annotations: map[string]string{resource.DisplaysAnnotation: "1920X1200"}, wantErr: "invalid display"},
		"internal space":   {annotations: map[string]string{resource.DisplaysAnnotation: "1920 x 1200"}, wantErr: "invalid display"},
		"width low":        {annotations: map[string]string{resource.DisplaysAnnotation: "639x1200"}, wantErr: "out of range"},
		"width high":       {annotations: map[string]string{resource.DisplaysAnnotation: "7681x1200"}, wantErr: "out of range"},
		"height low":       {annotations: map[string]string{resource.DisplaysAnnotation: "1920x639"}, wantErr: "out of range"},
		"height high":      {annotations: map[string]string{resource.DisplaysAnnotation: "1920x7681"}, wantErr: "out of range"},
		"ppi low":          {annotations: map[string]string{resource.DisplaysAnnotation: "1920x1200@49"}, wantErr: "out of range"},
		"ppi high":         {annotations: map[string]string{resource.DisplaysAnnotation: "1920x1200@301"}, wantErr: "out of range"},
		"duplicate": {annotations: map[string]string{resource.DisplaysAnnotation: "1920x1200@80, 1920x1200@80"}, want: []resource.Display{
			{Width: 1920, Height: 1200, PPI: 80},
			{Width: 1920, Height: 1200, PPI: 80},
		}},
		"duplicate default ppi": {annotations: map[string]string{resource.DisplaysAnnotation: "1920x1200,1920x1200@80"}, want: []resource.Display{
			{Width: 1920, Height: 1200, PPI: 80},
			{Width: 1920, Height: 1200, PPI: 80},
		}},
		"dual 1920x1080": {annotations: map[string]string{resource.DisplaysAnnotation: "1920x1080,1920x1080"}, want: []resource.Display{
			{Width: 1920, Height: 1080, PPI: 80},
			{Width: 1920, Height: 1080, PPI: 80},
		}},
	} {
		t.Run(name, func(t *testing.T) {
			got, err := resource.Displays(&corev1.Pod{ObjectMeta: metav1.ObjectMeta{Annotations: tc.annotations}})
			if tc.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.wantErr)
				assert.Contains(t, err.Error(), resource.DisplaysAnnotation)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}

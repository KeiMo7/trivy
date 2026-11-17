package image_test

import (
	"math/rand"
	"sync"
	"testing"

	"github.com/google/go-containerregistry/pkg/v1/random"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/internal/cachetest"
	"github.com/aquasecurity/trivy/pkg/fanal/artifact"
	image2 "github.com/aquasecurity/trivy/pkg/fanal/artifact/image"
	"github.com/aquasecurity/trivy/pkg/observe"

	_ "github.com/aquasecurity/trivy/pkg/fanal/analyzer/config/all"
	_ "github.com/aquasecurity/trivy/pkg/fanal/analyzer/imgconf/apk"
	_ "github.com/aquasecurity/trivy/pkg/fanal/analyzer/language/php/composer"
	_ "github.com/aquasecurity/trivy/pkg/fanal/analyzer/language/ruby/bundler"
	_ "github.com/aquasecurity/trivy/pkg/fanal/analyzer/licensing"
	_ "github.com/aquasecurity/trivy/pkg/fanal/analyzer/os/alpine"
	_ "github.com/aquasecurity/trivy/pkg/fanal/analyzer/os/debian"
	_ "github.com/aquasecurity/trivy/pkg/fanal/analyzer/pkg/apk"
	_ "github.com/aquasecurity/trivy/pkg/fanal/analyzer/pkg/dpkg"
	_ "github.com/aquasecurity/trivy/pkg/fanal/analyzer/repo/apk"
	_ "github.com/aquasecurity/trivy/pkg/fanal/analyzer/secret"
	_ "github.com/aquasecurity/trivy/pkg/fanal/handler/sysfile"
)

// TestArtifact_ProgressReflectsLayers runs a real inspection over a multi-layer
// image and verifies the acceptance criteria: at least three callbacks,
// monotonically increasing counters, and a total equal to the layer count.
func TestArtifact_ProgressReflectsLayers(t *testing.T) {
	const layerCount = 5
	randomImage, err := random.Image(2048, layerCount, random.WithSource(rand.NewSource(1)))
	require.NoError(t, err)

	img := &fakeImage{Image: randomImage}
	c := cachetest.NewCache(t, nil)

	var mu sync.Mutex
	var events []observe.Progress
	tracker := observe.NewTracker(observe.Options{
		Callback: func(p observe.Progress) {
			mu.Lock()
			events = append(events, p)
			mu.Unlock()
		},
	})

	art, err := image2.NewArtifact(img, c, artifact.Option{})
	require.NoError(t, err)

	ctx := observe.WithTracker(t.Context(), tracker)
	_, err = art.Inspect(ctx)
	require.NoError(t, err)
	tracker.Finish()

	mu.Lock()
	defer mu.Unlock()
	require.GreaterOrEqual(t, len(events), 3, "progress must be reported at least three times")

	for i, p := range events {
		assert.Equal(t, observe.StageImageLayers, p.Stage)
		assert.Equal(t, int64(layerCount), p.Total, "total must reflect the number of layers")
		if i > 0 {
			assert.GreaterOrEqual(t, p.Current, events[i-1].Current, "current must be monotonic")
		}
	}

	last := events[len(events)-1]
	assert.Equal(t, int64(layerCount), last.Current, "all layers must be accounted for")
	assert.Greater(t, last.BytesProcessed, int64(0), "processed bytes should be observed")
}

// TestArtifact_ProgressCallbackPanicDoesNotFailScan proves a faulty callback
// cannot take the scan down.
func TestArtifact_ProgressCallbackPanicDoesNotFailScan(t *testing.T) {
	randomImage, err := random.Image(1024, 3, random.WithSource(rand.NewSource(2)))
	require.NoError(t, err)

	c := cachetest.NewCache(t, nil)
	tracker := observe.NewTracker(observe.Options{
		Callback: func(observe.Progress) { panic("callback blew up") },
	})

	art, err := image2.NewArtifact(&fakeImage{Image: randomImage}, c, artifact.Option{})
	require.NoError(t, err)

	assert.NotPanics(t, func() {
		_, err = art.Inspect(observe.WithTracker(t.Context(), tracker))
	})
	require.NoError(t, err)
}

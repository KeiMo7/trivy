package local

import (
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/internal/cachetest"
	"github.com/aquasecurity/trivy/pkg/fanal/artifact"
	"github.com/aquasecurity/trivy/pkg/fanal/walker"
	"github.com/aquasecurity/trivy/pkg/observe"

	_ "github.com/aquasecurity/trivy/pkg/fanal/analyzer/config/all"
	_ "github.com/aquasecurity/trivy/pkg/fanal/analyzer/language/python/pip"
	_ "github.com/aquasecurity/trivy/pkg/fanal/analyzer/os/alpine"
	_ "github.com/aquasecurity/trivy/pkg/fanal/analyzer/pkg/apk"
	_ "github.com/aquasecurity/trivy/pkg/fanal/analyzer/secret"
	_ "github.com/aquasecurity/trivy/pkg/fanal/handler/sysfile"
)

// TestArtifact_ProgressUnknownTotal covers the streaming-input degradation:
// filesystem walks cannot know the total up front, so progress must remain
// usable with Total == 0 while Current keeps advancing.
func TestArtifact_ProgressUnknownTotal(t *testing.T) {
	var mu sync.Mutex
	var events []observe.Progress
	tracker := observe.NewTracker(observe.Options{
		Callback: func(p observe.Progress) {
			mu.Lock()
			events = append(events, p)
			mu.Unlock()
		},
	})

	art, err := NewArtifact("./testdata/alpine", cachetest.NewCache(t, nil), walker.NewFS(), artifact.Option{})
	require.NoError(t, err)

	_, err = art.Inspect(observe.WithTracker(t.Context(), tracker))
	require.NoError(t, err)
	tracker.Finish()

	mu.Lock()
	defer mu.Unlock()
	require.NotEmpty(t, events)

	for _, p := range events {
		assert.Equal(t, observe.StageFiles, p.Stage)
		assert.Equal(t, int64(0), p.Total, "filesystem total is unknown during a walk")
	}

	last := events[len(events)-1]
	assert.Greater(t, last.Current, int64(0), "at least one file must have been observed")
	assert.Greater(t, last.BytesProcessed, int64(0))

	for i := 1; i < len(events); i++ {
		assert.GreaterOrEqual(t, events[i].Current, events[i-1].Current)
	}
}

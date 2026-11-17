package flag_test

import (
	"testing"
	"time"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/flag"
)

func TestObserveFlagGroup_ToOptions(t *testing.T) {
	tests := []struct {
		name        string
		enabled     bool
		interval    any
		wantEnabled bool
		wantGap     time.Duration
	}{
		{
			name:        "default keeps observability disabled",
			enabled:     false,
			wantEnabled: false,
			wantGap:     500 * time.Millisecond,
		},
		{
			name:        "explicitly enabled with custom interval",
			enabled:     true,
			interval:    "2s",
			wantEnabled: true,
			wantGap:     2 * time.Second,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			viper.SetDefault(flag.ObserveIntervalFlag.ConfigName, 500*time.Millisecond)
			viper.Set(flag.ObserveProgressFlag.ConfigName, tt.enabled)
			if tt.interval != nil {
				viper.Set(flag.ObserveIntervalFlag.ConfigName, tt.interval)
			}

			f := flag.NewObserveFlagGroup()
			flags := flag.Flags{f}
			got, err := flags.ToOptions(nil)
			require.NoError(t, err)

			assert.Equal(t, tt.wantEnabled, got.ObserveOptions.Enabled)
			assert.Equal(t, tt.wantGap, got.ObserveOptions.Interval)
		})
	}
}

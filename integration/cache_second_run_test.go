//go:build integration

package integration

import (
	"bufio"
	"context"
	"io"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/internal/testutil"
	"github.com/aquasecurity/trivy/pkg/clock"
	"github.com/aquasecurity/trivy/pkg/commands"
)

// executeWithStderrCapture runs Trivy while redirecting os.Stderr, the fixed
// output of the CLI logger (log.InitLogger writes there), into a pipe and
// returns every captured log line. It restores os.Stderr even on failure.
func executeWithStderrCapture(t *testing.T, osArgs []string) []string {
	t.Helper()

	original := os.Stderr
	r, w, err := os.Pipe()
	require.NoError(t, err)
	os.Stderr = w

	var (
		lines []string
		wg    sync.WaitGroup
	)
	wg.Go(func() {
		scanner := bufio.NewScanner(r)
		scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
		for scanner.Scan() {
			lines = append(lines, scanner.Text())
		}
	})

	execErr := executeWithArgs(osArgs)

	require.NoError(t, w.Close())
	os.Stderr = original
	wg.Wait()
	require.NoError(t, execErr)
	return lines
}

func executeWithArgs(osArgs []string) error {
	defer viper.Reset()

	ctx := clock.With(context.Background(), time.Date(2021, 8, 25, 12, 20, 30, 5, time.UTC))

	app := commands.NewApp()
	app.SetOut(io.Discard)
	app.SetArgs(osArgs)
	return app.ExecuteContext(ctx)
}

func countMessage(lines []string, substr string) int {
	var n int
	for _, line := range lines {
		if strings.Contains(line, substr) {
			n++
		}
	}
	return n
}

// TestImageCacheSecondRun scans the same image twice against a shared cache
// directory and asserts that the second run does not analyze any layer again:
// the "Missing diff ID in cache" debug message must appear zero times on the
// second run because every layer is served from the cache.
func TestImageCacheSecondRun(t *testing.T) {
	cacheDir := initDB(t)
	t.Setenv("XDG_DATA_HOME", cacheDir)

	ctx := t.Context()
	cli := testutil.NewDockerClient(t)
	imageName := cli.ImageCleanLoad(t, ctx, "testdata/fixtures/images/alpine-39.tar.gz")

	osArgs := []string{
		"image",
		imageName,
		"--cache-dir",
		cacheDir,
		"--debug",
		"--skip-db-update",
		"--format=json",
		"--list-all-pkgs=false",
		"--image-src=docker",
	}

	// First run populates the layer and artifact cache.
	firstLines := executeWithStderrCapture(t, osArgs)
	assert.Positive(t, countMessage(firstLines, "Missing diff ID in cache"),
		"the cold run must analyze at least one layer")

	// Second run hits the cache for every layer, so no diff ID is missing.
	secondLines := executeWithStderrCapture(t, osArgs)
	assert.Zero(t, countMessage(secondLines, "Missing diff ID in cache"),
		"the warm run must not re-analyze any layer")
}

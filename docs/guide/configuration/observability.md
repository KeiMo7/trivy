# Runtime Observability

Trivy can emit runtime progress events and structured scan errors while a scan
is running. The capability is **opt-in**: nothing changes unless you enable it.

## Enabling Progress Events

| Flag | Config key | Default | Description |
|------|------------|---------|-------------|
| `--observe-progress` | `observe.progress.enabled` | `false` | Enable progress callbacks and structured errors |
| `--observe-interval` | `observe.progress.interval` | `500ms` | Minimum interval between progress callbacks |

```shell
$ trivy image --observe-progress --observe-interval 2s alpine:3.19
```

Each event contains the current stage, processed amount, total amount (when
known), processed bytes and elapsed time. For container images the total is the
number of layers, so progress reflects how many layers have been analyzed. For
filesystem and repository scans the tree is walked as a stream, so the total is
reported as `0` (unknown) while the processed counter keeps advancing.

When enabled from the CLI, events are written as structured log lines on
stderr:

```
INFO    Scan progress    stage="image_layers" current=3 total=12 elapsed=4.2s percent=25
```

## Structured Errors and Cancellation

With observability enabled, scan failures are wrapped in a structured error
that carries a category (`validation`, `dependency`, `auth`, `network`,
`resource`, `internal`), the failing operation and sanitized context. Targets in
errors are sanitized the same way as in reports: URL credentials are stripped
and absolute local paths are reduced to their basename.

Cancellation is reported separately from failure. A scan stopped through its
`context.Context` returns a `CanceledError` (which also satisfies
`errors.Is(err, context.Canceled)`) rather than a generic scan error, and
artifact cleanup runs before the call returns.

## Embedding Trivy as a Library

Programs embedding Trivy register a callback through the runner option:

```go
runner, err := artifact.NewRunner(ctx, opts, artifact.TargetFilesystem,
    artifact.WithProgressCallback(func(p observe.Progress) {
        metrics.Set(float64(p.Current)) // update your own metrics
    }),
)
```

Callbacks are invoked synchronously and should return quickly. A panicking
callback is recovered and logged; it never aborts the scan. The tracker keeps
only fixed-size counters, so long-running scans do not accumulate memory.

## Migration Example

The feature is disabled by default, so existing invocations need no changes.
To opt in, add the flag (or the equivalent config key) without touching any
other argument. Report formats, return values and log output remain identical
on the default path.

Before (unchanged behavior):

```shell
$ trivy fs --format json --output report.json ./project
```

After (progress events added on stderr; `report.json` is unchanged):

```shell
$ trivy fs --observe-progress --observe-interval 1s \
    --format json --output report.json ./project
```

Equivalent config file:

```yaml
observe:
  progress:
    enabled: true
    interval: 1s
```

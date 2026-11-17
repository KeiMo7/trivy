# Runtime Observability for Trivy Scans

## Modules Touched

- `pkg/observe/` (new): opt-in `Tracker` with throttled progress callbacks,
  `ScanError` structured errors with category classification, `CanceledError`
  distinct from failures, target sanitization, and the `Run` wrapper that emits
  the enter/exit/failure log trio.
- `pkg/scan/service.go`: reads the tracker from context, reports layer/file
  completion, and converts cancellation into `CanceledError` only when a
  tracker is present. Cleanup is now registered before `Inspect` so resources
  are released on cancellation or early failure.
- `pkg/fanal/artifact/image/image.go`: emits per-layer progress (total equals
  the layer count) and processed bytes for large images.
- `pkg/fanal/artifact/local/fs.go`: emits streaming file progress with an
  unknown total (`Total == 0`) for filesystem/repository walks.
- `pkg/flag/observe_flags.go` (new) + `pkg/flag/options.go`:
  `--observe-progress` / `--observe-interval` flags
  (`observe.progress.enabled` / `observe.progress.interval`), disabled by
  default; interval defaults to 500ms.
- `pkg/commands/app.go`: attaches the new flag group to every scan command.
- `pkg/commands/artifact/run.go`: builds the tracker when enabled, wires it
  into the context, and exposes `WithProgressCallback` for library embedders.
- `docs/guide/configuration/observability.md` (new) + `mkdocs.yml`: usage and
  migration example.
- Tests follow existing conventions: `observe_test.go` next to each touched
  package, table-driven where the surrounding package does so.

## Boundaries Not Covered Yet

- DB/Java-DB downloads and the checks-bundle fetch keep their existing
  progress bars; they are not yet translated into tracker events.
- Remote client/server mode forwards the scan over RPC but progress events are
  only produced client-side; server-side stages are not streamed back.
- Vulnerability matching (post-inspect backend `Scan`) has no unit-level
  progress granularity beyond stage completion, because the DB lookup batch is
  not sized per item.
- Classification uses keyword matching on wrapped error text for external
  daemons/registries; an unknown message falls back to `internal` rather than
  guessing.
- The CLI log sink is line-oriented; a machine-readable event stream (e.g.
  newline-delimited JSON to a file) is not added.

## Future Extension Points

- Add new `Stage` values and call `tracker.SetTotal/Add` from additional
  producers (DB download, RPC server) without touching callback semantics.
- Replace keyword classification with typed sentinel errors as upstream
  libraries expose them; `classify()` is the single place to extend.
- Add a pluggable `ProgressCallback` sink (file, OTel span events) alongside
  the existing log callback.
- Stream server-side progress over the existing RPC stream in client/server
  mode.

## Concurrency

The tracker is safe for concurrent use: counters use `atomic.Int64` and
callback dispatch is serialized under a mutex. Multiple analyzer goroutines can
call `Add` concurrently. Callbacks run synchronously in the calling goroutine,
so a slow callback exerts backpressure on that worker; keep callbacks cheap.
Verified with `go test -race ./pkg/observe/` and a concurrent counter test.

## Default Behavior

Without `--observe-progress` (and without a programmatic callback), no tracker
is created: report signatures/return values, error types and log output are
unchanged. Verified by building pre/post binaries and diffing both table and
JSON report outputs (identical apart from the pre-existing random `ReportID`
and wall-clock `CreatedAt`) and normalized stderr (identical).

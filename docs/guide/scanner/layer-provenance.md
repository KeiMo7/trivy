# Layer Provenance

Trivy's regular reports list *which* vulnerabilities an image contains. They do
not say *which layer* introduced each one, which makes it hard to answer a
question like: is this critical vulnerability inherited from the base image, or
did our own application layer introduce it?

The `layer-provenance` format records the origin layer of every vulnerability
and, optionally, compares two scans. It is opt-in: other formats and their exit
codes are unchanged.

## Enabling it

```bash
trivy image --format layer-provenance --output provenance.jsonl myimage:latest
```

To compare with a previous scan, pass the report written earlier:

```bash
trivy image --format layer-provenance \
  --previous-report provenance-previous.jsonl \
  --output provenance.jsonl myimage:latest
```

`--previous-report` is only accepted together with `--format layer-provenance`.

## Layer roles

Layers are classified while the image is analyzed, from the image history and
the base-image boundary detected at that time:

| Role          | Meaning                                                              |
|---------------|----------------------------------------------------------------------|
| `base`        | The layer belongs to the base image.                                 |
| `middle`      | A layer built on top of the base image that is not the top-most one. |
| `application` | The top-most layer of the image, where the application is added.     |

The role is recorded at scan time. It is deliberately *not* inferred later from
file paths: the same path can exist in more than one layer, and a path lookup
would attribute the finding to the wrong layer.

## Report structure

The report is a stream of JSON Lines records, so a large image is written
incrementally rather than assembled in memory.

```jsonc
{"type":"header","schemaVersion":1,"generatedBy":{"name":"trivy","version":"..."},"artifact":{...},"layers":[...]}
{"type":"finding","status":"added","identity":"sha256:...","vulnerability":{"id":"CVE-2024-0001",...},"package":{...},"layer":{"index":0,"role":"base","diffID":"..."}}
{"type":"layer_summary","layer":{...},"inCurrent":true,"inPrevious":true,"findings":{"total":3,"added":1,"removed":0,"unchanged":2}}
{"type":"summary","findings":{"total":4,"added":1,"removed":1,"unchanged":2,"layerChanged":0},"byRole":{...},"reconciled":true}
```

- **`finding`** — one record per vulnerability *per package version*. A
  vulnerability that affects several packages, or appears in several layers,
  produces several records rather than being collapsed into one.
- **`status`** — `added`, `removed` or `unchanged` relative to the previous
  report.
- **`layer_summary`** — one record per layer with the number of findings
  attributed to it. Each finding is counted under exactly one layer, so the
  detail and the summaries add up (`summary.reconciled` is `true` when they do).
- **`summary.byRole`** — the same counts grouped by layer role. When a change
  concentrates in the base layers, `base` carries most of the `added`/`removed`
  counts.

### Stable identity

`identity` is a hash of the vulnerability, package and installed version. It
does not include the scan time, the image tag or the output order, so the same
finding has the same identity in both scans. Because the installed version is
part of the identity, a package upgrade that removes an old vulnerability and
introduces a new one is recorded as *one removal and one addition*, not as a
single net change.

### Determinism

Findings are sorted before they are written. The same two input reports always
produce byte-identical output.

## Errors

- A missing previous report is an error naming the path; it is never treated as
  "everything is new".
- A corrupt previous report is an error naming the path and the offending line.
- A previous report written by an incompatible Trivy version is rejected with a
  message saying which format version was found and what to do.
- When writing to a file, the report is written to a temporary file and renamed
  into place, so a failure mid-write does not leave a half-written report.

## Example

[`layer-provenance.sample.jsonl`](layer-provenance.sample.jsonl) is the output
of a scan compared with a previous one. In this example:

- the base layer carries 2 findings (1 unchanged, 1 removed),
- the application layer carries 1 finding (1 added),

and `summary.reconciled` is `true`, so the per-layer counts add up to the
findings.

## Limitations

- Layer roles require image layer information. For scans without layers (for
  example a filesystem or a JSON report passed to `trivy convert`), the role is
  `unknown`.
- The base/middle boundary is guessed from the image history, as with the base
  layer detection used elsewhere in Trivy. If it cannot be detected, only the
  top-most layer is classified.

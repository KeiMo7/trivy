# Machine-readable coverage report: field contract

Every scan emits one JSON document. The coverage section is the authoritative
record of *how much was actually seen* and is designed to be aggregated by
artifact without parsing logs.

## Top level

| Field | Type | Meaning |
|---|---|---|
| `schema_version` | string | Contract version, currently `"1.0"` |
| `kind` | string | Always `"coverage-scan-report"` |
| `status` | string | Batch verdict, see [statuses](#statuses-and-exit-codes) |
| `summary` | object | Aggregated totals and human-readable verdict text |
| `artifacts` | array | One entry per scanned artifact (batch-safe) |
| `config_effective` | object | Thresholds in effect during this scan |
| `coverage_fingerprint` | string | SHA-256 over all coverage sections, excluding timestamps |
| `generated_at` | string | UTC ISO-8601 timestamp; the only field allowed to differ between repeated scans |

## `summary.totals` — the reconciliation contract

```
traversed == analyzed + skipped + unrecognized
```

The identity is evaluated per artifact and for the batch; a violation aborts
report production (exit code 4) instead of emitting a dishonest report.

| Field | Meaning |
|---|---|
| `artifacts` / `artifacts_failed` | Batch size and how many artifacts failed outright |
| `traversed` | Nodes the scanner reached (files, members, segments) |
| `analyzed` | Nodes fully read and inspected |
| `skipped` | Nodes abandoned for one of the four reason categories |
| `unrecognized` | Nodes whose format matches no known signature |
| `directories_traversed` / `directories_skipped` | Directory-level accounting (kept separate so the file identity stays exact) |
| `findings` | Total security findings |
| `unreadable_segments` | Count of segments that could not be unpacked as a whole |
| `skipped_by_reason` | Per-reason counts: `size_limit`, `no_permission`, `unpack_failed`, `unrecognized` |
| `identity_holds` | Boolean proof of the reconciliation identity |

## Reason taxonomy (never collapsed into one category)

| Code | Meaning |
|---|---|
| `size_limit` | Node exceeded the configured `max_file_size` (archive members) or unpacked-byte/member caps (containers) |
| `no_permission` | Node could not be opened/read (EACCES/EPERM), including encrypted archive members |
| `unpack_failed` | Truncated/corrupted/over-deep archive or a segment unreadable as a whole |
| `unrecognized` | Content matches no known signature; aggregated per directory, never expanded per file |

## Per-artifact `coverage` block

```json
{
  "artifact_id": "mixed-batch",
  "counters": { "traversed": 5, "analyzed": 1, "skipped": 3,
                "unrecognized": 1, "identity_holds": true, "...": "..." },
  "skipped_by_reason": { "size_limit": 1, "no_permission": 1,
                         "unpack_failed": 1, "unrecognized": 1 },
  "abandoned": [
    {
      "reason": "no_permission",
      "directory": "noaccess",
      "count": 1,
      "total_size_bytes": 0,
      "items": [
        { "reason": "no_permission",
          "location": "noaccess/<REDACTED:b7613dcd3c1cf576>",
          "location_hash": "…", "kind": "file",
          "size_bytes": null, "detail": "PermissionError",
          "container": null, "segment_id": null }
      ]
    }
  ],
  "directory_abandoned": [
    { "reason": "no_permission", "directory": ".", "count": 1,
      "items": [ { "reason": "no_permission", "location": "vault",
                   "location_hash": "…", "kind": "directory",
                   "size_bytes": null, "detail": "PermissionError",
                   "container": null, "segment_id": null } ] }
  ],
  "unrecognized": [
    { "directory": "weird", "count": 1,
      "total_size_bytes": 303, "sample_extensions": [".qqq"] }
  ],
  "unreadable_segments": [
    { "segment_id": "seg-…", "location": "packs/broken.zip",
      "location_hash": "…", "format": "zip",
      "detail": "BadZipFile: File is not a zip file",
      "affected_packages": ["*"] }
  ],
  "directories": { "traversed": 4, "skipped": 0 },
  "findings": [
    { "rule_id": "aws-access-key-id",
      "location": "config.ini", "line_hint": 2, "location_hash": "…" }
  ],
  "fatal_error": null
}
```

### Aggregation rules

- The three abandonment reasons (`size_limit`, `no_permission`,
  `unpack_failed`) keep one item per abandoned node — each names a redacted
  location, size, kind and classifier detail, because an operator must act on
  them. They live in `abandoned` and sum to `counters.skipped`.
- `unrecognized` is a distinct terminal state, rendered only under the
  `unrecognized` array as per-directory counts (plus sample extensions), so
  unknown-format noise cannot flood the report or bury real alerts. It has no
  per-file expansion and is mirrored in `skipped_by_reason.unrecognized` only
  to keep the four-category taxonomy queryable in one object.
- Directory-level abandonments are isolated in `directory_abandoned` and feed
  only the `directories_*` counters, never the file-level identity. A directory
  that cannot be scanned therefore cannot perturb
  `traversed == analyzed + skipped + unrecognized`, while still carrying a
  reason-classified, redacted record of its own.
- `affected_packages` names the top-level package set inside an unreadable
  segment. When truncation struck after some members were read, the reached
  packages are named explicitly alongside a sentinel. Sentinels: `"*"` (the
  whole segment, e.g. nothing could be opened), `"*remaining*"` (a cap was
  hit), `"*tail*"` (truncation; content after the named packages went unread).

## Statuses and exit codes

| `status` | Meaning | Exit code |
|---|---|---|
| `clean` | No findings **and** full coverage | 0 |
| `findings` | Findings with full coverage | 1 |
| `incomplete` | No findings, but coverage gaps exist | 2 |
| `findings_incomplete` | Both findings and coverage gaps | 1 (gap still visible in status/text) |
| `failed` | Every artifact failed before scanning | 3 |
| — | Report could not be produced / bad invocation / coverage identity violated | 4 |

A skipped node can never promote the verdict to `clean`. Coverage gaps force
`incomplete` (or `findings_incomplete`) regardless of how clean the readable
subset looks.

## Redaction contract

Any path component matching a configured sensitive-name rule (private keys,
`.env`, `.aws/`, `.ssh/`, credential/token/password names, keystores, …) is
replaced by `<REDACTED:sha256-16>` before entering the report. The hash is
deterministic and content-derived, so two scans produce identical tokens and
two different sensitive names remain distinguishable. Matched secret material
itself is never copied into findings — only rule id, redacted location and
line hint are recorded.

# coverage-scan — a scanner that never mistakes "unread" for "clean"

A coverage-aware artifact scanner built in response to a white-box review
finding: the previous "zero vulnerabilities" conclusion was produced from a
scan in which roughly a third of the artifact's content was never read, yet
the report was indistinguishable from one produced against genuinely clean
input.

This scanner makes unread content first-class. Every node it reaches is
accounted for as exactly one of **analyzed**, **skipped** (with one of four
distinct reason categories) or **unrecognized**, and the report's
reconciliation identity is enforced before any report is allowed to exist:

```
traversed == analyzed + skipped + unrecognized
```

## Why this exists (the eight failure modes it closes)

1. Oversized files were silently dropped at debug-log level → now a
   `size_limit` skip record with location, size and detail.
2. Permission-denied / truncated reads were indistinguishable from "large
   file" → `no_permission` is its own category, separate from size and unpack
   failures.
3. Half-failed archive extraction left extracted parts in an undefined state →
   extraction is an event stream; members read before the failure keep their
   classification and the failure becomes an `unreadable_segments` record.
4. A wholly unreadable segment produced neither error nor annotation → segment
   id plus the affected package set are recorded.
5. One failed artifact in a batch still produced a single "no problem" summary
   → every artifact gets its own status; one failure never collapses the batch.
6. Unknown formats were neither counted nor summarized → counted and
   aggregated per directory, never expanded per file.
7. Reports carried no "how much was seen" numbers → counters, per-reason
   breakdowns and a reconciliation identity in every report.
8. Exit codes expressed only "findings yes/no" → five codes distinguish clean,
   findings, incomplete, all-failed and report-error states.

## Layout

```
coverage_scan/
  model.py       reason taxonomy, statuses, exit codes, record types, counters
  config.py      configurable thresholds (cannot change verdict logic)
  redact.py      deterministic path/name redaction
  filetype.py    magic-byte content identification
  secrets.py     streaming secret rules (no matched material is stored)
  archive.py     zip/tar/gzip event-stream extraction with failure events
  collector.py   counting, aggregation, reconciliation enforcement
  walker.py      filesystem + nested-archive traversal and classification
  scanner.py     batch orchestration, verdicts, atomic report writing
  render.py      human-readable companion rendering
  cli.py         command-line entry point
tests/
  make_fixtures.py            deterministic fixture factory
  test_units.py               unit tests
  test_integration.py         end-to-end acceptance tests
docs/coverage-report-schema.md   machine-readable field contract
reports/                       generated JSON + text reports
```

## Running

```bash
# regenerate the fixture set (oversized, no-perm, truncated zip/tar/gzip,
# encrypted, deep-nested, unknown, corrupted, sensitive paths, mixed tree)
python3 tests/make_fixtures.py

# scan one or many artifacts; reports are machine-readable JSON plus optional text
python3 scripts/coverage_scan_launcher.py <path>... \
    --json reports/report.json [--text reports/report.txt] \
    [--max-file-size 4096] [--max-archive-depth 8] [--config config.json]

# full acceptance run: unit + integration suites, four reasons, identity,
# three exit codes, determinism, redaction, report-failure guard
bash scripts/acceptance.sh
```

The launcher runs under `python -I` so a planted `json.py` (or any other
module) inside an untrusted artifact directory cannot be imported; the
package path is injected explicitly by the launcher, which lives outside the
artifact directories. This is verified by scanning a directory that contains
a hostile `json.py`/`os.py` from inside that directory: the planted modules
are never executed.

## Exit codes

| Code | Situation |
|---|---|
| 0 | Clean **and** fully covered |
| 1 | Findings present (with or without a coverage gap) |
| 2 | No findings, but coverage is incomplete |
| 3 | Every artifact in the batch failed before scanning |
| 4 | Report could not be produced, bad invocation, or reconciliation failure |

## Hard guarantees

- **Machine-readable coverage, aggregatable per artifact** — coverage lives in
  JSON, never only in logs.
- **No malformed input escapes accounting** — zip/tar/gzip decoding errors
  (`TarError`, `zlib.error`, `BadZipFile`, `LZMAError`, truncated member
  streams, …) are all funneled through the event model into `unpack_failed`
  records plus an `unreadable_segments` entry, so a corrupt member can never
  silently drop its container out of coverage. Verified with a 350+ input
  mutation/fuzz campaign: zero fatal collapses, zero identity violations.
- **Skips never promote to a pass** — abandoned nodes carry an independent
  status and force `incomplete`/`findings_incomplete`.
- **Configuration cannot change verdicts** — thresholds change what gets
  skipped; finding evaluation and the reconciliation rules are fixed.
- **Sensitive strings are redacted before output** — key paths, credential
  filenames and similar names become deterministic `<REDACTED:…>` tokens;
  secret material is never stored.
- **Coverage-write failure fails the whole report** — serialization is
  validated and writes are atomic (temp file + rename); no partially-complete
  report is ever left in place.
- **Deterministic coverage** — repeated scans of the same artifact produce
  identical coverage sections and fingerprints; only `generated_at` differs.

See [`docs/coverage-report-schema.md`](../docs/coverage-report-schema.md) for
the full field contract.

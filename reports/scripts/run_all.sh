#!/usr/bin/env bash
# Runs the full acceptance flow: build (offline) -> generate -> round-trip ->
# compare -> reproducibility check -> failure/degrade cases.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
LOG="$ROOT/reports/logs"
mkdir -p "$LOG"

export PATH="$HOME/go-sdk/bin:$PATH"
export TMPDIR="${TMPDIR:-$HOME/tmpuid1/gotmp}"
export GOCACHE="${GOCACHE:-$HOME/tmpuid1/gocache}"
export GOPROXY=off
mkdir -p "$TMPDIR" "$GOCACHE"

echo "### Building vexgen (offline, GOPROXY=off)"
go build -o "$HERE/vexgen" "$ROOT/cmd/vexgen"

echo "### Step 1: generate"
"$HERE/01_generate.sh" | tee "$LOG/01_generate_and_roundtrip.log"

echo "### Step 2: round-trip through the unmodified consumer"
"$HERE/02_roundtrip.sh" 2>&1 | tee -a "$LOG/01_generate_and_roundtrip.log"

echo "### Step 3: exact-set comparison"
"$HERE/03_compare.sh"

echo "### Reproducibility: second generation must be byte-identical"
SECOND="$TMPDIR/openvex.repro.json"
SOURCE_DATE_EPOCH=1763942400 "$HERE/vexgen" generate \
  --scans "$ROOT/reports/input/scans.json" \
  --reviews "$ROOT/reports/input/reviews_round1.json,$ROOT/reports/input/reviews_round2.json" \
  --out "$SECOND" \
  --reconcile "$TMPDIR/repro.reconcile.json"
if cmp -s "$ROOT/reports/output/openvex.json" "$SECOND"; then
  echo "OK: documents are byte-identical"
else
  echo "FAIL: reproducibility check" >&2
  exit 1
fi

echo "### Failure and degradation cases"
"$HERE/04_failures.sh"

echo
echo "ALL ACCEPTANCE STEPS PASSED"

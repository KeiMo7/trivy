#!/usr/bin/env bash
# Step 1/3 - generate the OpenVEX document and reconciliation report.
#
# Offline and deterministic: SOURCE_DATE_EPOCH pins every timestamp so two
# runs over identical inputs produce byte-identical documents.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
BIN="$HERE/vexgen"
IN="$ROOT/reports/input"
OUT="$ROOT/reports/output"
LOG="$ROOT/reports/logs"

mkdir -p "$OUT" "$LOG"

# Fixed epoch makes output reproducible regardless of wall clock.
export SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-1763942400}"
export VEXGEN_AUTHOR="${VEXGEN_AUTHOR:-security-review-team}"
# GOPROXY=off guarantees the build/run never reaches the network.
export GOPROXY=off

"$BIN" generate \
  --scans "$IN/scans.json" \
  --reviews "$IN/reviews_round1.json,$IN/reviews_round2.json" \
  --out "$OUT/openvex.json" \
  --reconcile "$OUT/reconciliation.json"

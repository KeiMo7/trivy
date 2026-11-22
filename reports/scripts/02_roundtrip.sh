#!/usr/bin/env bash
# Step 2/3 - feed the generated document back through the unmodified Trivy VEX
# consumer (pkg/vex). This is the real matching path, not a reimplementation.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
BIN="$HERE/vexgen"
IN="$ROOT/reports/input"
OUT="$ROOT/reports/output"

export SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-1763942400}"
export VEXGEN_AUTHOR="${VEXGEN_AUTHOR:-security-review-team}"
export GOPROXY=off

"$BIN" roundtrip \
  --scans "$IN/scans.json" \
  --document "$OUT/openvex.json" \
  --report "$OUT/roundtrip.json"

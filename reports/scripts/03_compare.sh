#!/usr/bin/env bash
# Step 3/3 - assert the observed consumer hit set equals the expected set
# exactly (no more, no fewer) and every status matches. Fails loudly on any
# missing/unexpected hit or status mismatch.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
REPORT="$ROOT/reports/output/roundtrip.json"

if [[ ! -f "$REPORT" ]]; then
  echo "FAIL: $REPORT not found; run 02_roundtrip.sh first" >&2
  exit 1
fi

fail=0
check_zero() {
  local field="$1" label="$2"
  local n
  n="$(python3 -c "import json,sys; print(len(json.load(open('$REPORT'))['$field']))")"
  if [[ "$n" != "0" ]]; then
    echo "FAIL: $label has $n entries" >&2
    python3 -c "import json; [print('  -', x) for x in json.load(open('$REPORT'))['$field']]" >&2
    fail=1
  else
    echo "OK:   $label is empty"
  fi
}

check_zero missing_hits "missing hits"
check_zero unexpected_hits "unexpected hits"
check_zero status_mismatch "status mismatches"

python3 - "$REPORT" <<'EOF'
import json, sys
r = json.load(open(sys.argv[1]))
assert r["expected_count"] > 0, "zero expected hits would mask a broken match"
assert r["expected_count"] == r["observed_count"], (r["expected_count"], r["observed_count"])
print(f"OK:   expected={r['expected_count']} observed={r['observed_count']} (exact set match)")
EOF

if [[ "$fail" != "0" ]]; then
  echo "ROUND-TRIP VERIFICATION FAILED" >&2
  exit 1
fi
echo "ROUND-TRIP VERIFICATION PASSED"

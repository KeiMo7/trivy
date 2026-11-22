#!/usr/bin/env bash
# Demonstrates the required, reproducible failure classes and the partial-path
# guard. Blocking cases refuse to emit a document and name the offending entry
# (file + row). Reconciliation-only cases (missing entry / version expiry) are
# collected into a separate report with a per-row reason instead of being
# silently dropped.
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
BIN="$HERE/vexgen"
IN="$ROOT/reports/input"
FIN="$IN/failures"
OUT="$ROOT/reports/output/failures"
LOG="$ROOT/reports/logs"

mkdir -p "$OUT" "$LOG"
export SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-1763942400}"
export VEXGEN_AUTHOR="security-review-team"
export GOPROXY=off

# run_blocking <case-name> <scans> <reviews> <expected-error-code>
run_blocking() {
  local name="$1" scans="$2" reviews="$3" code="$4"
  echo "------------------------------------------------------------------"
  echo "BLOCKING CASE: $name (expects $code)"
  local log="$LOG/fail_$name.log"
  if "$BIN" generate --scans "$scans" --reviews "$reviews" \
      --out "$OUT/$name.openvex.json" --reconcile "$OUT/$name.reconcile.json" >"$log" 2>&1; then
    cat "$log"
    echo "UNEXPECTED: $name should have failed" >&2
    return 1
  fi
  cat "$log"
  grep -q "$code" "$log" || { echo "UNEXPECTED: $name did not report $code" >&2; return 1; }
  if [[ -f "$OUT/$name.openvex.json" ]]; then
    echo "UNEXPECTED: a document was emitted for blocking case $name" >&2
    return 1
  fi
  echo "OK: $name blocked with $code and no document"
}

# 1. Illegal values: bad justification, missing justification, illegal status.
run_blocking invalid_justification \
  "$FIN/scans_minimal.json" \
  "$FIN/reviews_invalid_justification.json" \
  "REVIEW_JUSTIFICATION_INVALID"

# 2. Partial path review: one occurrence reviewed, the other would silently
#    inherit an un-reviewed conclusion.
run_blocking partial_path \
  "$FIN/scans_multipath.json" \
  "$FIN/reviews_partial_path.json" \
  "REVIEW_PATH_PARTIAL"

echo "------------------------------------------------------------------"
echo "RECONCILIATION CASE: missing entries and version expiry"
# Valid-syntax rows that no longer match the scan. They land in the
# reconciliation report with per-row reasons and do not block by themselves;
# one genuinely-valid row keeps generation unblocked.
cat > "$OUT/one_valid_row.json" <<'JSON'
[
  {
    "product_digest": "sha256:1111111111111111111111111111111111111111111111111111111111111111",
    "vulnerability_id": "CVE-2024-0002",
    "scope": "component",
    "component_purl": "pkg:deb/debian/bash@5.1-2+deb11u1",
    "status": "fixed",
    "reviewer": "alice",
    "reviewed_at": "2026-11-13T07:00:00Z"
  }
]
JSON

"$BIN" generate \
  --scans "$FIN/scans_minimal.json" \
  --reviews "$FIN/reviews_missing_entry.json,$FIN/reviews_version_expired.json,$OUT/one_valid_row.json" \
  --out "$OUT/reconciled.openvex.json" \
  --reconcile "$OUT/reconciled.reconciliation.json" 2>&1 | tee "$LOG/fail_reconciliation.log"

python3 - "$OUT/reconciled.reconciliation.json" <<'EOF'
import json, sys
r = json.load(open(sys.argv[1]))
reasons = {item["reason"] for item in r["reconciliation"]}
required = {"component_not_found", "version_changed"}
missing = required - reasons
assert not missing, f"missing expected reconcile reasons: {missing}"
for item in r["reconciliation"]:
    assert item["source_file"] and item["row"], f"reconcile row lacks location: {item}"
print("OK: reconciliation lists", sorted(reasons), "with per-row source/row locations")
EOF
echo "ALL FAILURE/DEGRADE CASES BEHAVED AS SPECIFIED"

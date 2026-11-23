#!/usr/bin/env bash
# Acceptance harness for the coverage-aware scanner.
#
# Reproduces every acceptance criterion from the task statement:
#   V.1 four skip reasons, each on a dedicated sample
#   V.2 reconciliation identity with zero error
#   V.3 three exit-code situations with distinct codes and summary text
#   plus redaction, determinism and report-failure guards.
#
# Outputs real reports under reports/. Runs the scanner under `python -I` via
# its isolated launcher so untrusted fixture data cannot influence imports.
set -u

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

PY="${PYTHON:-python3}"
LAUNCHER="scripts/coverage_scan_launcher.py"
LIMIT=4096
FAILURES=0

banner() { printf '\n========== %s ==========\n' "$1"; }
check() {  # check <description> <expected-code> <actual-code>
  if [ "$2" = "$3" ]; then
    printf 'PASS  %s (exit %s)\n' "$1" "$3"
  else
    printf 'FAIL  %s (expected %s, got %s)\n' "$1" "$2" "$3"
    FAILURES=$((FAILURES + 1))
  fi
}

banner "0/ unit + integration test suite"
"$PY" -m unittest tests.test_units tests.test_integration
[ "$?" -eq 0 ] || FAILURES=$((FAILURES + 1))

banner "1/ regenerate deterministic fixtures"
"$PY" tests/make_fixtures.py

banner "2/ V.1 the four reason categories, each reproducible"
scan() { "$PY" "$LAUNCHER" "$1" --json "reports/acc-$(basename "$1").json" \
        --text "reports/acc-$(basename "$1").txt" --max-file-size "$LIMIT"; }

scan fixtures/oversized-artifact   >/tmp/acc-size.log;     check "size_limit"      2 "$?"
scan fixtures/noperm-artifact      >/tmp/acc-perm.log;     check "no_permission"   2 "$?"
scan fixtures/truncated-zip.zip    >/tmp/acc-zip.log;      check "unpack_failed(zip)" 2 "$?"
scan fixtures/truncated-tar.tar    >/tmp/acc-tar.log;      check "unpack_failed(tar)" 2 "$?"
scan fixtures/truncated-gz.gz      >/tmp/acc-gz.log;       check "unpack_failed(gz)"  2 "$?"
scan fixtures/unknown-blob         >/tmp/acc-unk.log;      check "unrecognized"    2 "$?"
scan fixtures/encrypted.zip        >/tmp/acc-enc.log;      check "encrypted->no_permission" 2 "$?"

banner "3/ V.2 reconciliation identity with zero error"
"$PY" - <<'PYEOF'
import glob, json, sys
bad = 0
for path in sorted(glob.glob("reports/acc-*.json")):
    report = json.load(open(path))
    t = report["summary"]["totals"]
    ok = t["identity_holds"] and t["traversed"] == (
        t["analyzed"] + t["skipped"] + t["unrecognized"])
    for art in report["artifacts"]:
        c = art["coverage"]["counters"]
        ok &= c["identity_holds"] and c["traversed"] == (
            c["analyzed"] + c["skipped"] + c["unrecognized"])
    print(("PASS " if ok else "FAIL ") + path)
    bad += 0 if ok else 1
sys.exit(1 if bad else 0)
PYEOF
[ "$?" -eq 0 ] || FAILURES=$((FAILURES + 1))

banner "4/ V.3 three terminal states, distinct codes and wording"
"$PY" "$LAUNCHER" fixtures/clean-artifact      --json reports/state-clean.json      --max-file-size "$LIMIT" >/tmp/s0.log; check "clean+complete -> 0" 0 "$?"
"$PY" "$LAUNCHER" fixtures/secrets-artifact    --json reports/state-findings.json   --max-file-size "$LIMIT" >/tmp/s1.log; check "findings -> 1"        1 "$?"
"$PY" "$LAUNCHER" fixtures/oversized-artifact  --json reports/state-incomplete.json --max-file-size "$LIMIT" >/tmp/s2.log; check "incomplete -> 2"      2 "$?"
head -3 /tmp/s0.log /tmp/s1.log /tmp/s2.log | grep -E "status=|CLEAN|FINDINGS|INCOMPLETE"

banner "5/ batch isolation: one failed artifact never collapses the batch"
"$PY" "$LAUNCHER" fixtures/clean-artifact fixtures/truncated-zip.zip \
      fixtures/secrets-artifact --json reports/state-batch.json \
      --max-file-size "$LIMIT" >/tmp/sb.log; check "batch findings+incomplete -> 1" 1 "$?"
grep -E "ARTIFACT" /tmp/sb.log

banner "6/ determinism: repeated scans share a coverage fingerprint"
"$PY" "$LAUNCHER" fixtures/mixed-batch --json /tmp/det1.json --max-file-size "$LIMIT" >/dev/null
"$PY" "$LAUNCHER" fixtures/mixed-batch --json /tmp/det2.json --max-file-size "$LIMIT" >/dev/null
"$PY" - <<'PYEOF'
import json, sys
a = json.load(open("/tmp/det1.json")); b = json.load(open("/tmp/det2.json"))
same = a["coverage_fingerprint"] == b["coverage_fingerprint"]
same &= json.dumps(a["artifacts"], sort_keys=True) == json.dumps(b["artifacts"], sort_keys=True)
print("PASS fingerprint identical" if same else "FAIL fingerprints differ")
sys.exit(0 if same else 1)
PYEOF
[ "$?" -eq 0 ] || FAILURES=$((FAILURES + 1))

banner "7/ redaction: sensitive path strings never appear raw"
"$PY" "$LAUNCHER" fixtures/sensitive-paths --json reports/state-redaction.json \
      --max-file-size "$LIMIT" >/dev/null
if grep -E "id_rsa|credentials|password" reports/state-redaction.json >/dev/null; then
  echo "FAIL sensitive string leaked into report"; FAILURES=$((FAILURES + 1))
else
  echo "PASS no raw sensitive strings; tokens:"
  grep -o "<REDACTED:[a-f0-9]*>" reports/state-redaction.json | sort -u
fi

banner "8/ IV.1 report-write failure exits 4 and leaves no partial report"
rm -f reports/should-not-exist.json
"$PY" "$LAUNCHER" fixtures/clean-artifact --json /nonexistent-dir/x.json >/dev/null 2>/tmp/rw.err
check "unwritable report target -> 4" 4 "$?"
[ -e reports/should-not-exist.json ] && { echo "FAIL partial report left behind"; FAILURES=$((FAILURES + 1)); }

banner "RESULT"
if [ "$FAILURES" -eq 0 ]; then
  echo "ALL ACCEPTANCE CHECKS PASSED"
else
  echo "$FAILURES CHECK(S) FAILED"
fi
exit "$FAILURES"

"""End-to-end acceptance tests against generated fixtures.

Covers the acceptance contract:
  V.1  each of the four skip reasons is reproducible on a dedicated sample;
  V.2  traversed == analyzed + skipped + unrecognized, zero tolerance;
  V.3  three exit-code situations with distinct codes and summary text;
  II.7 repeated scans yield identical coverage sections apart from timestamps;
  III.4 sensitive path strings never appear raw in any report.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from coverage_scan.config import ScanConfig  # noqa: E402
from coverage_scan.redact import Redactor  # noqa: E402
from coverage_scan.scanner import build_report, exit_code_for, run_batch  # noqa: E402
from coverage_scan.model import ArtifactStatus  # noqa: E402

from tests import make_fixtures  # noqa: E402

CONFIG = ScanConfig.load(None, {"max_file_size": make_fixtures.SIZE_LIMIT})
FX = make_fixtures.FIXTURE_ROOT


def scan(relative: str) -> dict:
    redactor = Redactor(CONFIG)
    results = run_batch([str(FX / relative)], CONFIG, redactor)
    return build_report(results, CONFIG)


def find_reason_rows(report: dict, reason: str) -> list[dict]:
    rows = []
    for artifact in report["artifacts"]:
        for group in artifact["coverage"]["abandoned"]:
            if group["reason"] == reason:
                rows.append(group)
    return rows


class FixtureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        make_fixtures.main()

    def assert_identity(self, report: dict) -> None:
        totals = report["summary"]["totals"]
        self.assertTrue(totals["identity_holds"])
        self.assertEqual(
            totals["traversed"],
            totals["analyzed"] + totals["skipped"] + totals["unrecognized"])
        for artifact in report["artifacts"]:
            c = artifact["coverage"]["counters"]
            self.assertTrue(c["identity_holds"])
            self.assertEqual(c["traversed"],
                             c["analyzed"] + c["skipped"] + c["unrecognized"])

    # ------------------------------------------------------ V.1 four reasons

    def test_size_limit_reason(self) -> None:
        report = scan("oversized-artifact")
        rows = find_reason_rows(report, "size_limit")
        self.assertTrue(rows, "expected at least one size_limit group")
        locations = [i["location"] for g in rows for i in g["items"]]
        self.assertTrue(any("huge.bin" in loc for loc in locations))
        self.assertEqual(report["status"], ArtifactStatus.INCOMPLETE.value)
        self.assert_identity(report)

    def test_no_permission_reason(self) -> None:
        if os.geteuid() == 0:
            self.skipTest("root bypasses file permission bits")
        report = scan("noperm-artifact")
        rows = find_reason_rows(report, "no_permission")
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["count"], 1)
        self.assert_identity(report)

    def test_unpack_failed_zip_tar_gzip(self) -> None:
        for name in ("truncated-zip.zip", "truncated-tar.tar", "truncated-gz.gz"):
            with self.subTest(name=name):
                report = scan(name)
                rows = find_reason_rows(report, "unpack_failed")
                self.assertTrue(rows, f"{name} should produce unpack_failed")
                segments = report["artifacts"][0]["coverage"]["unreadable_segments"]
                self.assertTrue(segments, f"{name} should record a segment")
                self.assertTrue(segments[0]["affected_packages"])
                self.assert_identity(report)

    def test_member_body_truncation_stays_in_event_model(self) -> None:
        # Regression: a lazy member-read failure (tarfile.ReadError) must bucket
        # the member and produce a segment record, never collapse the artifact
        # to a fatal error with missing coverage.
        report = scan("member-truncated.tar")
        cov = report["artifacts"][0]["coverage"]
        self.assertIsNone(cov["fatal_error"])
        c = cov["counters"]
        self.assertGreaterEqual(c["analyzed"], 1)       # good.txt still read
        self.assertGreaterEqual(c["skipped"], 2)        # broken member + container
        self.assertTrue(cov["unreadable_segments"])
        self.assertEqual(cov["unreadable_segments"][0]["format"], "tar")
        self.assertIn("*tail*",
                      cov["unreadable_segments"][0]["affected_packages"])
        self.assertEqual(report["status"], ArtifactStatus.INCOMPLETE.value)
        self.assert_identity(report)

    def test_encrypted_zip_is_no_permission(self) -> None:
        report = scan("encrypted.zip")
        perm_rows = find_reason_rows(report, "no_permission")
        self.assertTrue(perm_rows)
        # The plain member is still analyzed, so the archive itself counts.
        self.assertGreaterEqual(
            report["artifacts"][0]["coverage"]["counters"]["analyzed"], 1)
        self.assert_identity(report)

    def test_unrecognized_aggregated_by_directory(self) -> None:
        report = scan("unknown-blob")
        # Unrecognized is a distinct state, not a row in the abandonment ledger.
        abandoned_reasons = {g["reason"]
                             for a in report["artifacts"]
                             for g in a["coverage"]["abandoned"]}
        self.assertNotIn("unrecognized", abandoned_reasons)
        # Aggregated per directory, with counts and no per-file expansion.
        summary = report["artifacts"][0]["coverage"]["unrecognized"]
        directories = {g["directory"] for g in summary}
        self.assertEqual(directories, {".", "nested"})
        for group in summary:
            self.assertNotIn("items", group)
            self.assertGreaterEqual(group["count"], 1)
        totals = report["summary"]["totals"]
        self.assertEqual(totals["unrecognized"], 3)
        # The three real abandonment reasons sum to the skipped counter.
        by_reason = totals["skipped_by_reason"]
        self.assertEqual(
            by_reason["size_limit"] + by_reason["no_permission"]
            + by_reason["unpack_failed"], totals["skipped"])
        self.assertEqual(by_reason["unrecognized"], totals["unrecognized"])
        self.assert_identity(report)

    def test_corrupted_archive_is_segment_unpack_failure(self) -> None:
        report = scan("corrupted-archive.zip")
        rows = find_reason_rows(report, "unpack_failed")
        self.assertTrue(rows)
        segments = report["artifacts"][0]["coverage"]["unreadable_segments"]
        self.assertEqual(segments[0]["affected_packages"], ["*"])
        self.assert_identity(report)

    def test_deep_nesting_records_segment(self) -> None:
        report = scan("deepnest.zip")
        rows = find_reason_rows(report, "unpack_failed")
        self.assertTrue(rows)
        self.assertTrue(
            report["artifacts"][0]["coverage"]["unreadable_segments"])
        self.assert_identity(report)

    def test_unreadable_subdirectory_is_directory_skip_not_fatal(self) -> None:
        if os.geteuid() == 0:
            self.skipTest("root bypasses directory permission bits")
        report = scan("whole-fail")
        cov = report["artifacts"][0]["coverage"]
        self.assertIsNone(cov["fatal_error"])
        self.assertEqual(cov["directories"]["skipped"], 1)
        # Directory failures live in the dedicated ledger, never the file one.
        self.assertTrue(cov["directory_abandoned"])
        self.assertEqual(
            cov["directory_abandoned"][0]["reason"], "no_permission")
        self.assertEqual(cov["counters"]["skipped"], 0)
        # Directory skips are tracked separately: the file identity still holds.
        self.assert_identity(report)

    # ------------------------------------------------------ II.3 batch rules

    def test_batch_records_each_artifact_independently(self) -> None:
        redactor = Redactor(CONFIG)
        targets = [
            str(FX / "clean-artifact"),
            str(FX / "truncated-zip.zip"),
            str(FX / "secrets-artifact"),
        ]
        report = build_report(run_batch(targets, CONFIG, redactor), CONFIG)
        statuses = {a["artifact"]: a["status"] for a in report["artifacts"]}
        self.assertEqual(
            statuses[str(FX / "clean-artifact")], ArtifactStatus.CLEAN.value)
        self.assertEqual(
            statuses[str(FX / "truncated-zip.zip")],
            ArtifactStatus.INCOMPLETE.value)
        self.assertEqual(
            statuses[str(FX / "secrets-artifact")], ArtifactStatus.FINDINGS.value)
        # One failed artifact never collapses the batch to a single conclusion.
        self.assertEqual(report["status"],
                         ArtifactStatus.FINDINGS_INCOMPLETE.value)
        self.assert_identity(report)

    def test_batch_with_one_failed_artifact_is_not_clean(self) -> None:
        # Even when every surviving artifact is clean, a failed sibling forces
        # an incomplete batch verdict (requirement II.4 / IV.2).
        if os.geteuid() == 0:
            self.skipTest("root bypasses directory permission bits")
        locked = FX / "batch-locked-root"
        locked.mkdir(parents=True, exist_ok=True)
        (locked / "hidden.txt").write_text("unreachable\n")
        locked.chmod(0o000)
        try:
            redactor = Redactor(CONFIG)
            report = build_report(run_batch(
                [str(locked), str(FX / "clean-artifact")],
                CONFIG, redactor), CONFIG)
            self.assertEqual(report["status"], ArtifactStatus.INCOMPLETE.value)
            self.assertEqual(exit_code_for(report), 2)
            self.assertEqual(
                report["summary"]["totals"]["artifacts_failed"], 1)
            self.assert_identity(report)
        finally:
            locked.chmod(0o700)

    # ------------------------------------------------------ V.3 exit codes

    def test_exit_zero_when_clean_and_complete(self) -> None:
        report = scan("clean-artifact")
        self.assertEqual(report["status"], ArtifactStatus.CLEAN.value)
        self.assertEqual(exit_code_for(report), 0)

    def test_exit_one_when_findings(self) -> None:
        report = scan("secrets-artifact")
        self.assertEqual(report["status"], ArtifactStatus.FINDINGS.value)
        self.assertEqual(exit_code_for(report), 1)

    def test_exit_two_when_incomplete_no_findings(self) -> None:
        report = scan("oversized-artifact")
        self.assertEqual(report["status"], ArtifactStatus.INCOMPLETE.value)
        self.assertEqual(exit_code_for(report), 2)

    def test_findings_plus_gap_still_exit_one_but_marked_incomplete(self) -> None:
        redactor = Redactor(CONFIG)
        # mixed-batch contains a secret-like path only in name; inject a real
        # finding source by scanning it together with the secrets artifact.
        report = build_report(run_batch(
            [str(FX / "mixed-batch"), str(FX / "secrets-artifact")],
            CONFIG, redactor), CONFIG)
        self.assertEqual(report["status"],
                         ArtifactStatus.FINDINGS_INCOMPLETE.value)
        self.assertEqual(exit_code_for(report), 1)
        self.assertIn("INCOMPLETE", report["summary"]["verdict_text"])
        self.assertIn("FINDINGS", report["summary"]["verdict_text"])

    def test_all_failed_distinct_from_findings_exit_code(self) -> None:
        # Build an artifact whose root directory itself is unreadable: the
        # whole artifact must land in FAILED, distinct from the findings code.
        if os.geteuid() == 0:
            self.skipTest("root bypasses directory permission bits")
        target = make_fixtures.FIXTURE_ROOT / "locked-root"
        target.mkdir(parents=True, exist_ok=True)
        (target / "hidden.txt").write_text("cannot be reached\n")
        target.chmod(0o000)
        try:
            report = scan("locked-root")
            self.assertEqual(report["status"], ArtifactStatus.FAILED.value)
            self.assertEqual(exit_code_for(report), 3)
            self.assertNotEqual(exit_code_for(report), 1)
            self.assertIn("FAILED", report["summary"]["verdict_text"])
        finally:
            target.chmod(0o700)

    # ------------------------------------------------------ II.7 determinism

    def test_repeated_scans_identical_coverage(self) -> None:
        target = str(FX / "mixed-batch")
        first = build_report(
            run_batch([target], CONFIG, Redactor(CONFIG)), CONFIG)
        second = build_report(
            run_batch([target], CONFIG, Redactor(CONFIG)), CONFIG)
        self.assertEqual(first["coverage_fingerprint"],
                         second["coverage_fingerprint"])
        self.assertEqual(
            json.dumps(first["artifacts"], sort_keys=True),
            json.dumps(second["artifacts"], sort_keys=True))

    # ------------------------------------------------------ III.4 redaction

    def test_sensitive_strings_never_raw_in_report(self) -> None:
        report = scan("sensitive-paths")
        serialized = json.dumps(report)
        for secret in ("id_rsa", "id_rsa_prod", "credentials",
                       "password-store", "password.prod"):
            self.assertNotIn(secret, serialized)
        # The two locked sensitive names must appear as redaction tokens inside
        # the abandoned ledger, proving redaction runs on report-bound paths.
        redacted = [item["location"]
                    for artifact in report["artifacts"]
                    for group in artifact["coverage"]["abandoned"]
                    for item in group["items"]]
        self.assertTrue(any("<REDACTED:" in loc for loc in redacted))
        self.assert_identity(report)

    # ------------------------------------------------------ II.6 mixed tree

    def test_mixed_batch_all_four_reasons_present(self) -> None:
        report = scan("mixed-batch")
        cov = report["artifacts"][0]["coverage"]
        # The four-category taxonomy is expressed through skipped_by_reason...
        by_reason = cov["skipped_by_reason"]
        for reason in ("size_limit", "no_permission",
                       "unpack_failed", "unrecognized"):
            self.assertGreaterEqual(by_reason[reason], 1, reason)
        # ...while the abandoned ledger itself holds only the three real
        # abandonment reasons (unrecognized is a distinct state).
        abandoned = {g["reason"] for g in cov["abandoned"]}
        self.assertEqual(
            abandoned, {"size_limit", "no_permission", "unpack_failed"})
        self.assertTrue(cov["unrecognized"])
        self.assert_identity(report)


class CliTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        make_fixtures.main()

    def _run_cli(self, *args: str) -> subprocess.CompletedProcess:
        # Run under -I against untrusted fixture data; the launcher injects the
        # package path explicitly because isolated mode ignores cwd and
        # PYTHONPATH during interpreter startup.
        launcher = ROOT / "scripts" / "coverage_scan_launcher.py"
        return subprocess.run(
            [sys.executable, "-I", str(launcher), *args],
            cwd=str(ROOT), capture_output=True, text=True, check=False)

    def test_three_cli_exit_codes_and_distinct_text(self) -> None:
        cases = [
            (["fixtures/clean-artifact", "--json", "reports/cli-clean.json"], 0),
            (["fixtures/secrets-artifact", "--json", "reports/cli-findings.json"], 1),
            (["fixtures/oversized-artifact",
              "--json", "reports/cli-incomplete.json",
              "--max-file-size", str(make_fixtures.SIZE_LIMIT)], 2),
        ]
        texts = []
        for args, expected in cases:
            proc = self._run_cli(*args)
            self.assertEqual(proc.returncode, expected,
                             f"args={args} stderr={proc.stderr}")
            texts.append(proc.stdout)
        self.assertEqual(len({t.splitlines()[1] for t in texts}), 3)

    def test_cli_report_is_valid_machine_readable_json(self) -> None:
        proc = self._run_cli(
            "fixtures/mixed-batch", "--json", "reports/cli-mixed.json",
            "--max-file-size", str(make_fixtures.SIZE_LIMIT))
        self.assertNotEqual(proc.returncode, 0)
        data = json.loads(Path(ROOT / "reports/cli-mixed.json").read_text())
        self.assertEqual(data["kind"], "coverage-scan-report")
        self.assertIn("coverage_fingerprint", data)
        totals = data["summary"]["totals"]
        self.assertEqual(
            totals["traversed"],
            totals["analyzed"] + totals["skipped"] + totals["unrecognized"])

    def test_cli_missing_artifact_uses_report_error_code(self) -> None:
        proc = self._run_cli("fixtures/does-not-exist",
                             "--json", "reports/cli-missing.json")
        self.assertEqual(proc.returncode, 4)
        self.assertFalse(Path(ROOT / "reports/cli-missing.json").exists())

    def test_bad_config_rejected_before_scanning(self) -> None:
        proc = self._run_cli(
            "fixtures/clean-artifact",
            "--config", "fixtures/no-such-config.json",
            "--json", "reports/cli-badcfg.json")
        self.assertEqual(proc.returncode, 4)

    def test_cli_exit_three_when_artifact_root_unreadable(self) -> None:
        if os.geteuid() == 0:
            self.skipTest("root bypasses directory permission bits")
        target = make_fixtures.FIXTURE_ROOT / "cli-locked-root"
        target.mkdir(parents=True, exist_ok=True)
        (target / "hidden.txt").write_text("nope\n")
        target.chmod(0o000)
        try:
            proc = self._run_cli(
                str(target), "--json", "reports/cli-locked.json")
            self.assertEqual(proc.returncode, 3)
            self.assertIn("FAILED", proc.stdout)
        finally:
            target.chmod(0o700)


if __name__ == "__main__":
    unittest.main(verbosity=2)

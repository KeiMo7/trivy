"""Batch orchestration, verdict rules and report assembly."""

from __future__ import annotations

import dataclasses
import hashlib
import json
import os
import tempfile
from typing import Any

from .collector import ReconciliationError
from .config import ScanConfig
from .model import ArtifactStatus, ExitCode
from .redact import Redactor
from .walker import scan_artifact

SCHEMA_VERSION = "1.0"
REPORT_KIND = "coverage-scan-report"


class ReportWriteError(RuntimeError):
    """Raised when the coverage section cannot be serialized/written.

    Per failure rule IV.1 this is fatal: no partially-complete report is left
    behind and the process exits with the dedicated report-error code.
    """


@dataclasses.dataclass
class ArtifactResult:
    path: str
    status: ArtifactStatus
    coverage: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {
            "artifact": self.path,
            "status": self.status.value,
            "coverage": self.coverage,
        }


def _verdict(coverage: dict[str, Any]) -> ArtifactStatus:
    if coverage["fatal_error"] is not None:
        return ArtifactStatus.FAILED
    counters = coverage["counters"]
    has_gap = (
        counters["skipped"] > 0
        or counters["unrecognized"] > 0
        or counters["directories_skipped"] > 0
        or bool(coverage["unreadable_segments"])
    )
    has_findings = bool(coverage["findings"])
    if has_findings and has_gap:
        return ArtifactStatus.FINDINGS_INCOMPLETE
    if has_findings:
        return ArtifactStatus.FINDINGS
    if has_gap:
        return ArtifactStatus.INCOMPLETE
    return ArtifactStatus.CLEAN


def run_batch(artifact_paths: list[str], config: ScanConfig,
              redactor: Redactor) -> list[ArtifactResult]:
    results: list[ArtifactResult] = []
    for path in artifact_paths:
        collector = scan_artifact(path, config, redactor)
        # finalize() raises if the per-artifact identity is violated, which
        # aborts report production rather than emitting a dishonest report.
        coverage = collector.finalize()
        results.append(ArtifactResult(
            path=path,
            status=_verdict(coverage),
            coverage=coverage,
        ))
    return results


def _batch_totals(results: list[ArtifactResult]) -> dict[str, Any]:
    totals = {
        "artifacts": len(results),
        "artifacts_failed": 0,
        "traversed": 0,
        "analyzed": 0,
        "skipped": 0,
        "unrecognized": 0,
        "directories_traversed": 0,
        "directories_skipped": 0,
        "findings": 0,
        "unreadable_segments": 0,
        "skipped_by_reason": {
            "size_limit": 0, "no_permission": 0,
            "unpack_failed": 0, "unrecognized": 0,
        },
    }
    for result in results:
        if result.status == ArtifactStatus.FAILED:
            totals["artifacts_failed"] += 1
        c = result.coverage["counters"]
        for key in ("traversed", "analyzed", "skipped", "unrecognized",
                    "directories_traversed", "directories_skipped"):
            totals[key] += c[key]
        totals["findings"] += len(result.coverage["findings"])
        totals["unreadable_segments"] += len(
            result.coverage["unreadable_segments"])
        for reason, count in result.coverage["skipped_by_reason"].items():
            totals["skipped_by_reason"][reason] += count
    totals["identity_holds"] = (
        totals["traversed"]
        == totals["analyzed"] + totals["skipped"] + totals["unrecognized"]
    )
    return totals


def _batch_status(results: list[ArtifactResult], totals: dict[str, Any]) -> ArtifactStatus:
    if not results:
        return ArtifactStatus.FAILED
    non_failed = [r for r in results if r.status != ArtifactStatus.FAILED]
    if not non_failed:
        return ArtifactStatus.FAILED
    has_failed_artifact = any(
        r.status == ArtifactStatus.FAILED for r in results)
    has_findings = any(r.status in (ArtifactStatus.FINDINGS,
                                    ArtifactStatus.FINDINGS_INCOMPLETE)
                       for r in non_failed)
    has_gap = any(r.status in (ArtifactStatus.INCOMPLETE,
                               ArtifactStatus.FINDINGS_INCOMPLETE)
                  for r in non_failed)
    # A failed sibling artifact is itself a coverage gap for the batch: the
    # batch cannot claim to have seen everything, even if every surviving
    # artifact is clean.
    if has_findings and (has_gap or has_failed_artifact):
        return ArtifactStatus.FINDINGS_INCOMPLETE
    if has_findings:
        return ArtifactStatus.FINDINGS
    if has_gap or has_failed_artifact:
        return ArtifactStatus.INCOMPLETE
    return ArtifactStatus.CLEAN


def _coverage_fingerprint(results: list[ArtifactResult]) -> str:
    """Deterministic hash of everything in the coverage sections.

    Timestamps and report paths are excluded from the hash so two scans of the
    same artifact produce the same fingerprint (requirement II.7).
    """
    payload = json.dumps(
        [r.to_dict() for r in sorted(results, key=lambda r: r.path)],
        sort_keys=True, separators=(",", ":"), ensure_ascii=False,
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def build_report(results: list[ArtifactResult], config: ScanConfig) -> dict[str, Any]:
    totals = _batch_totals(results)
    if not totals["identity_holds"]:
        raise ReconciliationError(
            "batch coverage identity violated: "
            f"traversed={totals['traversed']} analyzed={totals['analyzed']} "
            f"skipped={totals['skipped']} unrecognized={totals['unrecognized']}")
    status = _batch_status(results, totals)
    report = {
        "schema_version": SCHEMA_VERSION,
        "kind": REPORT_KIND,
        "status": status.value,
        "summary": {
            "totals": totals,
            "verdict_text": _verdict_text(status, totals),
        },
        "artifacts": [r.to_dict() for r in sorted(results, key=lambda r: r.path)],
        "config_effective": {
            "max_file_size": config.max_file_size,
            "max_archive_depth": config.max_archive_depth,
            "max_archive_members": config.max_archive_members,
            "max_unpacked_bytes": config.max_unpacked_bytes,
            "follow_symlinks": config.follow_symlinks,
            "secret_scan": config.secret_scan,
        },
        "coverage_fingerprint": _coverage_fingerprint(results),
    }
    # Prove to ourselves the coverage section is serializable before returning.
    try:
        json.dumps(report, sort_keys=True, ensure_ascii=False)
    except (TypeError, ValueError) as exc:
        raise ReconciliationError(f"coverage section not serializable: {exc}") from exc
    return report


def _verdict_text(status: ArtifactStatus, totals: dict[str, Any]) -> str:
    if status == ArtifactStatus.CLEAN:
        return ("CLEAN: no findings and full coverage "
                f"({totals['analyzed']} analyzed, 0 abandoned, 0 unrecognized)")
    if status == ArtifactStatus.FINDINGS:
        return (f"FINDINGS: {totals['findings']} finding(s) with full coverage")
    if status == ArtifactStatus.FINDINGS_INCOMPLETE:
        return (f"FINDINGS + INCOMPLETE: {totals['findings']} finding(s), "
                f"{totals['skipped']} abandoned, {totals['unrecognized']} unrecognized "
                "-- coverage is not complete")
    if status == ArtifactStatus.INCOMPLETE:
        failed_note = (f", {totals['artifacts_failed']} artifact(s) failed"
                       if totals["artifacts_failed"] else "")
        return (f"INCOMPLETE: no findings but {totals['skipped']} abandoned and "
                f"{totals['unrecognized']} unrecognized node(s) were never analyzed"
                f"{failed_note}")
    return ("FAILED: every artifact failed before scanning; no coverage "
            "conclusion is available")


def write_report(report: dict[str, Any], output_path: str) -> None:
    """Atomically write the JSON report.

    Serialization happens to a temp file in the same directory first; only a
    successful full render is renamed into place, so a coverage-write failure
    can never leave a report that merely looks complete.
    """
    directory = os.path.dirname(os.path.abspath(output_path)) or "."
    try:
        os.makedirs(directory, exist_ok=True)
        fd, tmp = tempfile.mkstemp(prefix=".report-", suffix=".tmp", dir=directory)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(report, fh, indent=2, sort_keys=True,
                          ensure_ascii=False)
                fh.write("\n")
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(tmp, output_path)
        except BaseException:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise
    except OSError as exc:
        raise ReportWriteError(f"could not write report to {output_path}: {exc}") from exc


def exit_code_for(report: dict[str, Any]) -> int:
    status = ArtifactStatus(report["status"])
    totals = report["summary"]["totals"]
    if status == ArtifactStatus.FAILED:
        return ExitCode.ALL_FAILED
    if status in (ArtifactStatus.FINDINGS, ArtifactStatus.FINDINGS_INCOMPLETE):
        # Findings dominate; incompleteness is still carried in status + text.
        return ExitCode.FINDINGS
    if status == ArtifactStatus.INCOMPLETE:
        return ExitCode.INCOMPLETE
    if not totals["identity_holds"]:  # pragma: no cover - blocked at build time
        return ExitCode.REPORT_ERROR
    return ExitCode.CLEAN

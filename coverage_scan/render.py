"""Human-readable rendering of a coverage report (stdout companion to JSON)."""

from __future__ import annotations

from typing import Any

from .model import ArtifactStatus, SkipReason

_REASON_ORDER = (
    SkipReason.SIZE_LIMIT.value,
    SkipReason.NO_PERMISSION.value,
    SkipReason.UNPACK_FAILED.value,
    SkipReason.UNRECOGNIZED.value,
)


def render_text(report: dict[str, Any]) -> str:
    lines: list[str] = []
    lines.append("=" * 72)
    lines.append(f"COVERAGE SCAN REPORT  schema={report['schema_version']} "
                 f"status={report['status'].upper()}")
    lines.append("=" * 72)
    lines.append(report["summary"]["verdict_text"])
    totals = report["summary"]["totals"]
    lines.append("")
    lines.append("BATCH COVERAGE (reconciliation: traversed = analyzed + "
                 "abandoned + unrecognized)")
    lines.append(
        f"  artifacts={totals['artifacts']} (failed={totals['artifacts_failed']})  "
        f"traversed={totals['traversed']}  analyzed={totals['analyzed']}  "
        f"abandoned={totals['skipped']}  unrecognized={totals['unrecognized']}  "
        f"identity_holds={totals['identity_holds']}"
    )
    lines.append("  abandoned by reason: " + ", ".join(
        f"{reason}={totals['skipped_by_reason'][reason]}"
        for reason in _REASON_ORDER))
    lines.append(f"  unreadable segments={totals['unreadable_segments']}  "
                 f"findings={totals['findings']}  "
                 f"directories skipped={totals['directories_skipped']}")

    for artifact in report["artifacts"]:
        lines.append("")
        lines.append("-" * 72)
        lines.append(f"ARTIFACT {artifact['artifact']}  "
                     f"status={_status_label(artifact['status'])}")
        cov = artifact["coverage"]
        c = cov["counters"]
        lines.append(
            f"  traversed={c['traversed']} analyzed={c['analyzed']} "
            f"abandoned={c['skipped']} unrecognized={c['unrecognized']} "
            f"identity_holds={c['identity_holds']}"
        )
        if cov["fatal_error"]:
            lines.append(f"  FATAL: {cov['fatal_error']}")
        if cov["findings"]:
            lines.append("  findings:")
            for finding in cov["findings"]:
                lines.append(f"    - [{finding['rule_id']}] {finding['location']}"
                             f":{finding['line_hint'] or '?'}")
        if cov["unreadable_segments"]:
            lines.append("  unreadable segments:")
            for seg in cov["unreadable_segments"]:
                packages = ", ".join(seg["affected_packages"])
                lines.append(
                    f"    - {seg['segment_id']} {seg['location']} "
                    f"({seg['format']}): {seg['detail']} "
                    f"affected_packages=[{packages}]")
        if cov["abandoned"]:
            lines.append("  abandoned (aggregated by reason + directory):")
            for group in cov["abandoned"]:
                lines.append(
                    f"    * {group['reason']} @ {group['directory']} "
                    f"count={group['count']} size={group['total_size_bytes']}B")
                for item in group["items"]:
                    lines.append(
                        f"        - {item['location']} [{item['kind']}] "
                        f"{item['size_bytes'] if item['size_bytes'] is not None else '?'}B "
                        f"detail={item['detail']}")
        if cov["directory_abandoned"]:
            lines.append("  abandoned directories (separate from file identity):")
            for group in cov["directory_abandoned"]:
                lines.append(
                    f"    * {group['reason']} @ {group['directory']} "
                    f"count={group['count']}")
                for item in group["items"]:
                    lines.append(
                        f"        - {item['location']} [directory] "
                        f"detail={item['detail']}")
        if cov["unrecognized"]:
            lines.append("  unrecognized content (counts per directory, no per-file dump):")
            for agg in cov["unrecognized"]:
                lines.append(
                    f"    * {agg['directory']} count={agg['count']} "
                    f"size={agg['total_size_bytes']}B "
                    f"extensions={','.join(agg['sample_extensions']) or 'none'}")
    lines.append("")
    lines.append(f"coverage_fingerprint={report['coverage_fingerprint']}")
    return "\n".join(lines)


def _status_label(status: str) -> str:
    labels = {
        ArtifactStatus.CLEAN.value: "CLEAN (fully covered, no findings)",
        ArtifactStatus.FINDINGS.value: "FINDINGS (fully covered)",
        ArtifactStatus.INCOMPLETE.value: "INCOMPLETE (coverage gap, no findings)",
        ArtifactStatus.FINDINGS_INCOMPLETE.value:
            "FINDINGS + INCOMPLETE (findings and coverage gap)",
        ArtifactStatus.FAILED.value: "FAILED (artifact could not be scanned)",
    }
    return labels.get(status, status)

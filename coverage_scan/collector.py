"""Coverage collection and aggregation.

The collector is the only place counters move. Every traversed node lands in
exactly one bucket (analyzed / skipped / unrecognized), and every skip carries
a distinct reason category. At finalization the collector enforces the
reconciliation identity before a report is allowed to exist:

    traversed == analyzed + skipped + unrecognized
"""

from __future__ import annotations

import dataclasses
import posixpath
from collections import defaultdict
from typing import Optional

from .model import (
    CoverageCounters,
    Finding,
    NodeKind,
    SegmentRecord,
    SkipReason,
    SkipRecord,
)
from .redact import Redactor


class ReconciliationError(RuntimeError):
    """Raised when the coverage identity does not hold -- no report may be emitted."""


@dataclasses.dataclass
class _UnrecognizedAgg:
    count: int = 0
    total_size: int = 0
    sample_extensions: set[str] = dataclasses.field(default_factory=set)


class CoverageCollector:
    def __init__(self, artifact_id: str, redactor: Redactor) -> None:
        self.artifact_id = artifact_id
        self._redactor = redactor
        self.counters = CoverageCounters()
        self._skips: list[SkipRecord] = []          # file/member/segment nodes
        self._dir_skips: list[SkipRecord] = []      # directory nodes (separate identity)
        self._segments: dict[str, SegmentRecord] = {}
        self.findings: list[Finding] = []
        self.fatal_error: Optional[str] = None
        # Unrecognized content is aggregated per redacted directory, never
        # expanded per file (requirement II.5).
        self._unrecognized: dict[str, _UnrecognizedAgg] = defaultdict(_UnrecognizedAgg)

    # ------------------------------------------------------------- node events

    def mark_analyzed(self) -> None:
        self.counters.traversed += 1
        self.counters.analyzed += 1

    def mark_directory(self, accessible: bool, raw_path: str,
                       detail: str = "", container: Optional[str] = None,
                       reason: SkipReason = SkipReason.NO_PERMISSION) -> None:
        self.counters.directories_traversed += 1
        if accessible:
            return
        self.counters.directories_skipped += 1
        # Directory failures live entirely in the directory counters, so they
        # never perturb the file-level reconciliation identity. They are kept
        # in a dedicated ledger and rendered under a separate section.
        self._dir_skips.append(SkipRecord(
            reason=reason,
            location=self._redactor.redact_path(raw_path),
            location_hash=Redactor.stable_hash(raw_path),
            kind=NodeKind.DIRECTORY,
            size_bytes=None,
            detail=detail,
            container=container,
            segment_id=None,
        ))

    def mark_skipped(self, reason: SkipReason, raw_path: str, kind: NodeKind,
                     size_bytes: Optional[int], detail: str,
                     container: Optional[str] = None,
                     segment_id: Optional[str] = None) -> None:
        self.counters.traversed += 1
        self.counters.skipped += 1
        self._record_skip(reason, raw_path, kind, size_bytes, detail,
                          container, segment_id)

    def mark_unrecognized(self, raw_path: str, size_bytes: int,
                          container: Optional[str] = None) -> None:
        # Unrecognized is a distinct terminal state, NOT a skip: it has its own
        # counter bucket and its own aggregation channel. Keeping it out of the
        # skip ledger means counters.skipped counts only the three real
        # abandonment reasons and the reconciliation identity stays exact.
        self.counters.traversed += 1
        self.counters.unrecognized += 1
        directory = self._redactor.redact_dirname(raw_path)
        agg = self._unrecognized[directory]
        agg.count += 1
        agg.total_size += size_bytes
        suffix = posixpath.splitext(raw_path.replace("\\", "/"))[1].lower()
        if suffix:
            agg.sample_extensions.add(suffix)

    def _record_skip(self, reason: SkipReason, raw_path: str, kind: NodeKind,
                     size_bytes: Optional[int], detail: str,
                     container: Optional[str] = None,
                     segment_id: Optional[str] = None) -> None:
        self._skips.append(SkipRecord(
            reason=reason,
            location=self._redactor.redact_path(raw_path),
            location_hash=Redactor.stable_hash(raw_path),
            kind=kind,
            size_bytes=size_bytes,
            detail=detail,
            container=container,
            segment_id=segment_id,
        ))

    def add_finding(self, rule_id: str, raw_path: str, line_hint: Optional[int]) -> None:
        self.findings.append(Finding(
            rule_id=rule_id,
            location=self._redactor.redact_path(raw_path),
            location_hash=Redactor.stable_hash(raw_path),
            line_hint=line_hint,
        ))

    def add_segment(self, segment: SegmentRecord) -> None:
        # Same segment may be reported once; keep the first, merge package sets.
        existing = self._segments.get(segment.segment_id)
        if existing is None:
            self._segments[segment.segment_id] = segment
            return
        merged = tuple(sorted(set(existing.affected_packages) |
                              set(segment.affected_packages)))
        self._segments[segment.segment_id] = dataclasses.replace(
            existing, affected_packages=merged)

    def mark_fatal(self, message: str) -> None:
        self.fatal_error = message

    # ------------------------------------------------------------- rendering

    def skipped_by_reason(self) -> dict[str, int]:
        """Counts for the three abandonment reasons plus the unrecognized state.

        The first three keys sum to ``counters.skipped``; ``unrecognized``
        mirrors ``counters.unrecognized`` and is reported separately so the
        four-category taxonomy stays queryable in one place.
        """
        out = {r.value: 0 for r in SkipReason}
        for record in self._skips:
            out[record.reason.value] += 1
        out[SkipReason.UNRECOGNIZED.value] = self.counters.unrecognized
        return out

    def aggregated_skips(self) -> list[dict]:
        """Abandonment ledger grouped by (reason, redacted directory).

        Only the three real abandonment reasons appear here; unrecognized
        content is rendered separately via :meth:`unrecognized_summary` and is
        aggregated as counts only, never expanded per file.
        """
        grouped: dict[tuple[str, str], list[SkipRecord]] = defaultdict(list)
        for record in self._skips:
            directory = posixpath.dirname(record.location) or "."
            grouped[(record.reason.value, directory)].append(record)

        rows: list[dict] = []
        for (reason, directory), records in sorted(grouped.items()):
            rows.append({
                "reason": reason,
                "directory": directory,
                "count": len(records),
                "total_size_bytes": sum(r.size_bytes or 0 for r in records),
                "items": [r.to_dict() for r in sorted(
                    records, key=lambda r: (r.location, r.location_hash))],
            })
        return rows

    def unrecognized_summary(self) -> list[dict]:
        return [
            {
                "directory": directory,
                "count": agg.count,
                "total_size_bytes": agg.total_size,
                "sample_extensions": sorted(agg.sample_extensions),
            }
            for directory, agg in sorted(self._unrecognized.items())
        ]

    def directory_skips(self) -> list[dict]:
        """Directory-level abandonments, reason-classified and grouped."""
        grouped: dict[tuple[str, str], list[SkipRecord]] = defaultdict(list)
        for record in self._dir_skips:
            directory = posixpath.dirname(record.location) or "."
            grouped[(record.reason.value, directory)].append(record)
        return [
            {
                "reason": reason,
                "directory": directory,
                "count": len(records),
                "items": [r.to_dict() for r in sorted(
                    records, key=lambda r: (r.location, r.location_hash))],
            }
            for (reason, directory), records in sorted(grouped.items())
        ]

    def segments(self) -> list[dict]:
        return [s.to_dict() for s in sorted(self._segments.values(),
                                            key=lambda s: s.segment_id)]

    def finalize(self) -> dict:
        """Build the per-artifact coverage block and enforce reconciliation."""
        if not self.counters.reconcile():
            raise ReconciliationError(
                f"coverage identity violated for {self.artifact_id}: "
                f"traversed={self.counters.traversed} "
                f"analyzed={self.counters.analyzed} "
                f"skipped={self.counters.skipped} "
                f"unrecognized={self.counters.unrecognized}"
            )
        return {
            "artifact_id": self.artifact_id,
            "counters": self.counters.to_dict(),
            "skipped_by_reason": self.skipped_by_reason(),
            "abandoned": self.aggregated_skips(),
            "directory_abandoned": self.directory_skips(),
            "unrecognized": self.unrecognized_summary(),
            "unreadable_segments": self.segments(),
            "directories": {
                "traversed": self.counters.directories_traversed,
                "skipped": self.counters.directories_skipped,
            },
            "findings": [f.to_dict() for f in sorted(
                self.findings, key=lambda f: (f.location, f.rule_id, f.line_hint or 0))],
            "fatal_error": self.fatal_error,
        }

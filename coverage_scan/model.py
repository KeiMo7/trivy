"""Reason taxonomy and shared domain types.

The four skip reason categories are part of the machine-readable contract and
must never be collapsed into one another:

    SIZE_LIMIT      -- the node exceeded the configured size limit
    NO_PERMISSION   -- the node could not be opened/read due to permissions
    UNPACK_FAILED   -- an archive/segment could not be fully unpacked
    UNRECOGNIZED    -- the content format is not understood by the scanner
"""

from __future__ import annotations

import dataclasses
import enum
from typing import Any, Optional


class SkipReason(str, enum.Enum):
    """Stable, machine-facing reason codes."""

    SIZE_LIMIT = "size_limit"
    NO_PERMISSION = "no_permission"
    UNPACK_FAILED = "unpack_failed"
    UNRECOGNIZED = "unrecognized"

    @property
    def label(self) -> str:
        return {
            SkipReason.SIZE_LIMIT: "over size limit",
            SkipReason.NO_PERMISSION: "no read permission",
            SkipReason.UNPACK_FAILED: "unpack failed",
            SkipReason.UNRECOGNIZED: "unrecognized format",
        }[self]


class NodeKind(str, enum.Enum):
    FILE = "file"
    DIRECTORY = "directory"
    ARCHIVE_MEMBER = "archive_member"
    SEGMENT = "segment"


class ArtifactStatus(str, enum.Enum):
    """Per-artifact verdict.

    SKIPPED items never promote to a pass: an artifact with any coverage gap is
    INCOMPLETE, never CLEAN.
    """

    CLEAN = "clean"             # no findings AND full coverage
    FINDINGS = "findings"       # findings, full coverage
    INCOMPLETE = "incomplete"   # coverage gap, no findings
    FINDINGS_INCOMPLETE = "findings_incomplete"  # both
    FAILED = "failed"           # the artifact as a whole could not be scanned


class ExitCode(enum.IntEnum):
    """Three distinguishable terminal states plus operational failures.

    0  clean and fully covered
    1  findings (regardless of completeness)
    2  incomplete coverage without findings
    3  every artifact in the batch failed
    4  report could not be produced / invalid invocation
    """

    CLEAN = 0
    FINDINGS = 1
    INCOMPLETE = 2
    ALL_FAILED = 3
    REPORT_ERROR = 4


@dataclasses.dataclass(frozen=True)
class SkipRecord:
    """One abandoned node, aggregated in the report by artifact and directory."""

    reason: SkipReason
    location: str                 # redacted display path
    location_hash: str            # stable hash of the raw path (de-dup/id)
    kind: NodeKind
    size_bytes: Optional[int]
    detail: str                   # short classifier detail (no raw sensitive data)
    container: Optional[str]      # redacted path of enclosing archive / segment
    segment_id: Optional[str]     # set when the skip belongs to an unreadable segment

    def to_dict(self) -> dict[str, Any]:
        return {
            "reason": self.reason.value,
            "location": self.location,
            "location_hash": self.location_hash,
            "kind": self.kind.value,
            "size_bytes": self.size_bytes,
            "detail": self.detail,
            "container": self.container,
            "segment_id": self.segment_id,
        }


@dataclasses.dataclass(frozen=True)
class SegmentRecord:
    """A content segment that could not be unpacked as a whole."""

    segment_id: str
    location: str                 # redacted
    location_hash: str
    format: str
    detail: str
    affected_packages: tuple[str, ...]  # package set impacted by the unreadable segment

    def to_dict(self) -> dict[str, Any]:
        return {
            "segment_id": self.segment_id,
            "location": self.location,
            "location_hash": self.location_hash,
            "format": self.format,
            "detail": self.detail,
            "affected_packages": list(self.affected_packages),
        }


@dataclasses.dataclass(frozen=True)
class Finding:
    """A security finding. Matched secret material is never copied in."""

    rule_id: str
    location: str
    location_hash: str
    line_hint: Optional[int]

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "location": self.location,
            "line_hint": self.line_hint,
            "location_hash": self.location_hash,
        }


@dataclasses.dataclass
class CoverageCounters:
    """Reconciliation contract: traversed == analyzed + skipped + unrecognized."""

    traversed: int = 0
    analyzed: int = 0
    skipped: int = 0
    unrecognized: int = 0
    # Directories are tracked separately so the file-level identity stays exact;
    # directory permission failures are still first-class skip records.
    directories_traversed: int = 0
    directories_skipped: int = 0

    def reconcile(self) -> bool:
        return self.traversed == (
            self.analyzed + self.skipped + self.unrecognized
        )

    def to_dict(self) -> dict[str, Any]:
        data = dataclasses.asdict(self)
        data["identity_holds"] = self.reconcile()
        return data

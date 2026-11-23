"""The scan walker.

One entry point, :func:`scan_artifact`, handles both directory trees and
single-file artifacts (including archives, which are recursed into). The walker
owns *classification* -- which of the four reason categories a failure belongs
to -- and delegates counting to :class:`CoverageCollector`.

Invariants maintained here:

* every node reached is reported to the collector exactly once;
* permission problems are distinguished from size and unpack problems;
* a segment that cannot be unpacked as a whole produces a segment record whose
  ``affected_packages`` names the package set that went unread;
* nothing raw (un-redacted) ever reaches the collector's persistent records.
"""

from __future__ import annotations

import errno
import io
import os
from dataclasses import dataclass
from typing import Optional

from . import archive, filetype, secrets
from .archive import DECODE_ERRORS
from .collector import CoverageCollector
from .config import ScanConfig
from .model import NodeKind, SegmentRecord, SkipReason
from .redact import Redactor


class SizeLimitExceeded(Exception):
    """Raised while streaming once more than max_file_size bytes were read."""


@dataclass
class _Location:
    logical_path: str          # un-redacted logical path inside the artifact
    container: Optional[str]   # redacted enclosing archive path, if any


def _is_permission_error(exc: OSError) -> bool:
    return isinstance(exc, PermissionError) or exc.errno in (
        errno.EACCES, errno.EPERM)


def _segment_id(raw_path: str) -> str:
    return f"seg-{Redactor.stable_hash(raw_path)}"


def scan_artifact(artifact_path: str, config: ScanConfig,
                  redactor: Redactor) -> CoverageCollector:
    artifact_id = os.path.basename(os.path.normpath(artifact_path)) or artifact_path
    collector = CoverageCollector(artifact_id, redactor)
    try:
        if os.path.isdir(artifact_path):
            _walk_directory(artifact_path, artifact_path, config, redactor,
                            collector, container=None)
        elif os.path.isfile(artifact_path):
            loc = _Location(logical_path=artifact_id, container=None)
            _process_file(artifact_path, loc, config, redactor, collector, depth=0)
        else:
            collector.mark_fatal(f"artifact path is neither file nor directory: {artifact_path}")
    except Exception as exc:  # defensive: a whole-artifact failure must not crash the batch
        # The failure is recorded on the collector (so it reaches the report)
        # and echoed to stderr; it is never swallowed into a clean verdict.
        import logging
        logging.getLogger("coverage_scan").warning(
            "artifact %s failed before completion: %s: %s",
            artifact_path, type(exc).__name__, exc)
        collector.mark_fatal(f"{type(exc).__name__}: {exc}")
    return collector


# ---------------------------------------------------------------- filesystem

def _walk_directory(root: str, current: str, config: ScanConfig,
                    redactor: Redactor, collector: CoverageCollector,
                    container: Optional[str]) -> None:
    try:
        with os.scandir(current) as it:
            entries = sorted(it, key=lambda e: e.name)
    except OSError as exc:
        logical = os.path.relpath(current, root) if current != root else "."
        if _is_permission_error(exc):
            if current == root:
                # The artifact root itself cannot be opened: nothing in this
                # artifact can be covered, so the whole artifact fails rather
                # than emitting an empty "clean" tree.
                collector.mark_fatal(
                    f"artifact root not readable: {type(exc).__name__}")
                return
            collector.mark_directory(False, logical, detail=type(exc).__name__,
                                     container=container)
        else:
            # Non-permission directory failures (e.g. ENAMETOOLONG, ELOOP,
            # stale NFS handles) are still directory nodes: keep them in the
            # directory counters with an unpack_failed classification rather
            # than inflating the file-level identity.
            collector.mark_directory(
                False, logical,
                detail=f"{type(exc).__name__}: {exc}",
                container=container,
                reason=SkipReason.UNPACK_FAILED)
        return

    collector.mark_directory(True, current)
    for entry in entries:
        logical = entry.path if root == entry.path else os.path.relpath(
            entry.path, root)
        # Symlinks are deliberately not followed by default. That is an access
        # boundary the scanner declines to cross (the target could escape the
        # artifact), recorded as an unpack-level skip with an explicit detail;
        # enabling follow_symlinks processes the target normally instead.
        if entry.is_symlink() and not config.follow_symlinks:
            collector.mark_skipped(
                SkipReason.UNPACK_FAILED, logical, NodeKind.FILE, None,
                detail="symlink not followed (follow_symlinks disabled)",
                container=container)
            continue
        try:
            if entry.is_dir(follow_symlinks=config.follow_symlinks):
                _walk_directory(root, entry.path, config, redactor,
                                collector, container)
            elif entry.is_file(follow_symlinks=config.follow_symlinks):
                _process_file(entry.path, _Location(logical, container),
                              config, redactor, collector, depth=0)
            else:
                # Socket/FIFO/device node: a node type the content scanner has
                # no way to read. Count it as a distinct unrecognized state
                # rather than a file-level skip, so the buckets stay honest.
                collector.mark_unrecognized(logical, 0, container=container)
        except OSError as exc:
            _classify_os_error(exc, logical, None, collector, container,
                               kind=NodeKind.FILE)


def _classify_os_error(exc: OSError, logical: str, size: Optional[int],
                       collector: CoverageCollector, container: Optional[str],
                       kind: NodeKind) -> None:
    if _is_permission_error(exc):
        collector.mark_skipped(SkipReason.NO_PERMISSION, logical, kind, size,
                               detail=type(exc).__name__, container=container)
    else:
        collector.mark_skipped(SkipReason.UNPACK_FAILED, logical, kind, size,
                               detail=f"{type(exc).__name__}: {exc}",
                               container=container)


# ---------------------------------------------------------------- files

def _process_file(disk_path: Optional[str], loc: _Location, config: ScanConfig,
                  redactor: Redactor, collector: CoverageCollector,
                  depth: int, stream: Optional[io.BufferedReader] = None,
                  declared_size: Optional[int] = None) -> None:
    # Cheap size check first for regular files that do not claim to be
    # archives. Archive containers are read regardless of the per-file limit
    # and instead bounded by max_unpacked_bytes/member caps, so an oversized
    # archive still yields per-member coverage instead of one opaque skip.
    if stream is None and disk_path is not None and not filetype.has_archive_suffix(
            loc.logical_path):
        try:
            stat = os.stat(disk_path)
        except OSError as exc:
            _classify_os_error(exc, loc.logical_path, None, collector,
                               loc.container, NodeKind.FILE)
            return
        if stat.st_size > config.max_file_size:
            collector.mark_skipped(
                SkipReason.SIZE_LIMIT, loc.logical_path, NodeKind.FILE,
                stat.st_size, detail=f"size {stat.st_size} > limit {config.max_file_size}",
                container=loc.container)
            return

    owned = stream is None
    try:
        if stream is None:
            assert disk_path is not None
            try:
                handle = open(disk_path, "rb")
            except OSError as exc:
                _classify_os_error(exc, loc.logical_path, declared_size,
                                   collector, loc.container, NodeKind.FILE)
                return
        else:
            handle = stream
        try:
            if filetype.has_archive_suffix(loc.logical_path):
                # Archive containers are bounded by unpacked-bytes / member
                # caps during extraction, not by the per-file read limit.
                data = _read_unbounded(handle)
            else:
                data = _read_with_limits(handle, config, collector, loc)
        finally:
            if owned:
                handle.close()
    except SizeLimitExceeded as exc:
        collector.mark_skipped(
            SkipReason.SIZE_LIMIT, loc.logical_path, NodeKind.FILE,
            declared_size, detail=f"size exceeds limit {exc.args[0]}",
            container=loc.container)
        return
    except OSError as exc:
        _classify_os_error(exc, loc.logical_path, declared_size, collector,
                           loc.container, NodeKind.FILE)
        return

    if data is None:
        return  # already accounted (e.g. archive handled internally)

    if filetype.has_archive_suffix(loc.logical_path):
        # The name declares an archive. If magic bytes cannot confirm it, the
        # content is corrupted/head-truncated: classify as UNPACK_FAILED with a
        # segment record rather than misreading bytes as text.
        content_type = filetype.sniff(data[:512], loc.logical_path)
        if content_type not in filetype.ARCHIVE_TYPES:
            _record_unreadable_segment(
                collector, loc, redactor, fmt="archive",
                detail="archive signature missing or corrupted",
                affected=("*",), size=len(data))
            collector.mark_skipped(
                SkipReason.UNPACK_FAILED, loc.logical_path, NodeKind.SEGMENT,
                len(data), detail="corrupted archive container",
                container=loc.container,
                segment_id=_segment_id(loc.logical_path))
            return
    else:
        content_type = filetype.sniff(data[:512], loc.logical_path)

    if content_type in filetype.ARCHIVE_TYPES:
        _handle_archive(data, content_type, loc, config, redactor,
                        collector, depth)
    elif content_type == filetype.ContentType.TEXT:
        _analyze_text(data, loc, collector, config)
    else:
        collector.mark_unrecognized(loc.logical_path, len(data),
                                    container=loc.container)


def _read_with_limits(handle: io.BufferedReader, config: ScanConfig,
                      collector: CoverageCollector, loc: _Location) -> Optional[bytes]:
    chunks: list[bytes] = []
    total = 0
    while True:
        chunk = handle.read(1 << 16)
        if not chunk:
            break
        total += len(chunk)
        if total > config.max_file_size:
            raise SizeLimitExceeded(config.max_file_size)
        chunks.append(chunk)
    return b"".join(chunks)


def _read_unbounded(handle: io.BufferedReader) -> bytes:
    chunks: list[bytes] = []
    while True:
        chunk = handle.read(1 << 16)
        if not chunk:
            break
        chunks.append(chunk)
    return b"".join(chunks)


def _analyze_text(data: bytes, loc: _Location,
                  collector: CoverageCollector, config: ScanConfig) -> None:
    if config.secret_scan:
        hits = secrets.scan_stream(io.BytesIO(data))
        for hit in hits:
            collector.add_finding(hit.rule_id, loc.logical_path, hit.line_hint)
    collector.mark_analyzed()


# ---------------------------------------------------------------- archives

def _handle_archive(data: bytes, content_type: filetype.ContentType,
                    loc: _Location, config: ScanConfig, redactor: Redactor,
                    collector: CoverageCollector, depth: int) -> None:
    if depth >= config.max_archive_depth:
        # Over-deep nesting: the whole segment stays unread.
        _record_unreadable_segment(
            collector, loc, redactor, fmt=content_type.value,
            detail=f"nested archive depth limit {config.max_archive_depth} reached",
            affected=("*",), size=len(data))
        collector.mark_skipped(
            SkipReason.UNPACK_FAILED, loc.logical_path, NodeKind.SEGMENT,
            len(data), detail="max archive depth exceeded",
            container=loc.container, segment_id=_segment_id(loc.logical_path))
        return

    # The archive container itself is a traversed node; it is only "analyzed"
    # if a complete end event arrives. Failed containers move to skipped.
    container_redacted = redactor.redact_path(loc.logical_path)
    member_count = 0
    unpacked_bytes = 0
    failed_members: list[str] = []
    seen_packages: set[str] = set()
    member_drain_failed = False
    saw_end = False
    complete = False
    end_error = ""

    for event in archive.open_archive_stream(
            io.BytesIO(data), loc.logical_path, content_type):
        if event.kind == "open_failed":
            _record_unreadable_segment(
                collector, loc, redactor, fmt=content_type.value,
                detail=event.error or "open failed", affected=("*",),
                size=len(data))
            collector.mark_skipped(
                SkipReason.UNPACK_FAILED, loc.logical_path, NodeKind.SEGMENT,
                len(data), detail=event.error or "open failed",
                container=loc.container, segment_id=_segment_id(loc.logical_path))
            return

        if event.kind == "end":
            saw_end = True
            complete = event.complete
            end_error = event.error or ""
            continue

        if event.kind == "read_failed":
            assert event.info is not None
            failed_members.append(event.info.name)
            child_path = f"{loc.logical_path}/{event.info.name}"
            reason = (SkipReason.NO_PERMISSION if event.error == "encrypted member"
                      else SkipReason.UNPACK_FAILED)
            collector.mark_skipped(
                reason, child_path, NodeKind.ARCHIVE_MEMBER,
                event.info.size, detail=event.error or "read failed",
                container=container_redacted,
                segment_id=_segment_id(loc.logical_path) if reason == SkipReason.UNPACK_FAILED else None)
            continue

        if event.kind == "member":
            assert event.info is not None
            member_count += 1
            seen_packages.update(_package_set([event.info.name]))
            if member_count > config.max_archive_members:
                _record_unreadable_segment(
                    collector, loc, redactor, fmt=content_type.value,
                    detail=f"member cap {config.max_archive_members} exceeded",
                    affected=("*remaining*",), size=len(data))
                collector.mark_skipped(
                    SkipReason.UNPACK_FAILED, loc.logical_path, NodeKind.SEGMENT,
                    len(data), detail="archive member cap exceeded",
                    container=loc.container,
                    segment_id=_segment_id(loc.logical_path))
                return
            child_path = f"{loc.logical_path}/{event.info.name}"
            child_loc = _Location(child_path, container_redacted)
            if event.info.is_dir:
                collector.mark_directory(True, child_path,
                                         container=container_redacted)
                continue
            if event.stream is None:
                # Symlink/hardlink/non-regular member: nothing to analyze.
                collector.mark_skipped(
                    SkipReason.UNPACK_FAILED, child_path,
                    NodeKind.ARCHIVE_MEMBER, event.info.size,
                    detail="non-regular archive member",
                    container=container_redacted)
                continue
            member_data = _drain_member(event, config, collector, child_loc,
                                        unpacked_bytes)
            if member_data is None:
                # _drain_member already bucketed the member; remember that the
                # container produced an unreadable member so its own terminal
                # state is a segment failure, not a clean "analyzed".
                member_drain_failed = True
                continue
            unpacked_bytes += len(member_data)
            if unpacked_bytes > config.max_unpacked_bytes:
                _record_unreadable_segment(
                    collector, loc, redactor, fmt=content_type.value,
                    detail=f"unpacked byte cap {config.max_unpacked_bytes} exceeded",
                    affected=("*remaining*",), size=len(data))
                collector.mark_skipped(
                    SkipReason.UNPACK_FAILED, loc.logical_path, NodeKind.SEGMENT,
                    len(data), detail="unpacked byte cap exceeded",
                    container=loc.container,
                    segment_id=_segment_id(loc.logical_path))
                return
            _process_member_bytes(member_data, event.info, child_loc, config,
                                  redactor, collector, depth)

    if not saw_end:  # pragma: no cover - every archive implementation emits end
        complete = False
        end_error = "missing end event"

    # A member payload that failed to decode makes the container incomplete
    # even when the archive's own structural iteration reported a clean end.
    if complete and member_drain_failed:
        complete = False
        end_error = end_error or "one or more members could not be decoded"

    if not complete:
        # Name the packages reached before the structural failure; the
        # "*tail*" sentinel marks that content beyond them went unread.
        affected_set = set(_package_set(failed_members)) | seen_packages
        affected = tuple(sorted(affected_set | {"*tail*"}))
        _record_unreadable_segment(
            collector, loc, redactor, fmt=content_type.value,
            detail=end_error or "truncated archive",
            affected=affected, size=len(data))
        collector.mark_skipped(
            SkipReason.UNPACK_FAILED, loc.logical_path, NodeKind.SEGMENT,
            len(data), detail=end_error or "truncated archive",
            container=loc.container, segment_id=_segment_id(loc.logical_path))
    else:
        collector.mark_analyzed()


def _drain_member(event, config: ScanConfig, collector: CoverageCollector,
                  child_loc: _Location, already_unpacked: int) -> Optional[bytes]:
    try:
        data = event.stream.read()
    except DECODE_ERRORS as exc:
        # A corrupt/truncated member payload must stay inside the event model:
        # bucket the member as an unpack failure and attach it to its container
        # segment instead of letting the exception unwind (which would leave
        # both the member and the container entirely unaccounted for).
        collector.mark_skipped(
            SkipReason.UNPACK_FAILED, child_loc.logical_path,
            NodeKind.ARCHIVE_MEMBER, event.info.size,
            detail=f"{type(exc).__name__}: {exc}",
            container=child_loc.container,
            segment_id=_segment_id(child_loc.container or child_loc.logical_path))
        return None
    if len(data) > config.max_file_size:
        collector.mark_skipped(
            SkipReason.SIZE_LIMIT, child_loc.logical_path,
            NodeKind.ARCHIVE_MEMBER, len(data),
            detail=f"size {len(data)} > limit {config.max_file_size}",
            container=child_loc.container)
        return None
    return data


def _process_member_bytes(data: bytes, info, child_loc: _Location,
                          config: ScanConfig, redactor: Redactor,
                          collector: CoverageCollector, depth: int) -> None:
    if filetype.has_archive_suffix(info.name):
        content_type = filetype.sniff(data[:512], info.name)
        if content_type not in filetype.ARCHIVE_TYPES:
            _record_unreadable_segment(
                collector, child_loc, redactor, fmt="archive",
                detail="corrupted nested archive", affected=("*",),
                size=len(data))
            collector.mark_skipped(
                SkipReason.UNPACK_FAILED, child_loc.logical_path,
                NodeKind.SEGMENT, len(data),
                detail="corrupted archive container",
                container=child_loc.container,
                segment_id=_segment_id(child_loc.logical_path))
            return
    else:
        content_type = filetype.sniff(data[:512], info.name)

    if content_type in filetype.ARCHIVE_TYPES:
        _handle_archive(data, content_type, child_loc, config, redactor,
                        collector, depth + 1)
    elif content_type == filetype.ContentType.TEXT:
        _analyze_text(data, child_loc, collector, config)
    else:
        collector.mark_unrecognized(child_loc.logical_path, len(data),
                                    container=child_loc.container)


def _record_unreadable_segment(collector: CoverageCollector, loc: _Location,
                               redactor: Redactor, fmt: str, detail: str,
                               affected: tuple[str, ...], size: int) -> None:
    raw = loc.logical_path
    collector.add_segment(SegmentRecord(
        segment_id=_segment_id(raw),
        location=redactor.redact_path(raw),
        location_hash=Redactor.stable_hash(raw),
        format=fmt,
        detail=detail,
        affected_packages=tuple(sorted(affected)),
    ))


def _package_set(member_names: list[str]) -> list[str]:
    """Top-level package (directory) names seen inside a failed archive."""
    packages: set[str] = set()
    for name in member_names:
        head = name.replace("\\", "/").split("/", 1)[0]
        if head:
            packages.add(head)
    return sorted(packages)

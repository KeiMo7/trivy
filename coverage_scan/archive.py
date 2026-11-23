"""Archive unpacking with explicit failure events.

Every archive is exposed as a stream of :class:`ArchiveEvent` objects. An error
mid-way through extraction is an event, not an exception that loses the members
already read. The walker turns those events into coverage records, so a
truncated, encrypted or over-deep archive can never look like a clean one.

Supported containers: zip family, tar family (optionally gzip/bz2/xz
compressed) and single-stream gzip.
"""

from __future__ import annotations

import dataclasses
import gzip
import io
import lzma
import os
import tarfile
import zipfile
import zlib
from collections.abc import Iterator
from typing import Optional

from . import filetype

# Exceptions raised while decoding/reading a member's payload. These are all
# data-driven failures on untrusted input, never control flow: catching them
# broadly here is what keeps a single corrupt member from escaping the event
# model and silently dropping the whole container out of coverage accounting.
DECODE_ERRORS: tuple[type[BaseException], ...] = (
    tarfile.TarError,      # ReadError/CompressionError/StreamError/...
    zipfile.BadZipFile,
    zlib.error,
    gzip.BadGzipFile,
    lzma.LZMAError,
    OSError,               # includes EACCES, truncated gzip, some backend errors
    EOFError,
    RuntimeError,          # zip: unsupported compression/encryption
    ValueError,            # zip: negative seek, corrupt field values
)
# zstandard only ships with some Python builds; register it when present.
try:
    import zstandard as _zstd  # type: ignore
    DECODE_ERRORS = DECODE_ERRORS + (_zstd.ZstdError,)
except ImportError:
    pass


@dataclasses.dataclass
class MemberInfo:
    name: str
    size: Optional[int]
    is_dir: bool
    encrypted: bool = False


@dataclasses.dataclass
class ArchiveEvent:
    kind: str                       # "open_failed" | "member" | "read_failed" | "end"
    info: Optional[MemberInfo] = None
    error: Optional[str] = None
    stream: Optional[io.BufferedReader] = None
    # For "end": False when iteration stopped because of a structural failure.
    complete: bool = True
    fmt: str = ""


def open_archive(path: str, fmt: filetype.ContentType) -> Iterator[ArchiveEvent]:
    """Yield events for an archive located on disk at ``path``."""
    if fmt == filetype.ContentType.ZIP:
        yield from _open_zip(path)
    elif fmt == filetype.ContentType.TAR:
        yield from _open_tar(path)
    elif fmt == filetype.ContentType.GZIP:
        yield from _open_gzip(path)
    else:  # pragma: no cover - guarded by caller
        yield ArchiveEvent(kind="open_failed", error=f"not an archive format: {fmt}")


def open_archive_stream(stream: io.BufferedReader, name: str,
                        fmt: filetype.ContentType) -> Iterator[ArchiveEvent]:
    """Yield events for an archive delivered as an in-memory nested stream."""
    if fmt == filetype.ContentType.ZIP:
        yield from _open_zip_stream(stream, name)
    elif fmt == filetype.ContentType.TAR:
        yield from _open_tar_stream(stream, name)
    elif fmt == filetype.ContentType.GZIP:
        yield from _open_gzip_stream(stream, name)
    else:  # pragma: no cover - guarded by caller
        yield ArchiveEvent(kind="open_failed", error=f"not an archive format: {fmt}")


# ---------------------------------------------------------------- zip family

def _open_zip(path: str) -> Iterator[ArchiveEvent]:
    try:
        handle = open(path, "rb")
    except OSError as exc:
        yield ArchiveEvent(kind="open_failed", error=type(exc).__name__)
        return
    with handle:
        with zf:
            try:
                zf = zipfile.ZipFile(handle)
            except DECODE_ERRORS as exc:
                yield ArchiveEvent(kind="open_failed", error=f"{type(exc).__name__}: {exc.args[0] if exc.args else ''}")
                return
        yield from _zip_events(zf)


def _open_zip_stream(stream: io.BufferedReader, name: str) -> Iterator[ArchiveEvent]:
    try:
        zf = zipfile.ZipFile(io.BytesIO(stream.read()))
    except DECODE_ERRORS as exc:
        yield ArchiveEvent(kind="open_failed", error=f"{type(exc).__name__}: {exc.args[0] if exc.args else ''}")
        return
    yield from _zip_events(zf)


def _zip_events(zf: zipfile.ZipFile) -> Iterator[ArchiveEvent]:
    fmt = filetype.ContentType.ZIP.value
    try:
        with zf:
            infos = zf.infolist()
            for info in infos:
                member = MemberInfo(
                    name=info.filename,
                    size=info.file_size,
                    is_dir=info.is_dir(),
                    encrypted=filetype.zip_encrypted(info),
                )
                if member.encrypted:
                    # Encrypted content is access we are not allowed to perform.
                    yield ArchiveEvent(kind="read_failed", info=member,
                                       error="encrypted member", fmt=fmt)
                    continue
                try:
                    raw = zf.read(info)
                except DECODE_ERRORS as exc:
                    yield ArchiveEvent(
                        kind="read_failed", info=member,
                        error=f"{type(exc).__name__}: {exc.args[0] if exc.args else ''}",
                        fmt=fmt,
                    )
                    continue
                yield ArchiveEvent(kind="member", info=member,
                                   stream=io.BytesIO(raw), fmt=fmt)
    except DECODE_ERRORS as exc:
        # Structural failure while iterating: a truncated central directory etc.
        yield ArchiveEvent(kind="end", complete=False,
                           error=f"{type(exc).__name__}: {exc.args[0] if exc.args else ''}",
                           fmt=fmt)
        return
    yield ArchiveEvent(kind="end", complete=True, fmt=fmt)


# ---------------------------------------------------------------- tar family


def _open_tar(path: str) -> Iterator[ArchiveEvent]:
    try:
        handle = open(path, "rb")
    except OSError as exc:
        yield ArchiveEvent(kind="open_failed", error=type(exc).__name__)
        return
    with handle:
        try:
            tf = tarfile.open(fileobj=handle, mode="r:*")
        except DECODE_ERRORS as exc:
            yield ArchiveEvent(kind="open_failed",
                               error=f"{type(exc).__name__}: {exc.args[0] if exc.args else ''}")
            return
        yield from _tar_events(tf)


def _open_tar_stream(stream: io.BufferedReader, name: str) -> Iterator[ArchiveEvent]:
    try:
        tf = tarfile.open(fileobj=stream, mode="r:*")
    except DECODE_ERRORS as exc:
        yield ArchiveEvent(kind="open_failed",
                           error=f"{type(exc).__name__}: {exc.args[0] if exc.args else ''}")
        return
    yield from _tar_events(tf)


def _tar_events(tf: tarfile.TarFile) -> Iterator[ArchiveEvent]:
    fmt = filetype.ContentType.TAR.value
    structural_failure: Optional[str] = None
    try:
        with tf:
            while True:
                try:
                    member = tf.next()
                except DECODE_ERRORS as exc:
                    structural_failure = f"{type(exc).__name__}: {exc.args[0] if exc.args else ''}"
                    break
                if member is None:
                    break
                info = MemberInfo(
                    name=member.name,
                    size=member.size,
                    is_dir=member.isdir(),
                )
                if member.isdir() or member.issym() or member.islnk():
                    # Non-regular entries are reported for accounting but carry
                    # no readable stream; symlinks are never followed inside
                    # archives (they cannot escape to the host FS here).
                    yield ArchiveEvent(kind="member", info=info, stream=None, fmt=fmt)
                    continue
                try:
                    extracted = tf.extractfile(member)
                except DECODE_ERRORS as exc:
                    yield ArchiveEvent(
                        kind="read_failed", info=info,
                        error=f"{type(exc).__name__}: {exc.args[0] if exc.args else ''}",
                        fmt=fmt,
                    )
                    continue
                if extracted is None:
                    yield ArchiveEvent(kind="member", info=info, stream=None, fmt=fmt)
                    continue
                # Wrap so a truncated member raises during read, not at next().
                yield ArchiveEvent(kind="member", info=info, stream=extracted, fmt=fmt)
    except DECODE_ERRORS as exc:
        structural_failure = f"{type(exc).__name__}: {exc.args[0] if exc.args else ''}"

    if structural_failure is not None:
        yield ArchiveEvent(kind="end", complete=False, error=structural_failure, fmt=fmt)
    else:
        yield ArchiveEvent(kind="end", complete=True, fmt=fmt)


# ---------------------------------------------------------------- gzip

def _open_gzip(path: str) -> Iterator[ArchiveEvent]:
    try:
        handle = open(path, "rb")
    except OSError as exc:
        yield ArchiveEvent(kind="open_failed", error=type(exc).__name__)
        return
    with handle:
        try:
            gz = gzip.GzipFile(fileobj=handle)
            data = gz.read()
        except DECODE_ERRORS as exc:
            yield ArchiveEvent(kind="open_failed",
                               error=f"{type(exc).__name__}: {exc.args[0] if exc.args else ''}")
            return
    member_name = _gzip_member_name(path)
    info = MemberInfo(name=member_name, size=len(data), is_dir=False)
    yield ArchiveEvent(kind="member", info=info, stream=io.BytesIO(data),
                       fmt=filetype.ContentType.GZIP.value)
    yield ArchiveEvent(kind="end", complete=True, fmt=filetype.ContentType.GZIP.value)


def _open_gzip_stream(stream: io.BufferedReader, name: str) -> Iterator[ArchiveEvent]:
    try:
        gz = gzip.GzipFile(fileobj=stream)
        data = gz.read()
    except DECODE_ERRORS as exc:
        yield ArchiveEvent(kind="open_failed",
                           error=f"{type(exc).__name__}: {exc.args[0] if exc.args else ''}")
        return
    info = MemberInfo(name=_gzip_member_name(name), size=len(data), is_dir=False)
    yield ArchiveEvent(kind="member", info=info, stream=io.BytesIO(data),
                       fmt=filetype.ContentType.GZIP.value)
    yield ArchiveEvent(kind="end", complete=True, fmt=filetype.ContentType.GZIP.value)


def _gzip_member_name(path: str) -> str:
    base = os.path.basename(path)
    if base.endswith(".gz"):
        return base[:-3]
    if base.endswith(".tgz"):
        return base[:-4] + ".tar"
    return base + ".inflated"

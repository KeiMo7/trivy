"""Content identification by magic bytes.

Identification is deliberately conservative: a node whose bytes match no known
signature is reported as *unrecognized* and counted as such, rather than being
silently dropped or assumed safe. Extension names are never trusted on their
own, but a known container extension combined with a failed signature check is
what lets the walker classify the failure as UNPACK_FAILED instead.
"""

from __future__ import annotations

import enum
import zipfile


class ContentType(str, enum.Enum):
    ZIP = "zip"
    TAR = "tar"
    GZIP = "gzip"
    TEXT = "text"
    UNKNOWN = "unknown"


ARCHIVE_TYPES = frozenset({ContentType.ZIP, ContentType.TAR, ContentType.GZIP})

# Extensions that declare an archive intent. Used to distinguish "this claims
# to be an archive but is broken" (UNPACK_FAILED) from "we have no idea what
# this is" (UNRECOGNIZED).
_ARCHIVE_SUFFIXES = {
    ".zip", ".jar", ".war", ".ear", ".apk", ".ipa", ".whl", ".docx", ".xlsx",
    ".tar", ".gz", ".tgz", ".tar.gz", ".bz2", ".tbz2", ".tar.bz2",
    ".xz", ".txz", ".tar.xz", ".zst", ".tzst",
}


def has_archive_suffix(name: str) -> bool:
    lowered = name.lower()
    return any(lowered.endswith(suf) for suf in _ARCHIVE_SUFFIXES)


def sniff(head: bytes, name: str = "") -> ContentType:
    """Classify content from its leading bytes."""
    if head.startswith(b"PK\x03\x04") or head.startswith(b"PK\x05\x06"):
        return ContentType.ZIP
    if head.startswith(b"\x1f\x8b"):
        return ContentType.GZIP
    if _looks_like_tar(head):
        return ContentType.TAR
    if _looks_like_text(head):
        return ContentType.TEXT
    return ContentType.UNKNOWN


def _looks_like_tar(head: bytes) -> bool:
    # ustar magic lives at offset 257; need enough of the first header block.
    if len(head) >= 265 and head[257:262] in (b"ustar", b"ustar\x00"):
        return True
    # Old GNU tars without ustar magic: check the checksum field shape.
    if len(head) >= 156:
        field = head[148:156]
        if field[:6].strip(b" \x00").isdigit() and field[6:8] in (b"\x00 ", b" \x00", b"  "):
            return True
    return False


def _looks_like_text(head: bytes) -> bool:
    if not head:
        return True  # empty files are treated as (empty) text, fully analyzable
    if b"\x00" in head[:4096]:
        return False
    try:
        head[:4096].decode("utf-8")
        return True
    except UnicodeDecodeError:
        sample = head[:4096]
        # Latin-1 would accept every byte, so require BOTH sparse control
        # characters and sparse high bytes: random/binary payloads such as
        # 0xFF padding must not be mistaken for text.
        controls = sum(1 for b in sample if b < 9 or 13 < b < 32)
        high_bytes = sum(1 for b in sample if b >= 0x7F)
        return (controls / len(sample) < 0.05
                and high_bytes / len(sample) < 0.02)


def zip_encrypted(info: zipfile.ZipInfo) -> bool:
    """A zip member is encrypted when flag bit 0 is set."""
    return bool(info.flag_bits & 0x1)

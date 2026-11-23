"""Minimal secret scanning over analyzed content.

Only rule identifiers and locations are recorded -- matched material itself is
never copied into a report (hard constraint 4). Scanning is streaming and
keeps a small overlap window so a secret split across a chunk boundary is not
missed.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

# Rule order is stable; it is the report's rule_id namespace.
_RULES: tuple[tuple[str, "re.Pattern[bytes]"], ...] = (
    ("aws-access-key-id", re.compile(rb"AKIA[0-9A-Z]{16}")),
    ("aws-secret-access-key", re.compile(rb"(?i)aws(.{0,20})?['\"][0-9a-zA-Z/+]{40}['\"]")),
    ("github-pat", re.compile(rb"gh[pousr]_[A-Za-z0-9]{36,255}")),
    ("github-old-token", re.compile(rb"[0-9a-f]{40}")),
    ("private-key-pem", re.compile(rb"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY(?: BLOCK)?-----")),
    ("jwt", re.compile(rb"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}")),
    ("generic-bearer", re.compile(rb"(?i)bearer\s+[a-z0-9._\-]{20,}")),
    ("password-assignment", re.compile(rb"(?i)(?:password|passwd|pwd)\s*[:=]\s*['\"]?[^'\"\s]{8,}")),
)

_CHUNK = 1 << 20          # 1 MiB
_OVERLAP = 512            # max pattern look-behind window we need to preserve


@dataclass(frozen=True)
class RawHit:
    rule_id: str
    line_hint: int


def scan_stream(stream, limit: int | None = None) -> list[RawHit]:
    """Scan a binary stream, returning de-duplicated rule hits with line hints."""
    hits: list[RawHit] = []
    seen: set[tuple[str, int]] = set()
    carry = b""
    line_base = 0          # line count consumed in previous chunks
    consumed = 0
    while True:
        chunk = stream.read(_CHUNK)
        if not chunk:
            break
        if limit is not None and consumed + len(chunk) > limit:
            chunk = chunk[: max(0, limit - consumed)]
        buf = carry + chunk
        for rule_id, pattern in _RULES:
            for match in pattern.finditer(buf):
                line_hint = line_base + buf.count(b"\n", 0, match.start()) + 1
                key = (rule_id, line_hint)
                if key not in seen:
                    seen.add(key)
                    hits.append(RawHit(rule_id, line_hint))
        carry = buf[-_OVERLAP:] if len(buf) >= _OVERLAP else buf
        line_base += chunk.count(b"\n")
        consumed += len(chunk)
        if limit is not None and consumed >= limit:
            break
    hits.sort(key=lambda h: (h.line_hint, h.rule_id))
    return hits

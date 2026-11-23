"""Path/name redaction.

Locations and filenames may contain passwords, private-key paths and other
sensitive strings. Nothing raw leaves the scanner: every path is rendered
through this module before it enters a report.

Redaction is deterministic: the same raw path always maps to the same
redaction token, which keeps repeated scans byte-identical in their coverage
sections while still letting a human disambiguate two files of the same kind.
"""

from __future__ import annotations

import hashlib
import posixpath
import re

from .config import ScanConfig


class Redactor:
    def __init__(self, config: ScanConfig) -> None:
        self._rules = tuple(re.compile(p) for p in config.redaction_rules)
        # Cache so the same component always renders identically within a run
        # and across runs (the hash input is the raw string, not process state).
        self._cache: dict[str, str] = {}

    @staticmethod
    def stable_hash(raw: str) -> str:
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]

    def redact_component(self, component: str) -> str:
        """Redact a single path component (file/directory name)."""
        if not component:
            return component
        cached = self._cache.get(component)
        if cached is not None:
            return cached
        if any(rule.search(component) for rule in self._rules):
            token = f"<REDACTED:{self.stable_hash(component)}>"
        else:
            token = component
        self._cache[component] = token
        return token

    def redact_path(self, raw_path: str) -> str:
        """Redact a slash-separated logical path, keeping its structure visible.

        Directory structure stays readable (that is what coverage aggregation
        groups on); only the sensitive components themselves are replaced.
        """
        if not raw_path:
            return raw_path
        normalized = raw_path.replace("\\", "/")
        parts = normalized.split("/")
        return "/".join(self.redact_component(p) for p in parts)

    def redact_dirname(self, raw_path: str) -> str:
        """Redacted parent directory, used as the aggregation key."""
        parent = posixpath.dirname(raw_path.replace("\\", "/"))
        return self.redact_path(parent) if parent else "."

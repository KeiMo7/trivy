"""Configuration.

Thresholds and skip rules are configurable, but configuration only changes
*what gets skipped* -- never how a finding or the final verdict is evaluated.
Every field has a safe default so the scanner runs with no configuration at all.
"""

from __future__ import annotations

import dataclasses
import json
from pathlib import Path
from typing import Any


@dataclasses.dataclass(frozen=True)
class ScanConfig:
    max_file_size: int = 1 * 1024 * 1024          # individual file limit (bytes)
    max_archive_depth: int = 8                     # nested-archive depth limit
    max_archive_members: int = 10_000              # per-archive member cap
    max_unpacked_bytes: int = 256 * 1024 * 1024    # total bytes streamed per archive
    follow_symlinks: bool = False
    secret_scan: bool = True
    redaction_rules: tuple[str, ...] = (
        # Filename/path component patterns whose presence marks a sensitive path.
        r"(?i)id_rsa",
        r"(?i)id_ed25519",
        r"(?i)id_ecdsa",
        r"(?i)\.pem$",
        r"(?i)\.key$",
        r"(?i)\.p12$",
        r"(?i)\.pfx$",
        r"(?i)\.keystore$",
        r"(?i)\.jks$",
        r"(?i)\.kdbx$",
        r"(?i)\.env$",
        r"(?i)\.netrc$",
        r"(?i)\.htpasswd$",
        r"(?i)credentials?",
        r"(?i)secret[s]?",
        r"(?i)passwd",
        r"(?i)shadow",
        r"(?i)\.aws/",
        r"(?i)\.ssh/",
        r"(?i)\.gnupg/",
        r"(?i)token",
        r"(?i)password",
    )

    @staticmethod
    def load(path: str | Path | None, overrides: dict[str, Any] | None = None) -> "ScanConfig":
        raw: dict[str, Any] = {}
        if path is not None:
            with open(path, "r", encoding="utf-8") as fh:
                loaded = json.load(fh)
            if not isinstance(loaded, dict):
                raise ValueError("config file must contain a JSON object")
            raw.update(loaded)
        if overrides:
            raw.update({k: v for k, v in overrides.items() if v is not None})

        known = {f.name for f in dataclasses.fields(ScanConfig)}
        unknown = sorted(set(raw) - known)
        if unknown:
            raise ValueError(f"unknown configuration keys: {', '.join(unknown)}")

        cfg = ScanConfig(**raw)
        if cfg.max_file_size <= 0:
            raise ValueError("max_file_size must be positive")
        if cfg.max_archive_depth < 0 or cfg.max_archive_members <= 0:
            raise ValueError("archive limits must be non-negative/positive")
        if cfg.max_unpacked_bytes <= 0:
            raise ValueError("max_unpacked_bytes must be positive")
        return cfg

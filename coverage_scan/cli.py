"""Command-line entry point.

Exit codes (requirement II.8 / IV):
    0  clean and fully covered
    1  findings present (with or without a coverage gap)
    2  no findings, but coverage is incomplete
    3  every artifact in the batch failed
    4  report could not be produced / bad invocation
"""

from __future__ import annotations

import argparse
import datetime as _dt
import json
import os
import sys

from .collector import ReconciliationError
from .config import ScanConfig
from .redact import Redactor
from .render import render_text
from .scanner import (
    ReportWriteError,
    build_report,
    exit_code_for,
    run_batch,
    write_report,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="coverage-scan",
        description="Coverage-aware artifact scanner: skipped content is never "
                    "reported as a clean pass.",
    )
    parser.add_argument("artifacts", nargs="+",
                        help="artifact files or directories (batch mode when >1)")
    parser.add_argument("--json", dest="json_path", default="reports/report.json",
                        help="machine-readable report path (default: reports/report.json)")
    parser.add_argument("--text", dest="text_path", default=None,
                        help="optional human-readable report path")
    parser.add_argument("--config", dest="config_path", default=None,
                        help="JSON configuration file")
    parser.add_argument("--max-file-size", type=int, default=None,
                        help="per-file size limit in bytes")
    parser.add_argument("--max-archive-depth", type=int, default=None)
    parser.add_argument("--max-archive-members", type=int, default=None)
    parser.add_argument("--max-unpacked-bytes", type=int, default=None)
    parser.add_argument("--follow-symlinks", action="store_true", default=None)
    parser.add_argument("--no-secret-scan", action="store_true",
                        help="disable secret matching (coverage accounting unchanged)")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    overrides = {
        "max_file_size": args.max_file_size,
        "max_archive_depth": args.max_archive_depth,
        "max_archive_members": args.max_archive_members,
        "max_unpacked_bytes": args.max_unpacked_bytes,
        "follow_symlinks": args.follow_symlinks,
        "secret_scan": False if args.no_secret_scan else None,
    }
    try:
        config = ScanConfig.load(args.config_path, overrides)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"configuration error: {exc}", file=sys.stderr)
        return 4

    missing = [p for p in args.artifacts if not os.path.exists(p)]
    if missing:
        print(f"artifact path(s) not found: {', '.join(missing)}", file=sys.stderr)
        return 4

    redactor = Redactor(config)
    try:
        results = run_batch(args.artifacts, config, redactor)
        report = build_report(results, config)
        report["generated_at"] = _dt.datetime.now(_dt.timezone.utc).isoformat()
        write_report(report, args.json_path)
        if args.text_path:
            with open(args.text_path, "w", encoding="utf-8") as fh:
                fh.write(render_text(report))
                fh.write("\n")
    except ReconciliationError as exc:
        # IV.1: coverage section failure -> the whole report fails.
        print(f"report failed (coverage integrity): {exc}", file=sys.stderr)
        return 4
    except ReportWriteError as exc:
        print(f"report failed (write): {exc}", file=sys.stderr)
        return 4

    print(render_text(report))
    return exit_code_for(report)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())

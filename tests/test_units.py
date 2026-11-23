"""Unit tests for the coverage scanner internals."""

from __future__ import annotations

import io
import json
import os
import tempfile
import unittest
import zipfile
from pathlib import Path

from coverage_scan.archive import open_archive_stream
from coverage_scan.config import ScanConfig
from coverage_scan.filetype import ContentType, sniff
from coverage_scan.model import SkipReason
from coverage_scan.redact import Redactor
from coverage_scan.secrets import scan_stream


class ConfigTests(unittest.TestCase):
    def test_defaults_are_safe(self) -> None:
        cfg = ScanConfig.load(None)
        self.assertGreater(cfg.max_file_size, 0)
        self.assertGreaterEqual(cfg.max_archive_depth, 1)

    def test_unknown_keys_rejected(self) -> None:
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as fh:
            json.dump({"not_a_key": 1}, fh)
            path = fh.name
        try:
            with self.assertRaises(ValueError):
                ScanConfig.load(path)
        finally:
            os.unlink(path)

    def test_cli_overrides_win(self) -> None:
        cfg = ScanConfig.load(None, {"max_file_size": 1234})
        self.assertEqual(cfg.max_file_size, 1234)

    def test_bad_threshold_rejected(self) -> None:
        with self.assertRaises(ValueError):
            ScanConfig.load(None, {"max_file_size": 0})


class RedactionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.redactor = Redactor(ScanConfig.load(None))

    def test_sensitive_components_redacted(self) -> None:
        for raw in (".ssh/id_rsa", "deploy/password-store.env",
                    "certs/server.pem", ".aws/credentials", "vault/.env"):
            rendered = self.redactor.redact_path(raw)
            self.assertNotIn("id_rsa", rendered)
            self.assertNotIn("password", rendered)
            self.assertNotIn("credentials", rendered)
            self.assertIn("<REDACTED:", rendered)

    def test_structure_preserved_but_content_hidden(self) -> None:
        rendered = self.redactor.redact_path("a/b/id_ed25519")
        self.assertEqual(rendered.split("/")[:2], ["a", "b"])
        self.assertTrue(rendered.split("/")[2].startswith("<REDACTED:"))

    def test_deterministic_across_instances(self) -> None:
        other = Redactor(ScanConfig.load(None))
        raw = "secrets/prod.key"
        self.assertEqual(self.redactor.redact_path(raw),
                         other.redact_path(raw))

    def test_two_different_sensitive_names_disambiguated(self) -> None:
        one = self.redactor.redact_path("d/id_rsa")
        two = self.redactor.redact_path("d/id_ecdsa")
        self.assertNotEqual(one, two)

    def test_non_sensitive_path_unchanged(self) -> None:
        self.assertEqual(self.redactor.redact_path("src/main.py"),
                         "src/main.py")

    def test_directory_aggregation_key(self) -> None:
        self.assertEqual(
            self.redactor.redact_dirname("pkg/.ssh/id_rsa"),
            "pkg/" + self.redactor.redact_component(".ssh"))


class FiletypeTests(unittest.TestCase):
    def test_signatures(self) -> None:
        self.assertEqual(sniff(b"PK\x03\x04rest"), ContentType.ZIP)
        self.assertEqual(sniff(b"\x1f\x8brest"), ContentType.GZIP)
        self.assertEqual(sniff(b"plain text\n"), ContentType.TEXT)
        self.assertEqual(sniff(b"\x00\x01\x02\x03binary"), ContentType.UNKNOWN)

    def test_archive_suffix_intent(self) -> None:
        self.assertTrue(sniff  # module-level sanity
                        )
        from coverage_scan.filetype import has_archive_suffix
        self.assertTrue(has_archive_suffix("broken.zip"))
        self.assertTrue(has_archive_suffix("x.tar.gz"))
        self.assertFalse(has_archive_suffix("x.txt"))


class SecretScanTests(unittest.TestCase):
    def test_finds_aws_and_github(self) -> None:
        stream = io.BytesIO(
            b"line one\nAKIAIOSFODNN7EXAMPLE\n"
            b"github ghp_" + b"a" * 40 + b"\n")
        hits = scan_stream(stream)
        rules = {h.rule_id for h in hits}
        self.assertIn("aws-access-key-id", rules)
        self.assertIn("github-pat", rules)

    def test_chunk_boundary_does_not_hide_secret(self) -> None:
        token = b"ghp_" + b"z" * 40
        # Pad so the token straddles the 1 MiB chunk boundary.
        pad = b"a" * (1024 * 1024 - 10)
        stream = io.BytesIO(pad + token + b"\n")
        hits = scan_stream(stream)
        self.assertTrue(any(h.rule_id == "github-pat" for h in hits))

    def test_clean_content_has_no_hits(self) -> None:
        self.assertEqual(scan_stream(io.BytesIO(b"nothing here\n")), [])


class ArchiveEventTests(unittest.TestCase):
    def test_truncated_zip_emits_open_failed(self) -> None:
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("a.txt", b"x" * 100)
        good = buf.getvalue()
        events = list(open_archive_stream(
            io.BytesIO(good[: len(good) // 2]), "x.zip", ContentType.ZIP))
        self.assertEqual(events[0].kind, "open_failed")

    def test_good_zip_streams_member_and_complete_end(self) -> None:
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("a.txt", b"hello")
        events = list(open_archive_stream(
            io.BytesIO(buf.getvalue()), "x.zip", ContentType.ZIP))
        kinds = [e.kind for e in events]
        self.assertIn("member", kinds)
        self.assertEqual(events[-1].kind, "end")
        self.assertTrue(events[-1].complete)

    def test_encrypted_member_is_read_failed(self) -> None:
        from tests.make_fixtures import _flip_encrypted_flag
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("plain.txt", b"ok")
            zf.writestr("locked.txt", b"no")
        raw = _flip_encrypted_flag(buf.getvalue(), b"locked.txt")
        events = list(open_archive_stream(
            io.BytesIO(raw), "x.zip", ContentType.ZIP))
        failed = [e for e in events if e.kind == "read_failed"]
        self.assertEqual(len(failed), 1)
        self.assertEqual(failed[0].error, "encrypted member")


class ReasonTaxonomyTests(unittest.TestCase):
    def test_four_distinct_codes(self) -> None:
        values = {r.value for r in SkipReason}
        self.assertEqual(
            values,
            {"size_limit", "no_permission", "unpack_failed", "unrecognized"})


if __name__ == "__main__":
    unittest.main(verbosity=2)

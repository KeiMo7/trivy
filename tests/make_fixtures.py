#!/usr/bin/env python3
"""Deterministic fixture factory for coverage-scan acceptance tests.

Creates, under a fresh empty directory, artifacts that exercise every skip
reason category and every report state. All content is generated here; nothing
is downloaded. Re-running the script regenerates byte-identical fixtures.

Layout produced:
    fixtures/
      clean-artifact/            fully readable, no findings
      secrets-artifact/          fully readable, contains secrets
      oversized-artifact/        one file past the size limit
      noperm-artifact/           one unreadable file (mode 000)
      truncated-zip.zip          zip cut in half
      truncated-tar.tar          tar cut in the middle
      truncated-gz.gz            gzip stream cut in half
      encrypted.zip              zip with an encrypted member flag
      deepnest.zip               archives nested past the depth limit
      unknown-blob/              private/unknown binary format
      corrupted-archive.zip      archive suffix, non-archive bytes
      mixed-batch/               one of each problem in a tree
      whole-fail/                a directory with a 000-mode subdirectory
      sensitive-paths/           paths containing key/secret/password strings
"""

from __future__ import annotations

import gzip
import io
import os
import shutil
import sys
import tarfile
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
FIXTURE_ROOT = ROOT / "fixtures"

SIZE_LIMIT = 4096  # keep fixtures tiny; tests pass a matching config


def reset() -> None:
    if FIXTURE_ROOT.exists():
        # Restore permissions first: fixtures intentionally contain 000-mode
        # files and directories to exercise NO_PERMISSION handling.
        for dirpath, dirnames, filenames in os.walk(FIXTURE_ROOT):
            for name in dirnames + filenames:
                try:
                    os.chmod(os.path.join(dirpath, name), 0o700)
                except OSError:
                    pass
        try:
            os.chmod(FIXTURE_ROOT, 0o700)
        except OSError:
            pass
        shutil.rmtree(FIXTURE_ROOT)
    FIXTURE_ROOT.mkdir(parents=True)


def write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)


def make_clean() -> None:
    base = FIXTURE_ROOT / "clean-artifact"
    write(base / "README.txt", b"plain readable text\nsecond line\n")
    write(base / "docs" / "notes.md", b"# notes\nnothing sensitive here\n")
    write(base / "empty.dat", b"")


def make_secrets() -> None:
    base = FIXTURE_ROOT / "secrets-artifact"
    write(base / "config.ini",
          b"[default]\naws_key = AKIAIOSFODNN7EXAMPLE\n")
    write(base / "token.txt",
          b"github: ghp_" + b"a" * 36 + b"\n")
    write(base / "key.pem",
          b"-----BEGIN RSA PRIVATE KEY-----\nFAKEKEYMATERIAL\n-----END RSA PRIVATE KEY-----\n")


def make_oversized() -> None:
    base = FIXTURE_ROOT / "oversized-artifact"
    write(base / "small.txt", b"small and readable\n")
    write(base / "huge.bin", b"A" * (SIZE_LIMIT * 2))
    write(base / "nested" / "also-huge.log", b"B" * (SIZE_LIMIT * 3))


def make_noperm() -> None:
    base = FIXTURE_ROOT / "noperm-artifact"
    write(base / "readable.txt", b"you can read me\n")
    locked = base / "locked.bin"
    write(locked, b"unreadable content\n")
    locked.chmod(0o000)


def make_truncated_zip() -> None:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for i in range(4):
            zf.writestr(f"pkg/module{i}.txt", (f"payload-{i}-" * 40).encode())
        zf.writestr("pkg/readme.txt", b"zip readme\n")
    raw = buf.getvalue()
    write(FIXTURE_ROOT / "truncated-zip.zip", raw[: len(raw) // 2])


def make_truncated_tar() -> None:
    # Keep the whole container under the fixture size limit: size-limit and
    # unpack-failure must be independently reproducible, so this sample must
    # trip truncation, not the size threshold. tarfile pads output to a fixed
    # 10 KiB block size; strip the trailing zero blocks (two 512-byte end
    # markers plus block padding) and cut the member stream in half instead.
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w", format=tarfile.USTAR_FORMAT) as tf:
        for i in range(4):
            payload = (f"tar-payload-{i}-" * 12).encode()
            info = tarfile.TarInfo(f"package/entry{i}.bin")
            info.size = len(payload)
            tf.addfile(info, io.BytesIO(payload))
    raw = buf.getvalue().rstrip(b"\x00")
    raw = raw[: (len(raw) // 2)]  # cut mid-member -> ReadError on open/iterate
    assert len(raw) <= SIZE_LIMIT, f"tar fixture too large: {len(raw)}"
    write(FIXTURE_ROOT / "truncated-tar.tar", raw)


def make_truncated_gzip() -> None:
    raw = gzip.compress(b"compressed body\n" * 20)
    assert len(raw) <= SIZE_LIMIT
    write(FIXTURE_ROOT / "truncated-gz.gz", raw[: len(raw) // 2])


def _flip_encrypted_flag(raw: bytes, member_name: bytes) -> bytes:
    """Set the encrypted flag bit (bit 0) in both local and central headers.

    zipfile.ZipInfo.flag_bits is populated from the central directory, while
    extraction consults the local header -- both must agree for the fixture to
    behave like a genuinely encrypted entry without needing a crypto library.
    Headers are located by signature rather than fixed offsets because local
    and central directory headers have different prefix lengths.
    """
    import struct

    blob = bytearray(raw)
    touched = 0
    # Scan for every header signature; local headers are followed by variable
    # compressed payloads, so length-based walking from a local header cannot
    # find the next record reliably.
    positions = []
    cursor = 0
    while True:
        idx = blob.find(b"PK\x03\x04", cursor)
        if idx < 0:
            break
        positions.append(("local", idx))
        cursor = idx + 4
    cursor = 0
    while True:
        idx = blob.find(b"PK\x01\x02", cursor)
        if idx < 0:
            break
        positions.append(("central", idx))
        cursor = idx + 4

    for kind, pos in positions:
        if kind == "local":
            name_len = struct.unpack_from("<H", blob, pos + 26)[0]
            name = bytes(blob[pos + 30:pos + 30 + name_len])
            if name == member_name:
                blob[pos + 6] |= 0x1
                touched += 1
        else:
            # Central directory header: fixed prefix is 46 bytes; filename
            # length sits at offset 28, filename itself starts at offset 46.
            name_len = struct.unpack_from("<H", blob, pos + 28)[0]
            extra_len = struct.unpack_from("<H", blob, pos + 30)[0]
            comment_len = struct.unpack_from("<H", blob, pos + 32)[0]
            name = bytes(blob[pos + 46:pos + 46 + name_len])
            if name == member_name:
                blob[pos + 8] |= 0x1  # flags at offset 8 in central headers
                touched += 1
    if touched != 2:
        raise RuntimeError(
            f"expected to flag 2 headers for {member_name!r}, touched {touched}")
    return bytes(blob)


def make_member_truncated_tar() -> None:
    """Tar whose final member header is intact but whose body is cut short.

    Distinct from make_truncated_tar: the failure surfaces lazily inside
    ExFileObject.read() (tarfile.ReadError) rather than at tf.next(), which is
    the path that previously escaped the event model entirely.
    """
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w", format=tarfile.USTAR_FORMAT) as tf:
        good = b"first-good-member\n"
        info = tarfile.TarInfo("good.txt")
        info.size = len(good)
        tf.addfile(info, io.BytesIO(good))
        body = b"X" * 2000
        broken = tarfile.TarInfo("broken.txt")
        broken.size = len(body)
        tf.addfile(broken, io.BytesIO(body))
    raw = buf.getvalue()
    name_idx = raw.find(b"broken.txt")
    header = (name_idx // 512) * 512
    # Keep the full 512-byte header plus only 50 bytes of the 2000-byte body.
    cut = raw[: header + 512 + 50].rstrip(b"\x00")
    assert len(cut) <= SIZE_LIMIT * 2
    write(FIXTURE_ROOT / "member-truncated.tar", cut)


def make_encrypted_zip() -> None:
    """Flip the encrypted flag bit on one member without needing a crypto lib."""
    path = FIXTURE_ROOT / "encrypted.zip"
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("plain.txt", b"ordinary member\n")
        zf.writestr("secret-archive/notes.txt", b"should be inaccessible\n")
    write(path, _flip_encrypted_flag(buf.getvalue(),
                                     b"secret-archive/notes.txt"))


def make_deep_nest() -> None:
    # Build innermost-first: a text file, then wrap in zip repeatedly.
    inner = b"deeply nested readable text\n"
    blob = inner
    depth = 11
    for level in range(depth):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr(f"level{depth - level}.txt",
                        f"marker level {level}\n".encode())
            zf.writestr("nested.bin", blob)
        blob = buf.getvalue()
    write(FIXTURE_ROOT / "deepnest.zip", blob)


def make_unknown_blob() -> None:
    base = FIXTURE_ROOT / "unknown-blob"
    # Bytes with no recognized signature and a private extension.
    write(base / "data.xyz", bytes(range(1, 250)) * 4)
    write(base / "proprietary.zzz", b"\x89\x01\x02\x03" + b"\xff" * 512)
    write(base / "nested" / "mystery.bin", b"\xfe\xed\xfa\xce" + b"\x00" * 256)


def make_corrupted_archive() -> None:
    write(FIXTURE_ROOT / "corrupted-archive.zip",
          b"this claims to be a zip but is just text\n" * 10)


def make_mixed_batch() -> None:
    base = FIXTURE_ROOT / "mixed-batch"
    write(base / "ok" / "readme.txt", b"all good here\n")
    write(base / "big" / "overflow.bin", b"C" * (SIZE_LIMIT * 2))
    locked = base / "noaccess" / "id_rsa_prod"
    write(locked, b"fake private key path fixture\n")
    locked.chmod(0o000)
    # Truncated zip inside the tree.
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("inner/a.txt", b"x" * 4000)
        zf.writestr("inner/b.txt", b"y" * 4000)
    raw = buf.getvalue()
    write(base / "packs" / "broken.zip", raw[: len(raw) // 2])
    write(base / "weird" / "object.qqq", b"\xaa\xbb\xcc" + b"\x00" * 300)


def make_whole_fail() -> None:
    base = FIXTURE_ROOT / "whole-fail"
    write(base / "top.txt", b"visible\n")
    locked_dir = base / "vault"
    locked_dir.mkdir(parents=True, exist_ok=True)
    write(locked_dir / "inside.txt", b"hidden behind directory permissions\n")
    locked_dir.chmod(0o000)


def make_sensitive_paths() -> None:
    base = FIXTURE_ROOT / "sensitive-paths"
    write(base / ".ssh" / "id_rsa", b"fake key material for redaction test\n")
    write(base / ".aws" / "credentials", b"[default]\naws_access_key_id=test\n")
    write(base / "deploy" / "password-store.env", b"TOKEN=abc\n")
    write(base / "deploy" / "normal.txt", b"ordinary\n")
    # Two unreadable sensitive names so redaction is exercised on paths that
    # actually reach the report's abandoned section.
    locked_key = base / "secrets" / "id_rsa_prod"
    write(locked_key, b"fake locked key\n")
    locked_key.chmod(0o000)
    locked_env = base / "deploy" / "password.prod.env"
    write(locked_env, b"TOKEN=locked\n")
    locked_env.chmod(0o000)


def main() -> int:
    reset()
    make_clean()
    make_secrets()
    make_oversized()
    make_noperm()
    make_truncated_zip()
    make_truncated_tar()
    make_member_truncated_tar()
    make_truncated_gzip()
    make_encrypted_zip()
    make_deep_nest()
    make_unknown_blob()
    make_corrupted_archive()
    make_mixed_batch()
    make_whole_fail()
    make_sensitive_paths()
    print(f"fixtures written under {FIXTURE_ROOT}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

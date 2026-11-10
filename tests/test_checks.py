"""Tests for ServerZEN's native checks.

Run:  python serverzen/tests/test_checks.py    (plain, stdlib only)
Or:   pytest serverzen/tests/test_checks.py
"""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from serverzen.checks import run_file  # noqa: E402


def _checks(source: str):
    return {f.check for f in run_file("x.py", source)}


def test_weak_hash_flags_md5():
    assert "weak-hash-for-security" in _checks("import hashlib\nhashlib.md5(b'x')\n")


def test_weak_hash_respects_usedforsecurity_false():
    assert "weak-hash-for-security" not in _checks(
        "import hashlib\nhashlib.md5(b'x', usedforsecurity=False)\n"
    )


def test_weak_hash_flags_hashlib_new_md5():
    assert "weak-hash-for-security" in _checks("import hashlib\nhashlib.new('md5')\n")


def test_weak_hash_ignores_sha256():
    assert "weak-hash-for-security" not in _checks("import hashlib\nhashlib.sha256(b'x')\n")


def test_egress_flags_raw_httpx():
    assert "unguarded-egress" in _checks("import httpx\nhttpx.AsyncClient(timeout=5)\n")


def test_egress_flags_urlopen():
    assert "unguarded-egress" in _checks("import urllib.request\nurllib.request.urlopen(u)\n")


def test_egress_excused_when_safe_wrapper_present():
    # A file that routes egress through a recognised SSRF-safe wrapper is not flagged.
    src = (
        "import httpx\n"
        "from mnemos.core.safe_http import make_safe_client\n"
        "client, _ = make_safe_client(url)\n"
        "httpx.AsyncClient(timeout=5)\n"
    )
    assert "unguarded-egress" not in _checks(src)


def test_egress_ignores_non_http_calls():
    assert "unguarded-egress" not in _checks("x = dict(a=1)\nopen('f').read()\n")


def _run_all() -> int:
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    failed = 0
    for fn in tests:
        try:
            fn()
            print(f"  PASS  {fn.__name__}")
        except AssertionError as exc:
            failed += 1
            print(f"  FAIL  {fn.__name__}  -- {exc!r}")
    print(f"\n{len(tests) - failed}/{len(tests)} checks passed")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(_run_all())

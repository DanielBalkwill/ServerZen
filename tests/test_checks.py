"""Tests for ServerZEN's native checks.

Run:  python serverzen/tests/test_checks.py    (plain, stdlib only)
Or:   pytest serverzen/tests/test_checks.py
"""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from serverzen.checks import run_file  # noqa: E402
from serverzen.sarif import findings_to_sarif  # noqa: E402


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


def test_unsafe_deser_flags_pickle():
    assert "unsafe-deserialization" in _checks("import pickle\npickle.loads(b)\n")


def test_unsafe_deser_flags_yaml_load():
    assert "unsafe-deserialization" in _checks("import yaml\nyaml.load(t)\n")


def test_unsafe_deser_allows_yaml_safe_load():
    assert "unsafe-deserialization" not in _checks("import yaml\nyaml.safe_load(t)\n")


def test_unsafe_deser_allows_json():
    assert "unsafe-deserialization" not in _checks("import json\njson.loads(b)\n")


def test_unverified_tls_flags_verify_false():
    assert "unverified-tls" in _checks("import requests\nrequests.get(u, verify=False)\n")


def test_unverified_tls_allows_default():
    assert "unverified-tls" not in _checks("import requests\nrequests.get(u)\n")


def test_sarif_output_is_well_formed():
    findings = run_file("x.py", "import hashlib\nhashlib.md5(b'x')\n")
    doc = findings_to_sarif(findings)
    assert doc["version"] == "2.1.0"
    assert doc["runs"][0]["tool"]["driver"]["name"] == "ServerZEN"
    assert len(doc["runs"][0]["results"]) == len(findings) >= 1


def test_dangerous_exec_flags_eval():
    assert "dangerous-exec" in _checks("eval(user_input)\n")


def test_dangerous_exec_flags_shell_true():
    assert "dangerous-exec" in _checks("import subprocess\nsubprocess.run(cmd, shell=True)\n")


def test_dangerous_exec_allows_arg_list():
    assert "dangerous-exec" not in _checks("import subprocess\nsubprocess.run(['ls', '-l'])\n")


def test_hardcoded_secret_flags_openai_key():
    assert "hardcoded-secret" in _checks('KEY = "sk-ABCdef0123456789ABCdef0123456789"\n')


def test_hardcoded_secret_ignores_plain_string():
    assert "hardcoded-secret" not in _checks('greeting = "hello world"\n')


def test_prompt_injection_surface_flags_fstring_prompt():
    assert "prompt-injection-surface" in _checks('system_prompt = f"You are an agent. Context: {memory}"\n')


def test_prompt_injection_surface_flags_kwarg():
    assert "prompt-injection-surface" in _checks('llm(messages=f"{user_text}")\n')


def test_prompt_injection_surface_ignores_plain_fstring():
    assert "prompt-injection-surface" not in _checks('greeting = f"hello {name}"\n')


def test_finding_dict_has_cwe_and_owasp():
    from serverzen.checks import finding_dict
    findings = run_file("x.py", "import hashlib\nhashlib.md5(b'x')\n")
    d = finding_dict(findings[0])
    assert d["cwe"] and d["owasp"] and d["remediation"]


def test_api_scan_source_flags_eval():
    from serverzen import scan_source
    assert any(f.check == "dangerous-exec" for f in scan_source("eval(x)\n"))


def test_api_is_safe_gate():
    from serverzen import is_safe
    assert is_safe(code="x = 1\n") is True
    assert is_safe(code="eval(x)\n", fail_on="HIGH") is False


def test_api_findings_as_dicts_enriched():
    from serverzen import findings_as_dicts, scan_source
    ds = findings_as_dicts(scan_source("eval(x)\n"))
    assert ds and "cwe" in ds[0] and "remediation" in ds[0]


def test_mcp_module_imports_without_mcp_dep():
    # The module must import even when the optional 'mcp' package is absent;
    # if 'mcp' IS installed, build_server() must construct successfully.
    import importlib.util
    from serverzen import mcp_server
    assert hasattr(mcp_server, "run_stdio")
    if importlib.util.find_spec("mcp") is not None:
        assert mcp_server.build_server() is not None


def test_posture_grade_clean_is_A():
    from serverzen.report import posture_grade
    assert posture_grade([]) == "A"


def test_markdown_report_has_grade_and_metadata():
    from serverzen.report import to_markdown
    findings = run_file("x.py", "import hashlib\nhashlib.md5(b'x')\n")
    md = to_markdown(findings, "x.py")
    assert "Posture grade" in md and "weak-hash-for-security" in md and "CWE-328" in md


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

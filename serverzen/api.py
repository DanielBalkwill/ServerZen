"""Programmatic API for embedding ServerZEN in agent pipelines and CI scripts.

The headline use case: an agent generates code, and you want to check it before
running it.

    from serverzen import scan_source, is_safe

    if not is_safe(code=generated_code, fail_on="HIGH"):
        raise RuntimeError("refusing to run unsafe generated code")

    for f in scan_source(generated_code):
        print(f.severity, f.check, f.message)
"""
from __future__ import annotations

import os

from serverzen.checks import DEFAULT_SAFE_MARKERS, Finding, finding_dict, run_file

_SKIP_DIRS = {".git", "__pycache__", ".venv", "venv", "node_modules", "build",
              "dist", ".mypy_cache", ".pytest_cache", ".ruff_cache"}
_SEVERITY_ORDER = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3}


def _iter_py_files(root: str):
    if os.path.isfile(root):
        if root.endswith(".py"):
            yield root
        return
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS]
        for name in filenames:
            if name.endswith(".py"):
                yield os.path.join(dirpath, name)


def scan_source(code: str, *, filename: str = "<generated>",
                safe_markers=DEFAULT_SAFE_MARKERS) -> list[Finding]:
    """Scan a string of Python source (e.g. agent-generated code). No file I/O."""
    return run_file(filename, code, safe_markers=safe_markers)


def scan_path(root: str, *, safe_markers=DEFAULT_SAFE_MARKERS) -> list[Finding]:
    """Scan a file or directory on disk; returns findings sorted by severity."""
    findings: list[Finding] = []
    for path in _iter_py_files(root):
        try:
            with open(path, encoding="utf-8", errors="replace") as fh:
                source = fh.read()
        except OSError:
            continue
        findings += run_file(path, source, safe_markers=safe_markers)
    findings.sort(key=lambda f: (-_SEVERITY_ORDER.get(f.severity, 0), f.check, f.path, f.line))
    return findings


def findings_as_dicts(findings: list[Finding]) -> list[dict]:
    """Findings as JSON-serializable dicts, enriched with CWE / OWASP / remediation."""
    return [finding_dict(f) for f in findings]


def is_safe(*, code: str | None = None, path: str | None = None,
            fail_on: str = "HIGH", safe_markers=DEFAULT_SAFE_MARKERS) -> bool:
    """True if scanning ``code`` or ``path`` yields nothing at/above ``fail_on``.

    Designed as an agent gate: ``if not is_safe(code=generated): ...``.
    """
    if code is not None:
        findings = scan_source(code, safe_markers=safe_markers)
    elif path is not None:
        findings = scan_path(path, safe_markers=safe_markers)
    else:
        raise ValueError("pass code= or path=")
    floor = _SEVERITY_ORDER[fail_on]
    return not any(_SEVERITY_ORDER.get(f.severity, 0) >= floor for f in findings)

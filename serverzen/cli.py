"""ServerZEN command-line interface.

    serverzen scan <path> [--json] [--min-severity LEVEL] [--safe-marker NAME]
    serverzen version

`scan` runs ServerZEN's native, dependency-free checks over the Python under
<path> and prints a findings table (or JSON). Report-only by default; use
--fail-on to make it exit non-zero for CI gating.
"""
from __future__ import annotations

import argparse
import dataclasses
import json
import os
import sys

from serverzen import __version__
from serverzen.checks import Finding, DEFAULT_SAFE_MARKERS, run_file

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


def scan(root: str, *, safe_markers=DEFAULT_SAFE_MARKERS) -> list[Finding]:
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


def _print_table(findings: list[Finding]) -> None:
    from collections import Counter
    by_check = Counter(f.check for f in findings)
    by_sev = Counter(f.severity for f in findings)
    print(f"ServerZEN {__version__} - {len(findings)} finding(s)")
    if findings:
        sev = ", ".join(f"{k} {by_sev[k]}" for k in ("HIGH", "MEDIUM", "LOW", "INFO") if by_sev.get(k))
        print(f"  severity: {sev}")
        print(f"  by check: " + ", ".join(f"{k} {v}" for k, v in sorted(by_check.items())))
        print()
        for f in findings:
            loc = f"{f.path}:{f.line}"
            print(f"  [{f.severity:<6}] {f.check}")
            print(f"            {loc}")
            print(f"            {f.message}")
    else:
        print("  no findings")


def _cmd_scan(args: argparse.Namespace) -> int:
    markers = tuple(DEFAULT_SAFE_MARKERS) + tuple(args.safe_marker or ())
    findings = scan(args.path, safe_markers=markers)
    if args.min_severity:
        floor = _SEVERITY_ORDER[args.min_severity]
        findings = [f for f in findings if _SEVERITY_ORDER.get(f.severity, 0) >= floor]
    if args.json:
        print(json.dumps([dataclasses.asdict(f) for f in findings], indent=2))
    else:
        _print_table(findings)
    if args.fail_on:
        floor = _SEVERITY_ORDER[args.fail_on]
        if any(_SEVERITY_ORDER.get(f.severity, 0) >= floor for f in findings):
            return 1
    return 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="serverzen", description="Security toolkit for AI-agent memory runtimes.")
    sub = parser.add_subparsers(dest="command")

    p_scan = sub.add_parser("scan", help="run ServerZEN's native checks over a path")
    p_scan.add_argument("path", help="file or directory to scan")
    p_scan.add_argument("--json", action="store_true", help="emit findings as JSON")
    p_scan.add_argument("--min-severity", choices=list(_SEVERITY_ORDER), help="only show findings at/above this severity")
    p_scan.add_argument("--fail-on", choices=list(_SEVERITY_ORDER), help="exit 1 if any finding is at/above this severity (CI gate)")
    p_scan.add_argument("--safe-marker", action="append", help="extra SSRF-safe-wrapper name to recognise (repeatable)")
    p_scan.set_defaults(func=_cmd_scan)

    sub.add_parser("version", help="print the ServerZEN version")

    args = parser.parse_args(argv)
    if args.command in (None,):
        parser.print_help()
        return 0
    if args.command == "version":
        print(f"serverzen {__version__}")
        return 0
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())

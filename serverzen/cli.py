"""ServerZEN command-line interface.

    serverzen scan <path> [--format table|json|sarif] [-o FILE]
                          [--min-severity LEVEL] [--fail-on LEVEL] [--safe-marker NAME]
    serverzen version

`scan` runs ServerZEN's native, dependency-free checks over the Python under
<path>. Report-only by default; `--fail-on` makes it exit non-zero for CI.
"""
from __future__ import annotations

import argparse
import json

from serverzen import __version__
from serverzen import report
from serverzen.api import scan_path
from serverzen.checks import CHECK_META, DEFAULT_SAFE_MARKERS, Finding, finding_dict
from serverzen.sarif import findings_to_sarif

_SEVERITY_ORDER = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3}


def _render_table(findings: list[Finding]) -> str:
    from collections import Counter
    by_check = Counter(f.check for f in findings)
    by_sev = Counter(f.severity for f in findings)
    lines = [f"ServerZEN {__version__} - {len(findings)} finding(s)"]
    if not findings:
        lines.append("  no findings")
        return "\n".join(lines)
    sev = ", ".join(f"{k} {by_sev[k]}" for k in ("HIGH", "MEDIUM", "LOW", "INFO") if by_sev.get(k))
    lines.append(f"  severity: {sev}")
    lines.append("  by check: " + ", ".join(f"{k} {v}" for k, v in sorted(by_check.items())))
    lines.append("")
    for f in findings:
        meta = CHECK_META.get(f.check, {})
        tag = " / ".join(x for x in (meta.get("cwe", ""), meta.get("owasp", ""), meta.get("atlas", "")) if x)
        lines.append(f"  [{f.severity:<6}] {f.check}" + (f"  ({tag})" if tag else ""))
        lines.append(f"            {f.path}:{f.line}")
        lines.append(f"            {f.message}")
    return "\n".join(lines)


def _cmd_scan(args: argparse.Namespace) -> int:
    markers = tuple(DEFAULT_SAFE_MARKERS) + tuple(args.safe_marker or ())
    findings = scan_path(args.path, safe_markers=markers)
    if args.min_severity:
        floor = _SEVERITY_ORDER[args.min_severity]
        findings = [f for f in findings if _SEVERITY_ORDER.get(f.severity, 0) >= floor]

    fmt = "json" if args.json else args.format
    if fmt == "json":
        out = json.dumps([finding_dict(f) for f in findings], indent=2)
    elif fmt == "sarif":
        out = json.dumps(findings_to_sarif(findings), indent=2)
    elif fmt == "markdown":
        out = report.to_markdown(findings, args.path)
    else:
        out = _render_table(findings)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(out + "\n")
        print(f"wrote {len(findings)} finding(s) to {args.output} ({fmt})")
    else:
        print(out)

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
    p_scan.add_argument("--format", choices=["table", "json", "sarif", "markdown"], default="table",
                        help="output format (default: table)")
    p_scan.add_argument("-o", "--output", help="write output to FILE instead of stdout")
    p_scan.add_argument("--json", action="store_true", help="shortcut for --format json")
    p_scan.add_argument("--min-severity", choices=list(_SEVERITY_ORDER), help="only show findings at/above this severity")
    p_scan.add_argument("--fail-on", choices=list(_SEVERITY_ORDER), help="exit 1 if any finding is at/above this severity (CI gate)")
    p_scan.add_argument("--safe-marker", action="append", help="extra SSRF-safe-wrapper name to recognise (repeatable)")
    p_scan.set_defaults(func=_cmd_scan)

    sub.add_parser("version", help="print the ServerZEN version")
    sub.add_parser("mcp", help="run the MCP server over stdio (needs the 'mcp' extra)")

    args = parser.parse_args(argv)
    if args.command is None:
        parser.print_help()
        return 0
    if args.command == "version":
        print(f"serverzen {__version__}")
        return 0
    if args.command == "mcp":
        from serverzen import mcp_server
        mcp_server.run_stdio()
        return 0
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())

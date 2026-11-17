"""Human-readable security-posture overview (Markdown) for ServerZEN findings.

Turns a flat list of findings into an at-a-glance overview: a posture grade, a
severity summary, a by-check table with CWE/OWASP, and grouped findings with
remediation — the "overview" a reviewer or an agent wants, not just a log.
"""
from __future__ import annotations

from collections import Counter

from serverzen import __version__
from serverzen.checks import CHECK_META, Finding

# Rough risk weighting for an at-a-glance grade.
_WEIGHT = {"HIGH": 10, "MEDIUM": 3, "LOW": 1, "INFO": 0}


def risk_score(findings: list[Finding]) -> int:
    return sum(_WEIGHT.get(f.severity, 0) for f in findings)


def posture_grade(findings: list[Finding]) -> str:
    s = risk_score(findings)
    if s == 0:
        return "A"
    if s <= 5:
        return "B"
    if s <= 15:
        return "C"
    if s <= 30:
        return "D"
    return "F"


def to_markdown(findings: list[Finding], target: str) -> str:
    sev = Counter(f.severity for f in findings)
    by_check = Counter(f.check for f in findings)
    lines: list[str] = []
    lines.append("# ServerZEN security overview")
    lines.append("")
    lines.append(f"- **Target:** `{target}`")
    lines.append(f"- **Scanner:** ServerZEN {__version__}")
    lines.append(f"- **Posture grade:** **{posture_grade(findings)}**  "
                 f"(risk score {risk_score(findings)})")
    lines.append(f"- **Findings:** {len(findings)}  "
                 f"- HIGH {sev.get('HIGH', 0)}, MEDIUM {sev.get('MEDIUM', 0)}, "
                 f"LOW {sev.get('LOW', 0)}, INFO {sev.get('INFO', 0)}")
    lines.append("")
    if not findings:
        lines.append("No findings. :white_check_mark:")
        return "\n".join(lines)

    lines.append("## By check")
    lines.append("")
    lines.append("| Check | CWE | OWASP | ATLAS | Count |")
    lines.append("| --- | --- | --- | --- | --- |")
    for check, n in sorted(by_check.items(), key=lambda kv: (-kv[1], kv[0])):
        m = CHECK_META.get(check, {})
        lines.append(f"| `{check}` | {m.get('cwe', '')} | {m.get('owasp', '')} | {m.get('atlas', '')} | {n} |")
    lines.append("")

    lines.append("## Findings")
    for level in ("HIGH", "MEDIUM", "LOW", "INFO"):
        group = [f for f in findings if f.severity == level]
        if not group:
            continue
        lines.append("")
        lines.append(f"### {level} ({len(group)})")
        for f in group:
            m = CHECK_META.get(f.check, {})
            conf = f" (confidence {f.confidence})" if f.confidence != "MEDIUM" else ""
            lines.append("")
            lines.append(f"- **`{f.check}`** - `{f.path}:{f.line}`{conf}")
            lines.append(f"  - {f.message}")
            tag = " / ".join(x for x in (m.get("cwe", ""), m.get("owasp", ""), m.get("atlas", "")) if x)
            if tag:
                lines.append(f"  - _{tag}_")
            if m.get("remediation"):
                lines.append(f"  - **Fix:** {m['remediation']}")
    lines.append("")
    return "\n".join(lines)

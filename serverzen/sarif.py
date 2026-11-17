"""SARIF 2.1.0 output for ServerZEN findings.

SARIF is the standard static-analysis interchange format; emitting it lets
ServerZEN results flow into GitHub code scanning (the Security tab) and other
tools that ingest SARIF.
"""
from __future__ import annotations

from serverzen import __version__
from serverzen.checks import CHECK_META, Finding

# SARIF levels: error | warning | note.
_LEVEL = {"HIGH": "error", "MEDIUM": "warning", "LOW": "note", "INFO": "note"}


def findings_to_sarif(findings: list[Finding]) -> dict:
    rule_ids = sorted({f.check for f in findings})
    rules = []
    for rid in rule_ids:
        m = CHECK_META.get(rid, {})
        rules.append({
            "id": rid,
            "name": rid,
            "shortDescription": {"text": rid},
            "helpUri": "https://github.com/DanielBalkwill/ServerZen",
            "properties": {"cwe": m.get("cwe", ""), "owasp": m.get("owasp", ""),
                           "atlas": m.get("atlas", ""),
                           "tags": [t for t in (m.get("cwe", ""), m.get("atlas", "")) if t]},
        })
    results = []
    for f in findings:
        results.append({
            "ruleId": f.check,
            "level": _LEVEL.get(f.severity, "warning"),
            "message": {"text": f.message},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": f.path.replace("\\", "/")},
                    "region": {"startLine": max(1, f.line)},
                }
            }],
            "properties": {"severity": f.severity, "confidence": f.confidence,
                           "cwe": CHECK_META.get(f.check, {}).get("cwe", ""),
                           "atlas": CHECK_META.get(f.check, {}).get("atlas", "")},
        })
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "ServerZEN",
                "informationUri": "https://github.com/DanielBalkwill/ServerZen",
                "version": __version__,
                "rules": rules,
            }},
            "results": results,
        }],
    }

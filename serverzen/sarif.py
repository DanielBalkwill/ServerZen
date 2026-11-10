"""SARIF 2.1.0 output for ServerZEN findings.

SARIF is the standard static-analysis interchange format; emitting it lets
ServerZEN results flow into GitHub code scanning (the Security tab) and other
tools that ingest SARIF.
"""
from __future__ import annotations

from serverzen import __version__
from serverzen.checks import Finding

# SARIF levels: error | warning | note.
_LEVEL = {"HIGH": "error", "MEDIUM": "warning", "LOW": "note", "INFO": "note"}


def findings_to_sarif(findings: list[Finding]) -> dict:
    rule_ids = sorted({f.check for f in findings})
    rules = [{"id": rid, "name": rid, "shortDescription": {"text": rid}} for rid in rule_ids]
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
            "properties": {"severity": f.severity},
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

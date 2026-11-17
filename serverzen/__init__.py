"""ServerZEN — a security toolkit for AI-agent memory runtimes.

Generic SAST/DAST does not understand the attack surface specific to
agent-memory services — prompt-injection via stored memory, multi-tenant
isolation drift, SSRF in webhook/federation egress, and audit-chain integrity.
ServerZEN adds domain-specific checks for those classes and an opinionated
scanning pipeline. MNEMOS is the reference target the checks were derived from
(see the case study), not part of ServerZEN.
"""

__version__ = "0.4.0"

from serverzen.api import findings_as_dicts, is_safe, scan_path, scan_source  # noqa: E402
from serverzen.checks import Finding  # noqa: E402

__all__ = [
    "__version__", "Finding",
    "scan_source", "scan_path", "findings_as_dicts", "is_safe",
]

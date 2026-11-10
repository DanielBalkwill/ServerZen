"""ServerZEN — a security toolkit for AI-agent memory runtimes.

Generic SAST/DAST does not understand the attack surface specific to
agent-memory services — prompt-injection via stored memory, multi-tenant
isolation drift, SSRF in webhook/federation egress, and audit-chain integrity.
ServerZEN adds domain-specific checks for those classes and an opinionated
scanning pipeline. MNEMOS is the reference target the checks were derived from
(see the case study), not part of ServerZEN.
"""

__version__ = "0.2.0"

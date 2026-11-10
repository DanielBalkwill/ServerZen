"""ServerZEN native security checks for AI-agent memory runtimes.

Dependency-free AST checks that encode the vulnerability classes ServerZEN
targets — the ones generic scanners miss or mis-prioritize for an agent-memory
service. Each check yields :class:`Finding` records. The checks are deliberately
advisory (they surface candidates); triage decides. That split — flag broadly,
triage precisely — is the lesson baked in from the reference assessment.
"""
from __future__ import annotations

import ast
from dataclasses import dataclass


@dataclass(frozen=True)
class Finding:
    check: str
    severity: str  # HIGH | MEDIUM | LOW | INFO
    path: str
    line: int
    message: str


def _dotted(node: ast.AST) -> str:
    """Return the dotted name of an attribute/name chain (e.g. httpx.AsyncClient)."""
    parts: list[str] = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
    return ".".join(reversed(parts))


# ── Check 1: weak hash possibly used for security ────────────────────────────
# Maps to the audit-integrity / backup-crypto classes in the reference
# assessment (e.g. MD5/SHA-1 without usedforsecurity=False). Advisory: a HIGH
# from a generic scanner here is often a transport checksum — ServerZEN surfaces
# it for triage rather than asserting exploitability.
_WEAK_HASH_NAMES = {"md5", "sha1", "hashlib.md5", "hashlib.sha1"}
_WEAK_HASH_NEW = {"new", "hashlib.new"}


def _has_usedforsecurity_false(call: ast.Call) -> bool:
    for kw in call.keywords:
        if kw.arg == "usedforsecurity" and isinstance(kw.value, ast.Constant) and kw.value.value is False:
            return True
    return False


def check_weak_hash(tree: ast.AST, path: str, source: str) -> list[Finding]:
    out: list[Finding] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        name = _dotted(node.func)
        algo = None
        if name in _WEAK_HASH_NAMES:
            algo = name.rsplit(".", 1)[-1]
        elif name in _WEAK_HASH_NEW and node.args:
            first = node.args[0]
            if isinstance(first, ast.Constant) and isinstance(first.value, str) and first.value.lower() in {"md5", "sha1"}:
                algo = first.value.lower()
        if algo and not _has_usedforsecurity_false(node):
            out.append(Finding(
                check="weak-hash-for-security",
                severity="MEDIUM",
                path=path,
                line=node.lineno,
                message=(f"{algo.upper()} constructed without usedforsecurity=False - "
                         f"review whether it is security-load-bearing; if a non-security "
                         f"checksum, pass usedforsecurity=False."),
            ))
    return out


# ── Check 2: unguarded outbound HTTP (SSRF surface) ──────────────────────────
# Maps to the SSRF/egress class. An agent-memory runtime makes outbound calls
# (webhooks, federation, providers); each must pass through an SSRF-validating,
# DNS-pinning client. ServerZEN flags raw HTTP clients in files that do not go
# through a known safe wrapper.
_EGRESS_SUFFIXES = (
    "httpx.AsyncClient", "httpx.Client", "httpx.get", "httpx.post", "httpx.put",
    "httpx.delete", "httpx.patch", "httpx.request", "httpx.stream",
    "requests.get", "requests.post", "requests.put", "requests.delete",
    "requests.patch", "requests.head", "requests.request", "requests.Session",
    "request.urlopen", "aiohttp.ClientSession",
)
#: If a file references any of these, treat its egress as guarded. Projects can
#: extend this via the CLI (--safe-marker) to match their own wrapper's name.
DEFAULT_SAFE_MARKERS = (
    "make_safe_client", "validate_webhook_url", "PinnedDNSAsyncHTTPTransport", "safe_http",
)


def _matches_egress(dotted: str) -> bool:
    if dotted == "urlopen":
        return True
    return any(dotted == s or dotted.endswith("." + s) for s in _EGRESS_SUFFIXES)


def check_unguarded_egress(tree: ast.AST, path: str, source: str, *, safe_markers=DEFAULT_SAFE_MARKERS) -> list[Finding]:
    if any(marker in source for marker in safe_markers):
        return []  # file routes egress through a known SSRF-safe wrapper
    out: list[Finding] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and _matches_egress(_dotted(node.func)):
            out.append(Finding(
                check="unguarded-egress",
                severity="MEDIUM",
                path=path,
                line=node.lineno,
                message=(f"outbound HTTP via {_dotted(node.func)}() in a file with no "
                         f"SSRF-safe wrapper ({', '.join(safe_markers)}) - confirm the URL "
                         f"is not attacker-influenced, or route it through the safe client."),
            ))
    return out


# ── Check 3: unsafe deserialization ──────────────────────────────────────────
# Agent-memory runtimes ingest/import memories and bundles from outside the
# trust boundary; a pickle/marshal/yaml.load over untrusted bytes is remote
# code execution.
def check_unsafe_deserialization(tree: ast.AST, path: str, source: str) -> list[Finding]:
    out: list[Finding] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        name = _dotted(node.func)
        if name.endswith(("pickle.load", "pickle.loads", "cPickle.load",
                          "cPickle.loads", "marshal.load", "marshal.loads")):
            out.append(Finding("unsafe-deserialization", "HIGH", path, node.lineno,
                f"{name}() deserializes arbitrary objects - remote code execution on "
                f"untrusted input; use JSON or a vetted schema instead."))
        elif name.endswith(("yaml.load", "yaml.unsafe_load", "yaml.full_load")):
            safe = any(kw.arg == "Loader" and "Safe" in _dotted(kw.value) for kw in node.keywords)
            if not (name.endswith("yaml.load") and safe):
                out.append(Finding("unsafe-deserialization", "MEDIUM", path, node.lineno,
                    f"{name}() without a SafeLoader can execute arbitrary tags; use yaml.safe_load()."))
    return out


# ── Check 4: disabled TLS verification ───────────────────────────────────────
def check_unverified_tls(tree: ast.AST, path: str, source: str) -> list[Finding]:
    out: list[Finding] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        for kw in node.keywords:
            if kw.arg == "verify" and isinstance(kw.value, ast.Constant) and kw.value.value is False:
                out.append(Finding("unverified-tls", "HIGH", path, node.lineno,
                    "TLS certificate verification disabled (verify=False) - exposes the "
                    "request to interception / a forged endpoint."))
        if _dotted(node.func).endswith("ssl._create_unverified_context"):
            out.append(Finding("unverified-tls", "HIGH", path, node.lineno,
                "ssl._create_unverified_context() disables certificate validation."))
    return out


ALL_CHECKS = (check_weak_hash, check_unguarded_egress,
              check_unsafe_deserialization, check_unverified_tls)


def run_file(path: str, source: str, *, safe_markers=DEFAULT_SAFE_MARKERS) -> list[Finding]:
    """Parse ``source`` and run every check; returns [] on a syntax error."""
    try:
        tree = ast.parse(source, filename=path)
    except SyntaxError:
        return []
    findings: list[Finding] = []
    findings += check_weak_hash(tree, path, source)
    findings += check_unguarded_egress(tree, path, source, safe_markers=safe_markers)
    findings += check_unsafe_deserialization(tree, path, source)
    findings += check_unverified_tls(tree, path, source)
    return findings

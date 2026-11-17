"""ServerZEN native security checks for AI-agent memory runtimes.

Dependency-free AST checks that encode the vulnerability classes ServerZEN
targets — the ones generic scanners miss or mis-prioritize for an agent-memory
service. Each check yields :class:`Finding` records. The checks are deliberately
advisory (they surface candidates); triage decides. That split — flag broadly,
triage precisely — is the lesson baked in from the reference assessment.
"""
from __future__ import annotations

import ast
import re
from dataclasses import asdict, dataclass


@dataclass(frozen=True)
class Finding:
    check: str
    severity: str  # HIGH | MEDIUM | LOW | INFO
    path: str
    line: int
    message: str
    confidence: str = "MEDIUM"  # HIGH | MEDIUM | LOW


# Per-check metadata: CWE, OWASP mapping, and remediation guidance — surfaced in
# reports so every finding carries context, not just a one-line message.
CHECK_META: dict[str, dict[str, str]] = {
    "unguarded-egress": {"cwe": "CWE-918", "owasp": "API7:2023 (SSRF)",
        "remediation": "Route outbound HTTP through an SSRF-validating, DNS-pinning client."},
    "weak-hash-for-security": {"cwe": "CWE-328", "owasp": "A02:2021",
        "remediation": "Use SHA-256+; pass usedforsecurity=False for non-security checksums."},
    "unsafe-deserialization": {"cwe": "CWE-502", "owasp": "A08:2021",
        "remediation": "Use JSON or yaml.safe_load; never unpickle untrusted bytes."},
    "unverified-tls": {"cwe": "CWE-295", "owasp": "A07:2021",
        "remediation": "Remove verify=False; validate TLS certificates."},
    "dangerous-exec": {"cwe": "CWE-78 / CWE-95", "owasp": "A03:2021",
        "remediation": "Avoid eval/exec/os.system/shell=True; use argument lists and allow-lists."},
    "hardcoded-secret": {"cwe": "CWE-798", "owasp": "A05:2021",
        "remediation": "Move secrets to env vars / a secret store; rotate anything committed."},
    "prompt-injection-surface": {"cwe": "CWE-1427", "owasp": "LLM01:2025 (Prompt Injection)",
        "atlas": "AML.T0051",
        "remediation": "Frame stored/user/tool content as untrusted DATA in prompts; never let it change instructions."},
    "agent-tool-capability": {"cwe": "CWE-250", "owasp": "LLM08:2025 (Excessive Agency)",
        "remediation": "Constrain tool capabilities; validate inputs; require human approval for state-changing or code-executing actions."},
    "tool-poisoning": {"cwe": "CWE-1427", "owasp": "LLM01:2025 (Prompt Injection)", "atlas": "AML.T0051",
        "remediation": "Treat third-party tool descriptions/schemas as untrusted; pin and review them; isolate untrusted MCP servers."},
}
# NOTE: MITRE ATLAS ids are seeded for the AI-specific checks (prompt injection);
# verify/expand against the current ATLAS matrix (see docs/ROADMAP.md).


def finding_dict(f: Finding) -> dict:
    """Finding as a dict, enriched with its check's CWE / OWASP / remediation."""
    d = asdict(f)
    meta = CHECK_META.get(f.check, {})
    d["cwe"] = meta.get("cwe", "")
    d["owasp"] = meta.get("owasp", "")
    d["atlas"] = meta.get("atlas", "")
    d["remediation"] = meta.get("remediation", "")
    return d


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


# ── Check 5: dangerous dynamic execution ─────────────────────────────────────
# Agents increasingly generate and run code; eval/exec/shell=True over any
# influenced string is code/command injection.
def check_dangerous_exec(tree: ast.AST, path: str, source: str) -> list[Finding]:
    out: list[Finding] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        name = _dotted(node.func)
        if name in ("eval", "exec") or name.endswith(("os.system", "os.popen")):
            out.append(Finding("dangerous-exec", "HIGH", path, node.lineno,
                f"{name}() executes a dynamic string - code/command injection if any part is "
                f"attacker- or LLM-influenced."))
        elif name.endswith(("subprocess.run", "subprocess.call", "subprocess.Popen",
                            "subprocess.check_call", "subprocess.check_output")):
            if any(kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True
                   for kw in node.keywords):
                out.append(Finding("dangerous-exec", "HIGH", path, node.lineno,
                    f"{name}(shell=True) runs via the shell - command injection if the command "
                    f"string is influenced by input."))
    return out


# ── Check 6: hardcoded secrets ───────────────────────────────────────────────
_SECRET_PATTERNS = [
    (re.compile(r"sk-[A-Za-z0-9]{20,}"), "OpenAI-style API key"),
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "AWS access key id"),
    (re.compile(r"\bghp_[A-Za-z0-9]{36}\b"), "GitHub token"),
    (re.compile(r"\bgithub_pat_[A-Za-z0-9_]{22,}"), "GitHub fine-grained token"),
    (re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}"), "Slack token"),
    (re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"), "Google API key"),
    (re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----"), "private key"),
]


def check_hardcoded_secret(tree: ast.AST, path: str, source: str) -> list[Finding]:
    out: list[Finding] = []
    for i, line in enumerate(source.splitlines(), start=1):
        for pat, label in _SECRET_PATTERNS:
            if pat.search(line):
                out.append(Finding("hardcoded-secret", "HIGH", path, i,
                    f"Possible hardcoded {label} - move it to env/secret storage and rotate if committed.",
                    confidence="HIGH"))
                break
    return out


# ── Check 7: prompt-injection surface (OWASP LLM01) ──────────────────────────
# AI-agent-specific: a variable interpolated into an LLM prompt string. If that
# variable carries stored memory / user input / tool output, it must be framed
# as untrusted data, not concatenated straight into instructions.
_PROMPT_NAMES = ("prompt", "system", "instruction")
_PROMPT_KW = ("prompt", "system", "system_prompt", "messages", "content", "instructions")


def _fstring_with_var(node: ast.AST) -> bool:
    return isinstance(node, ast.JoinedStr) and any(isinstance(v, ast.FormattedValue) for v in node.values)


def check_prompt_injection_surface(tree: ast.AST, path: str, source: str) -> list[Finding]:
    out: list[Finding] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign) and _fstring_with_var(node.value):
            names = [t.id.lower() for t in node.targets if isinstance(t, ast.Name)]
            if any(p in n for n in names for p in _PROMPT_NAMES):
                out.append(Finding("prompt-injection-surface", "MEDIUM", path, node.lineno,
                    "Value interpolated into an LLM prompt string - if it carries stored/user/tool "
                    "content, frame it as untrusted data to resist prompt injection (OWASP LLM01).",
                    confidence="LOW"))
        if isinstance(node, ast.Call):
            for kw in node.keywords:
                if kw.arg in _PROMPT_KW and _fstring_with_var(kw.value):
                    out.append(Finding("prompt-injection-surface", "MEDIUM", path, node.lineno,
                        f"Interpolated value passed to '{kw.arg}=' of an LLM call - frame untrusted "
                        f"content as data to resist prompt injection (OWASP LLM01).",
                        confidence="LOW"))
    return out


# ── Checks 8 & 9: agent / MCP tool risks (OWASP LLM08 / LLM01) ────────────────
# AI-agent-native. A function registered as an agent or MCP tool is callable by
# the model, so it carries two risks a generic scanner has no concept of:
#   * excessive agency - the tool can DO dangerous things (run code, shell out,
#     reach the network, touch the filesystem); and
#   * tool poisoning - its description/schema can be crafted to steer the agent.
_TOOL_POISON_RE = re.compile(
    r"(?i)(ignore\s+(all\s+|the\s+|your\s+|previous\s+|above\s+|prior\s+)*"
    r"(instruction|prompt|rule)|you\s+are\s+now\b|disregard\s+(the|all|previous|prior)"
    r"|do\s+not\s+(tell|inform|mention|reveal)|system\s+prompt|</?\s*system\s*>)"
)


def _is_agent_tool(func: ast.AST) -> bool:
    """True if a function is registered as an agent/MCP tool via a decorator
    (`@server.tool()`, `@mcp.tool`, `@tool`, `@function_tool`, ...)."""
    for dec in getattr(func, "decorator_list", []):
        target = dec.func if isinstance(dec, ast.Call) else dec
        name = _dotted(target)
        if name.rsplit(".", 1)[-1] in ("tool", "function_tool") or name.endswith(".tool"):
            return True
    return False


def check_agent_tool_capability(tree: ast.AST, path: str, source: str) -> list[Finding]:
    out: list[Finding] = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) or not _is_agent_tool(node):
            continue
        caps: set[str] = set()
        high = False
        for sub in ast.walk(node):
            if not isinstance(sub, ast.Call):
                continue
            nm = _dotted(sub.func)
            if nm in ("eval", "exec") or nm.endswith(("os.system", "os.popen")):
                caps.add("runs shell / dynamic code"); high = True
            elif nm.endswith(("subprocess.run", "subprocess.call", "subprocess.Popen",
                             "subprocess.check_call", "subprocess.check_output")):
                caps.add("spawns subprocesses"); high = True
            elif _matches_egress(nm):
                caps.add("makes outbound network calls")
            elif nm == "open":
                caps.add("accesses the filesystem")
        if caps:
            out.append(Finding("agent-tool-capability", "HIGH" if high else "MEDIUM", path, node.lineno,
                f"LLM-invocable tool '{node.name}' {', '.join(sorted(caps))} - excessive agency "
                f"(OWASP LLM08): validate inputs and require human approval for dangerous actions."))
    return out


def check_tool_description_injection(tree: ast.AST, path: str, source: str) -> list[Finding]:
    out: list[Finding] = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) or not _is_agent_tool(node):
            continue
        doc = ast.get_docstring(node)
        if doc and _TOOL_POISON_RE.search(doc):
            out.append(Finding("tool-poisoning", "HIGH", path, node.lineno,
                f"Tool '{node.name}' description contains agent-directed instruction phrasing "
                f"(possible tool poisoning) - a crafted tool description can hijack the calling agent."))
    return out


ALL_CHECKS = (check_weak_hash, check_unguarded_egress, check_unsafe_deserialization,
              check_unverified_tls, check_dangerous_exec, check_hardcoded_secret,
              check_prompt_injection_surface, check_agent_tool_capability,
              check_tool_description_injection)


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
    findings += check_dangerous_exec(tree, path, source)
    findings += check_hardcoded_secret(tree, path, source)
    findings += check_prompt_injection_surface(tree, path, source)
    findings += check_agent_tool_capability(tree, path, source)
    findings += check_tool_description_injection(tree, path, source)
    return findings

# ServerZEN

**Static security analysis for AI agents & MCP.**

[![CI](https://github.com/DanielBalkwill/ServerZen/actions/workflows/ci.yml/badge.svg)](https://github.com/DanielBalkwill/ServerZen/actions/workflows/ci.yml) [![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE) ![Python 3.9+](https://img.shields.io/badge/python-3.9%2B-blue.svg) ![Status](https://img.shields.io/badge/status-v0.4.0%20alpha-orange.svg) ![Core deps](https://img.shields.io/badge/core%20deps-none-brightgreen.svg)

Generic SAST/DAST (Bandit, Semgrep, CodeQL) scan Python — but they don't
understand the *agent-memory* attack surface: prompt-injection via stored
memory, multi-tenant isolation drift, SSRF in webhook/federation egress, and
audit-chain integrity. So they under- or over-report exactly where it matters:
every `httpx`/`urllib` call is flagged identically whether or not it is
SSRF-guarded, and a transport-checksum MD5 is reported as a HIGH. **ServerZEN
adds domain-specific checks and an opinionated pipeline tuned for these
services.**

## The gap it fills

Static analysis that **understands agent code** — the questions a general-purpose
scanner can't ask:

- *Is this outbound call SSRF-guarded, or wide open?*
- *Is untrusted memory / tool output flowing into an LLM prompt?*
- *What can this agent tool actually do if the model is tricked into calling it?*

That niche is genuinely under-tooled — **especially for MCP**. ServerZEN doesn't
try to out-Bandit Bandit on generic checks (you'd lose to teams with hundreds of
rules); it **owns the AI-agent layer** those scanners don't model.

> Status: **v0.4** — nine native checks (incl. **agent/MCP tool risks**), each
> mapped to CWE / OWASP / **MITRE ATLAS**; output as table / JSON / SARIF /
> Markdown (A–F posture grade); a **Python API** and an **MCP server**; a Semgrep
> ruleset and a bundled test app.

## What it does

Native, dependency-free checks (`serverzen scan`, stdlib only):

| Check | What it finds | Why it's domain-aware |
|---|---|---|
| `unguarded-egress` | raw outbound HTTP (`httpx` / `requests` / `urllib` / `aiohttp`) in a file that does **not** route through an SSRF-safe wrapper | egress behind a recognised safe client (DNS-pinning, validate-then-connect) is **not** flagged — unlike a generic scanner that flags all egress |
| `weak-hash-for-security` | weak hashes (`md5`/`sha1`) built without `usedforsecurity=False` | surfaced for **triage**, not asserted as exploitable — the backup/transport-checksum case is the common false positive |
| `unsafe-deserialization` | `pickle` / `marshal` / `yaml.load` over untrusted bytes | agent-memory runtimes import memories & bundles from outside the trust boundary — a pickle load there is RCE |
| `unverified-tls` | `verify=False` or an unverified SSL context | provider / federation calls with certificate checking turned off |
| `dangerous-exec` | `eval` / `exec` / `os.system` / `subprocess(shell=True)` | agents that run generated code — any influenced string is code/command injection |
| `hardcoded-secret` | committed API keys / tokens / private keys (OpenAI, AWS, GitHub, Slack, Google) | credentials in source |
| `prompt-injection-surface` | stored/user/tool content interpolated into an LLM prompt | the AI-native risk (OWASP LLM01) a generic scanner has no concept of |
| `agent-tool-capability` | an LLM-invocable tool (`@tool`/`@mcp.tool`) that shells out, execs, hits the network, or touches the filesystem | **excessive agency** (LLM08) — the "what can this tool actually do?" question |
| `tool-poisoning` | an agent/MCP tool whose description contains instructions aimed at the model | **tool poisoning** — a crafted tool description hijacking the agent |

Output as **table, JSON, SARIF** (GitHub Security tab), or a **Markdown posture
report** (A–F grade + CWE/OWASP per finding). Plus a **custom Semgrep ruleset**
(`rules/`) for deeper patterns, and a CI recipe.

## Install & use

```bash
pip install -e .                 # or: pipx install .
serverzen scan path/to/code
serverzen scan path/to/code --min-severity MEDIUM
serverzen scan path/to/code --format markdown       # posture report (A-F grade)
serverzen scan path/to/code --format sarif -o serverzen.sarif  # GitHub Security tab
serverzen scan path/to/code --fail-on HIGH          # CI gate (exit 1)
serverzen scan path/to/code --safe-marker my_client # teach it your SSRF wrapper
```

No install needed to try it: `python -m serverzen scan path/to/code`.

**Try the bundled test app:** `serverzen scan examples/vulnerable` (findings) vs.
`serverzen scan examples/guarded` (clean). Full recipes — CI gate, pre-commit,
GitHub Actions — are in [`docs/USAGE.md`](docs/USAGE.md).

## Use it in an agent workflow

**Python API** — scan code an agent just generated, before running it:

```python
from serverzen import is_safe
if not is_safe(code=generated_code, fail_on="HIGH"):
    raise RuntimeError("ServerZEN blocked unsafe generated code")
```

**MCP server** — expose ServerZEN as a tool to Claude Desktop / Claude Code / Cursor:

```bash
pip install 'serverzen[mcp]'
serverzen mcp
```

Full API + MCP config in [`docs/AGENTIC.md`](docs/AGENTIC.md).

## Scale it out (PySpark)

The core is a fast single-machine scanner — but because every check is a pure
`run_file(path, source)` function, the same analysis distributes cleanly across a
Spark cluster to scan an entire **code estate** (thousands of repos, a monorepo,
an object-store bucket) in one job:

```bash
pip install 'serverzen[spark]'
python -m serverzen.spark ./path/to/repos --out findings.parquet
```

You get a typed findings DataFrame (CWE/OWASP/ATLAS columns) plus a per-file,
A–F posture summary whose grades match the single-node tool. Architecture,
cluster/object-store usage, **when *not* to reach for Spark**, and a learning
roadmap: [`docs/SPARK.md`](docs/SPARK.md). _(Optional extra — `import serverzen`
never pulls PySpark.)_

## Reference case study — MNEMOS

ServerZEN's checks were derived from a full, independent security assessment of
**MNEMOS**, an open-source AI-agent memory runtime (Apache-2.0, by Jason Perlow /
`ncz-os`). MNEMOS is the **reference target** the checks were built from and
demonstrated against — it is **not** part of ServerZEN. Run against that codebase:

- It automatically re-surfaces the assessment's real signal — the STYX backup
  MD5 (`mnemos/tools/styx/crypto.py:96`) and the unguarded provider/adapter
  egress.
- It correctly **does not** flag `mnemos/webhooks/sender.py` or
  `mnemos/domain/federation.py`: those route egress through the project's
  SSRF-safe, DNS-pinning client. That context-awareness is the whole point — a
  generic scanner flags every egress site identically and buries the signal.

The full assessment — threat model, findings with remediations, verified-secure
controls, and a DevSecOps pipeline — is maintained as a separate case study. Its
specific vulnerability details are held for **coordinated disclosure** and will
be published only after the upstream maintainer has had time to remediate.

## Roadmap

Next bets: **MCP config/schema scanning**, **framework rule packs** (LangChain,
CrewAI, AutoGen, …), **taint tracking** (untrusted source → prompt/exec sink),
expanded **MITRE ATLAS** coverage, and a **PyPI release**. The full phased plan
with checkpoints is in [`docs/ROADMAP.md`](docs/ROADMAP.md).

## License

MIT — ServerZEN is original work. The reference target (MNEMOS) is a separate
project under its own Apache-2.0 license; see [`NOTICE`](NOTICE).

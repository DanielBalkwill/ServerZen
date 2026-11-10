# ServerZEN

**A security toolkit for AI-agent memory runtimes.**

[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE) ![Python 3.9+](https://img.shields.io/badge/python-3.9%2B-blue.svg) ![Status](https://img.shields.io/badge/status-v0.1.0%20alpha-orange.svg) ![Core deps](https://img.shields.io/badge/core%20deps-none-brightgreen.svg)

Generic SAST/DAST (Bandit, Semgrep, CodeQL) scan Python — but they don't
understand the *agent-memory* attack surface: prompt-injection via stored
memory, multi-tenant isolation drift, SSRF in webhook/federation egress, and
audit-chain integrity. So they under- or over-report exactly where it matters:
every `httpx`/`urllib` call is flagged identically whether or not it is
SSRF-guarded, and a transport-checksum MD5 is reported as a HIGH. **ServerZEN
adds domain-specific checks and an opinionated pipeline tuned for these
services.**

> Status: **v0.1** — native checks + CLI, with a custom Semgrep ruleset and a
> reference case study. Roadmap below.

## What it does

Native, dependency-free checks (`serverzen scan`, stdlib only):

| Check | What it finds | Why it's domain-aware |
|---|---|---|
| `unguarded-egress` | raw outbound HTTP (`httpx` / `requests` / `urllib` / `aiohttp`) in a file that does **not** route through an SSRF-safe wrapper | egress behind a recognised safe client (DNS-pinning, validate-then-connect) is **not** flagged — unlike a generic scanner that flags all egress |
| `weak-hash-for-security` | weak hashes (`md5`/`sha1`) built without `usedforsecurity=False` | surfaced for **triage**, not asserted as exploitable — the backup/transport-checksum case is the common false positive |

Plus a **custom Semgrep ruleset** (`rules/`) for deeper patterns, and a CI recipe.

## Install & use

```bash
pip install -e .                 # or: pipx install .
serverzen scan path/to/code
serverzen scan path/to/code --min-severity MEDIUM --json
serverzen scan path/to/code --fail-on HIGH          # CI gate (exit 1)
serverzen scan path/to/code --safe-marker my_client # teach it your SSRF wrapper
```

No install needed to try it: `python -m serverzen scan path/to/code`.

## Reference case study — MNEMOS

ServerZEN's checks were derived from a full, independent security assessment of
**MNEMOS**, an open-source AI-agent memory runtime (Apache-2.0, by Jason Perlow /
`ncz-os`). MNEMOS is the **reference target** the checks were built from and
demonstrated against — it is **not** part of ServerZEN. Running v0.1 against it:

```
ServerZEN 0.1.0 — 36 finding(s)
  by check: unguarded-egress 35, weak-hash-for-security 1
```

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

- **More checks:** tenant-isolation predicate coverage; prompt-injection-defense
  coverage on memory→prompt paths; audit-chain integrity checks;
  secret-redaction coverage.
- **SARIF output** → GitHub Security tab; **aggregation** with Bandit / Semgrep /
  pip-audit / gitleaks / Trivy into one report.
- **Rule packs** per runtime (MNEMOS, and others as they emerge).

## License

MIT — ServerZEN is original work. The reference target (MNEMOS) is a separate
project under its own Apache-2.0 license; see [`NOTICE`](NOTICE).

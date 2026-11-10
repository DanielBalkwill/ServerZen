# Using ServerZEN

ServerZEN scans a Python codebase for the security weaknesses specific to
AI-agent memory runtimes. This page shows how to run it — on the bundled test
app, on your own code, and in CI.

## Install

```bash
# From a clone (an editable install gives you the `serverzen` command):
git clone https://github.com/DanielBalkwill/ServerZen && cd ServerZen
pip install -e .
serverzen version

# Or run with no install, from the repo root:
python -m serverzen scan <path>
```

## 1. Try the bundled test environment

The repo ships a tiny vulnerable/guarded sample so you can see it work:

```bash
serverzen scan examples/vulnerable     # 6 findings across all 4 checks
serverzen scan examples/guarded        # 0 findings — the same features, written safely
```

That contrast is the point: a generic scanner flags the egress and the MD5 in
*both*; ServerZEN flags `vulnerable/` and stays quiet on `guarded/`.

## 2. Scan your own test environment

Point it at any Python project or service you control:

```bash
serverzen scan ~/code/my-memory-service
serverzen scan .                       # the current directory
serverzen scan path/to/one_file.py     # a single file
```

Two flags make it precise for your codebase:

- `--min-severity MEDIUM` hides lower-signal findings.
- `--safe-marker my_safe_client` teaches ServerZEN the name of *your* SSRF-safe
  HTTP wrapper, so egress routed through it isn't flagged.

```bash
serverzen scan . --min-severity MEDIUM --safe-marker my_safe_client
```

## 3. Output formats

```bash
serverzen scan . --format table                  # human-readable (default)
serverzen scan . --format json  -o findings.json
serverzen scan . --format sarif -o serverzen.sarif
```

SARIF feeds GitHub's Security tab and other code-scanning dashboards.

## 4. Fail a build (CI gate)

```bash
serverzen scan . --fail-on HIGH     # exit 1 if any HIGH finding exists
```

Report-only by default (exit 0); `--fail-on` turns it into a gate.

## 5. Pre-commit hook

In `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: local
    hooks:
      - id: serverzen
        name: ServerZEN scan
        entry: serverzen scan
        language: system
        pass_filenames: false
        args: ["--fail-on", "HIGH", "."]
```

## 6. GitHub Actions

```yaml
name: ServerZEN
on: [push, pull_request]
permissions:
  contents: read
  security-events: write   # to upload SARIF to the Security tab
jobs:
  serverzen:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with: { python-version: "3.12" }
      - run: pip install -e .
      - run: serverzen scan . --format sarif -o serverzen.sarif
      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with: { sarif_file: serverzen.sarif }
      - run: serverzen scan . --fail-on HIGH   # gate the build
```

## 7. The Semgrep ruleset (optional, deeper patterns)

```bash
pip install semgrep
semgrep --config rules examples/vulnerable
```

## What it checks (v0.2)

| Check | Severity | Finds |
|---|---|---|
| `unguarded-egress` | MEDIUM | raw outbound HTTP not behind an SSRF-safe wrapper (context-aware) |
| `weak-hash-for-security` | MEDIUM | `md5`/`sha1` without `usedforsecurity=False` |
| `unsafe-deserialization` | HIGH/MED | `pickle`/`marshal`/`yaml.load` over untrusted input |
| `unverified-tls` | HIGH | `verify=False` / unverified SSL context |

Every check is advisory — it surfaces candidates for triage; you decide.

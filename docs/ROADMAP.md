# ServerZEN roadmap

**Mission:** own one lane — *static security analysis for AI agents and MCP*. Be
the tool that **understands agent code** (is this egress SSRF-guarded? is
untrusted memory flowing into a prompt? what can this tool actually do?) — not
another runtime guardrail or model red-teamer.

Phases are ordered roughly by leverage, not locked sequence. Each lists concrete
checkpoints.

## Phase 1 — Foundation ✅ (shipped)

- 9 native, dependency-free checks, including agent/MCP tool risks
  (`agent-tool-capability`, `tool-poisoning`).
- Every finding mapped to **CWE / OWASP** (incl. the OWASP LLM Top 10) **/ MITRE ATLAS**.
- Output as table / JSON / SARIF / **Markdown posture report** (A–F grade).
- **Python API** (`scan_source`, `is_safe`) and an **MCP server**.
- Self-CI, a bundled vulnerable/guarded test app, and a Semgrep ruleset.

## Phase 2 — MCP depth  (the headline bet)

- [ ] Scan **MCP config files** (`claude_desktop_config.json`, `.mcp.json`,
      `.cursor/mcp.json`) for risky servers and over-broad commands.
- [ ] **Tool-schema analysis** beyond Python: JSON tool definitions — unvalidated
      args, dangerous parameter types, missing constraints.
- [ ] Deepen **tool-poisoning**: hidden-unicode / encoded instructions,
      description-vs-behaviour mismatch, "rug-pull" (mutable tool definitions).
- [ ] **Capability policy**: declare allowed capabilities per tool; flag drift.

## Phase 3 — Framework rule packs

- [ ] Insecure-pattern packs for **LangChain, LlamaIndex, CrewAI, AutoGen,
      OpenAI Agents, Anthropic tool-use**: REPL/shell tools reachable from
      untrusted input, unframed memory → prompt, dangerous actions with no
      human-in-the-loop.
- [ ] `--framework` auto-detection and targeted rules.

## Phase 4 — Taint tracking  (the "exponentiate" step)

- [ ] Intra-procedural **data-flow**: untrusted **sources** (user input, tool
      output, retrieved memory, web/HTTP responses) → prompt / exec / SQL **sinks**.
- [ ] Upgrade `prompt-injection-surface` and `agent-tool-capability` from
      heuristic to taint-backed (higher confidence, fewer false positives).

## Phase 5 — Knowledge-base enrichment

- [ ] Expand and **verify MITRE ATLAS** mappings against the current matrix; map
      each agent control point (tool call, memory read, prompt build, action
      exec) to a named ATLAS / OWASP-LLM risk.
- [ ] **Bundled, updatable local DB** (Trivy/grype-style) of AI advisories / OSV
      data for AI libraries and model files — refreshed locally, **never
      per-scan network calls, never uploading scanned code**.

## Phase 6 — Distribution & developer experience

- [x] **Distributed scale-out** (PySpark) for scanning a whole code estate in one
      job — the pure checks fan across a cluster. See [`SPARK.md`](SPARK.md).
- [ ] **PyPI** release (`pip install serverzen`) + a published **GitHub Action**.
- [ ] **VS Code extension** for in-editor findings.
- [ ] **Baseline / suppression** (ignore triaged findings) and **autofix** hints.

## Non-goals (stay in the lane)

- Not a **runtime LLM firewall** (Lakera, NeMo Guardrails, LLM Guard).
- Not a **model red-teamer / eval** (garak, PyRIT, promptfoo).
- Not a **generic SAST** — defer to Bandit/Semgrep/CodeQL for non-agent checks;
  ServerZEN adds the agent-aware layer on top.

## Hard rules for every new feature

1. **Never send scanned code or prompts to an external service.** Look up *your*
   signatures locally; never upload *their* data.
2. Keep the core **fast, offline, zero-runtime-dependency**; enrichment stays
   local and optional.
3. Every check carries **CWE / OWASP / ATLAS** context and a remediation.

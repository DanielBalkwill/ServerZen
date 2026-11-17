# Using ServerZEN in agentic workflows

Two integration points: a **Python API** to embed in any agent or CI pipeline,
and an **MCP server** so an MCP-capable agent can call ServerZEN as a tool.

## Python API

```bash
pip install -e .        # or: pip install serverzen  (once published)
```

### Gate agent-generated code before running it

The headline use case — an agent writes Python, you check it before executing:

```python
from serverzen import is_safe

code = agent.generate_python(task)              # your agent's output
if not is_safe(code=code, fail_on="HIGH"):
    raise RuntimeError("ServerZEN blocked unsafe generated code")
exec(compile(code, "<agent>", "exec"))          # only runs if it passed
```

### Inspect findings

```python
from serverzen import scan_source, findings_as_dicts

for f in scan_source(code, filename="tool.py"):
    print(f.severity, f.check, f"{f.path}:{f.line}", "-", f.message)

payload = findings_as_dicts(scan_source(code))   # JSON-ready, with CWE/OWASP/remediation
```

### Scan a path on disk

```python
from serverzen import scan_path
findings = scan_path("src/")
```

**API surface:**
`scan_source(code, *, filename=..., safe_markers=...)` ·
`scan_path(root, *, safe_markers=...)` ·
`is_safe(*, code=..., path=..., fail_on="HIGH")` ·
`findings_as_dicts(findings)`.
Each `Finding` has `.check .severity .path .line .message .confidence`.

## MCP server (Claude Desktop, Claude Code, Cursor, ...)

ServerZEN ships an MCP server exposing two tools — `serverzen_scan_code` and
`serverzen_scan_path` — so an agent can scan code (or a path) as part of its
workflow, e.g. before it writes or runs something.

```bash
pip install 'serverzen[mcp]'
serverzen mcp          # runs over stdio
```

Add it to your MCP client's config as a stdio server:

**Claude Desktop** (`claude_desktop_config.json`) / generic MCP client:

```json
{
  "mcpServers": {
    "serverzen": { "command": "serverzen", "args": ["mcp"] }
  }
}
```

**Claude Code:**

```bash
claude mcp add serverzen -- serverzen mcp
```

**Cursor** (`.cursor/mcp.json` in your project, or global MCP settings):

```json
{
  "mcpServers": {
    "serverzen": { "command": "serverzen", "args": ["mcp"] }
  }
}
```

Once connected, the agent can call `serverzen_scan_code` with a snippet and get
a Markdown security report back. Tested against the `mcp` 2.x SDK (and
compatible with 1.x).

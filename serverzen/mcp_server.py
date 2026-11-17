"""ServerZEN as an MCP (Model Context Protocol) server.

Exposes ServerZEN as tools an MCP-capable agent (Claude Desktop, Cursor, Claude
Code, ...) can call in its workflow — most usefully, to scan code it is about to
write or run. Requires the optional `mcp` dependency:

    pip install 'serverzen[mcp]'
    serverzen mcp          # run over stdio

Wire it into a client's MCP config as a stdio server with command `serverzen`
and args `["mcp"]`.
"""
from __future__ import annotations


def _require_mcp() -> None:
    try:
        import mcp  # noqa: F401
    except ImportError as exc:  # pragma: no cover - exercised only without the extra
        raise SystemExit(
            "ServerZEN's MCP server needs the 'mcp' package. Install it with:\n"
            "    pip install 'serverzen[mcp]'"
        ) from exc


def build_server():
    """Build and return the MCP server with ServerZEN's tools registered.

    Supports both the mcp 2.x API (``MCPServer``) and the 1.x API (``FastMCP``);
    both expose the same ``@server.tool()`` decorator and ``server.run()``.
    """
    try:
        from mcp.server.mcpserver import MCPServer as _Server  # mcp >= 2.0
    except ImportError:  # pragma: no cover - mcp 1.x fallback
        from mcp.server.fastmcp import FastMCP as _Server  # mcp 1.x

    from serverzen.api import scan_path, scan_source
    from serverzen.report import to_markdown

    server = _Server("serverzen")

    @server.tool()
    def serverzen_scan_code(code: str, filename: str = "generated.py") -> str:
        """Scan a string of Python source for security issues and return a Markdown
        report. Covers: SSRF-prone egress, unsafe deserialization, dangerous exec
        (eval/exec/shell), hardcoded secrets, prompt-injection surface, weak hashes,
        and disabled TLS verification. Use before writing or running generated code."""
        return to_markdown(scan_source(code, filename=filename), filename)

    @server.tool()
    def serverzen_scan_path(path: str) -> str:
        """Scan a file or directory on disk for security issues and return a Markdown
        report (same checks as serverzen_scan_code)."""
        return to_markdown(scan_path(path), path)

    return server


def run_stdio() -> None:
    """Run the MCP server over stdio (the default transport)."""
    _require_mcp()
    build_server().run()

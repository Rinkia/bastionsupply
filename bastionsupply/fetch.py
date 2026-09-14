"""Load MCP tool definitions from three sources:

1. a JSON file (offline)   -- a `tools/list` dump, or {"tools":[...]}, or a list
2. a stdio MCP server      -- spawn it and speak JSON-RPC (stdlib only)
3. an MCP client config    -- discover servers from mcp.json / Claude config

Live fetch (2, 3) executes the server process. That is opt-in at the CLI.
"""

from __future__ import annotations

import json
import os
import shlex
import subprocess
from pathlib import Path

from .models import Server, Tool


# --------------------------------------------------------------------------- #
# offline: parse a tools/list JSON dump
# --------------------------------------------------------------------------- #
def tools_from_obj(obj) -> tuple[Tool, ...]:
    """Accept a list of tool dicts, or {"tools":[...]}, or a JSON-RPC result."""
    if isinstance(obj, dict):
        if "result" in obj and isinstance(obj["result"], dict):
            obj = obj["result"]
        obj = obj.get("tools", obj)
    if not isinstance(obj, list):
        raise ValueError("expected a list of tools or {'tools': [...]}")
    tools = []
    for row in obj:
        if not isinstance(row, dict) or "name" not in row:
            raise ValueError(f"bad tool row: {row!r}")
        tools.append(
            Tool(
                name=str(row["name"]),
                description=str(row.get("description", "")),
                input_schema=row.get("inputSchema") or row.get("input_schema") or {},
            )
        )
    return tuple(tools)


def load_json_file(path: str | Path, name: str | None = None) -> Server:
    p = Path(path)
    obj = json.loads(p.read_text(encoding="utf-8"))
    return Server(name=name or p.stem, tools=tools_from_obj(obj), source=str(p))


# --------------------------------------------------------------------------- #
# live: stdio MCP handshake (initialize -> initialized -> tools/list)
# --------------------------------------------------------------------------- #
_PROTOCOL = "2024-11-05"


def fetch_stdio(command: str, args=None, env=None, name="", timeout=20.0) -> Server:
    """Spawn a stdio MCP server, list its tools, shut it down.

    Executes `command`. Only call on servers you intend to run.
    """
    argv = [command, *(args or [])]
    proc = subprocess.Popen(
        argv,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        env={**os.environ, **(env or {})},
        text=True,
        bufsize=1,
    )
    try:
        _send(proc, 1, "initialize", {
            "protocolVersion": _PROTOCOL,
            "capabilities": {},
            "clientInfo": {"name": "bastionsupply", "version": "0"},
        })
        _read_result(proc, 1, timeout)
        _notify(proc, "notifications/initialized")
        _send(proc, 2, "tools/list", {})
        result = _read_result(proc, 2, timeout)
        tools = tools_from_obj(result)
        return Server(name=name or Path(command).stem, tools=tools, source=" ".join(argv))
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            proc.kill()


def _send(proc, mid, method, params) -> None:
    proc.stdin.write(json.dumps({"jsonrpc": "2.0", "id": mid, "method": method, "params": params}) + "\n")
    proc.stdin.flush()


def _notify(proc, method) -> None:
    proc.stdin.write(json.dumps({"jsonrpc": "2.0", "method": method}) + "\n")
    proc.stdin.flush()


def _read_result(proc, want_id, timeout):
    """Read newline-delimited JSON-RPC until the reply with id==want_id."""
    import time

    deadline = time.time() + timeout
    while time.time() < deadline:
        line = proc.stdout.readline()
        if not line:
            raise RuntimeError("MCP server closed the connection before replying")
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            continue  # server logging noise on stdout; skip
        if msg.get("id") == want_id:
            if "error" in msg:
                raise RuntimeError(f"MCP error: {msg['error']}")
            return msg.get("result", {})
    raise TimeoutError(f"no reply to id={want_id} within {timeout}s")


# --------------------------------------------------------------------------- #
# discovery: read an MCP client config's mcpServers map
# --------------------------------------------------------------------------- #
def discover_servers(config_path: str | Path) -> list[dict]:
    """Return [{name, command, args, env}] from an mcp.json / Claude config."""
    obj = json.loads(Path(config_path).read_text(encoding="utf-8"))
    servers = obj.get("mcpServers") or obj.get("servers") or {}
    out = []
    for name, spec in servers.items():
        if not isinstance(spec, dict) or "command" not in spec:
            continue  # skip URL-only / remote entries (see fetch_http TODO)
        out.append({
            "name": name,
            "command": spec["command"],
            "args": spec.get("args", []),
            "env": spec.get("env", {}),
        })
    return out


def parse_stdio_spec(spec: str) -> tuple[str, list[str]]:
    """Split a shell-ish 'cmd arg1 arg2' into (command, args)."""
    parts = shlex.split(spec, posix=(os.name != "nt"))
    if not parts:
        raise ValueError("empty --stdio spec")
    return parts[0], parts[1:]

# ponytail: HTTP/SSE transport not implemented — stdio covers the common
# locally-installed case. Add fetch_http() when a remote server needs scanning.

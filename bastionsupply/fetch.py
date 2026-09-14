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
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

from .models import Server, Tool

MAX_LINE = 5_000_000  # cap one JSON-RPC message (bytes) — bound memory vs a hostile server
MAX_HTTP_BODY = 10_000_000  # cap an HTTP response body


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """A malicious server must not bounce us to file:// or an internal address."""

    def redirect_request(self, *a, **k):
        return None


_OPENER = urllib.request.build_opener(
    _NoRedirect, urllib.request.HTTPHandler, urllib.request.HTTPSHandler
)


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
        schema = row.get("inputSchema") or row.get("input_schema") or {}
        if not isinstance(schema, dict):
            schema = {}  # hostile/malformed server: don't carry a non-dict schema
        tools.append(
            Tool(
                name=str(row["name"]),
                description=str(row.get("description", "")),
                input_schema=schema,
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
    """Read the reply with id==want_id, honoring `timeout` even if the server
    hangs mid-line. The blocking read runs in a thread we abandon on timeout;
    the caller's `finally` kills the process, which unblocks it.
    """
    box: dict = {}

    def work():
        try:
            box["v"] = _read_loop(proc, want_id, timeout)
        except BaseException as e:  # ferry any error back to the caller
            box["e"] = e

    th = threading.Thread(target=work, daemon=True)
    th.start()
    th.join(timeout + 1.0)
    if th.is_alive():
        raise TimeoutError(f"MCP server did not reply to id={want_id} within {timeout}s (hung)")
    if "e" in box:
        raise box["e"]
    return box["v"]


def _read_loop(proc, want_id, timeout):
    """Read newline-delimited JSON-RPC until the reply with id==want_id."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        line = proc.stdout.readline(MAX_LINE)
        if not line:
            raise RuntimeError("MCP server closed the connection before replying")
        if len(line) >= MAX_LINE and not line.endswith("\n"):
            raise RuntimeError("MCP server sent an oversized line (>5MB); aborting")
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
# live: HTTP (MCP Streamable HTTP) — initialize -> initialized -> tools/list
# --------------------------------------------------------------------------- #
def fetch_http(url: str, name: str = "", timeout: float = 20.0) -> Server:
    """Fetch tool definitions from a remote MCP Streamable-HTTP server.

    Contacts `url` over http/https only, never follows redirects (no SSRF to
    file:// or internal hosts), and caps the response body.
    """
    scheme = urllib.parse.urlparse(url).scheme
    if scheme not in ("http", "https"):
        raise ValueError(f"url must be http/https, got {scheme!r}")

    _obj, sid = _http_post(url, {
        "jsonrpc": "2.0", "id": 1, "method": "initialize",
        "params": {"protocolVersion": _PROTOCOL, "capabilities": {},
                   "clientInfo": {"name": "bastionsupply", "version": "0"}},
    }, None, timeout, want_id=1)
    # the initialized notification must carry the session id the server issued
    _http_post(url, {"jsonrpc": "2.0", "method": "notifications/initialized"}, sid, timeout)
    obj, _sid = _http_post(url, {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
                           sid, timeout, want_id=2)
    if not obj:
        raise RuntimeError("no tools/list response from server")
    if "error" in obj:
        raise RuntimeError(f"MCP error: {obj['error']}")
    tools = tools_from_obj(obj.get("result", obj))
    return Server(name=name or url, tools=tools, source=url)


def _http_post(url, msg, session, timeout, want_id=None):
    """POST one JSON-RPC message; return (reply_for_want_id_or_None, session_id).

    Handles JSON, JSON-RPC batch arrays, and multi-event SSE streams, picking the
    reply whose id matches `want_id`.
    """
    req = urllib.request.Request(
        url, data=json.dumps(msg).encode("utf-8"), method="POST",
        headers={"Content-Type": "application/json",
                 "Accept": "application/json, text/event-stream"},
    )
    if session:
        req.add_header("Mcp-Session-Id", session)
    try:
        resp = _OPENER.open(req, timeout=timeout)
    except urllib.error.HTTPError as e:
        raise RuntimeError(f"HTTP {e.code} from MCP server: {e.reason}") from e
    sid = resp.headers.get("Mcp-Session-Id") or session
    data = resp.read(MAX_HTTP_BODY)
    if not data:
        return None, sid  # e.g. 202 Accepted for a notification
    if resp.headers.get("Content-Type", "").startswith("text/event-stream"):
        msgs = _sse_messages(data)
    else:
        obj = json.loads(data)
        msgs = obj if isinstance(obj, list) else [obj]
    return _pick(msgs, want_id), sid


def _sse_messages(data: bytes) -> list:
    """All JSON-RPC messages across every event in an SSE stream (arrays flattened)."""
    msgs: list = []
    payload: list[str] = []

    def flush():
        if not payload:
            return
        try:
            obj = json.loads("\n".join(payload))
            msgs.extend(obj if isinstance(obj, list) else [obj])
        except json.JSONDecodeError:
            pass

    for line in data.decode("utf-8", "replace").splitlines():
        if line.startswith("data:"):
            payload.append(line[5:].lstrip())
        elif line == "":
            flush()
            payload = []
    flush()
    return msgs


def _pick(msgs: list, want_id):
    """The message matching want_id, else the first carrying a result/error."""
    if want_id is not None:
        for m in msgs:
            if isinstance(m, dict) and m.get("id") == want_id:
                return m
    for m in msgs:
        if isinstance(m, dict) and ("result" in m or "error" in m):
            return m
    return msgs[0] if msgs else None


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

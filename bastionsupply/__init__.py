"""bastionsupply — MCP supply-chain security scanner.

Static analysis of MCP server tool definitions: tool-poisoning, shadowing,
hidden unicode, secret solicitation, sensitive capabilities, and rug-pull
drift. The pre-flight leg of the bastion family (prevent / attack / investigate
/ scan) — feeds agentbastion policy via `harden`.

    from bastionsupply import load_json_file, scan, to_text
    report = scan(load_json_file("tools.json"))
    print(to_text(report))
"""

from __future__ import annotations

from .fetch import discover_servers, fetch_http, fetch_stdio, load_json_file, tools_from_obj
from .harden import to_policy_yaml
from .lockfile import make_lock, verify, write_lock
from .models import Finding, ScanReport, Server, Tool
from .report import to_json, to_text
from .scanner import scan

__version__ = "0.5.0"
__all__ = [
    "Tool",
    "Server",
    "Finding",
    "ScanReport",
    "scan",
    "load_json_file",
    "tools_from_obj",
    "fetch_stdio",
    "fetch_http",
    "discover_servers",
    "make_lock",
    "write_lock",
    "verify",
    "to_text",
    "to_json",
    "to_policy_yaml",
    "__version__",
]

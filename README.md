# bastionsupply

**MCP supply-chain security scanner.** Point it at an MCP server's tool
definitions and it flags the supply-chain attacks *before* you install:
tool-poisoning, tool-shadowing, hidden unicode, secret solicitation, dangerous
capabilities, and rug-pull drift.

The pre-flight leg of the **bastion family**:

| tool | job |
|------|-----|
| **bastionsupply** | **scan** an MCP server before you trust it |
| [agentbastion](https://github.com/Rinkia/agentbastion) | **prevent** — firewall around a running agent |
| [bastionprobe](https://github.com/Rinkia/bastionprobe) | **attack** — pentest your agent with injections |
| [bastiontrace](https://github.com/Rinkia/bastiontrace) | **investigate** — forensics on an agent trace |

No network, no LLM, no dependencies — pure static analysis of what a server
*claims about itself*, which is exactly where the attack hides.

## Install

```bash
pip install bastionsupply
```

## Use

```bash
# offline: scan a tools/list JSON dump
bastionsupply scan tools.json

# live: spawn a stdio MCP server and scan the tools it advertises
bastionsupply scan --stdio "npx -y @some/mcp-server" --live

# live: scan every server in an MCP client config
bastionsupply scan --config ~/.config/mcp.json --live

# rug-pull: pin tool hashes now, detect silent changes later
bastionsupply lock tools.json -o supply.lock
bastionsupply verify tools.json --lock supply.lock

# bridge: emit an agentbastion tool policy (default-deny, risky tools blocked)
bastionsupply harden tools.json -o policy.yaml
```

`scan` exits non-zero when anything **critical** or **high** is found — drop it
in CI to fail a build that pulls in a poisoned server.

## What it catches

| check | severity | what it means |
|-------|----------|---------------|
| `tool-poisoning` | critical | instructions aimed at the model — in the tool **description or a parameter** |
| `hidden-unicode` | critical | format / control / private-use chars (zero-width, bidi, tag) hiding in a name, description, **or parameter** |
| `homoglyph-name` | high | tool name mixes scripts (e.g. Cyrillic + Latin) — look-alike impersonation of another tool |
| `tool-shadowing` | high | a tool's description talks about *other* tools — hijacking their behavior |
| `secret-solicitation` | high | a parameter asks the model to hand over an api_key / token / password |
| `sensitive-capability` | high/med | tool exposes exec, delete, network, secret-read, or privilege escalation |
| rug-pull (`verify`) | — | tool definitions changed since you pinned them |

## Library

```python
from bastionsupply import load_json_file, scan, to_text, to_policy_yaml

report = scan(load_json_file("tools.json"))
print(to_text(report))
print("safe" if report.ok else "risky", report.risk)
```

## Live fetch note

`--stdio` / `--config --live` **spawn the server process** to call
`tools/list`. Only run them on servers you intend to execute. Offline
`scan tools.json` never runs anything. Live fetch is bounded — a hostile server
that hangs or streams a giant reply is cut off by the timeout and a per-message
size cap, not left to hang or exhaust memory.

HTTP/SSE transport isn't implemented yet — stdio covers the common
locally-installed case.

MIT.

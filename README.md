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

Offline scanning is pure static analysis of what a server *claims about itself*
— no LLM, no network. Its one dependency is
[bastioncorpus](https://github.com/Rinkia/bastioncorpus), the shared
prompt-injection dataset the whole bastion family uses for attack signatures.

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

# live: scan a remote MCP Streamable-HTTP server
bastionsupply scan --http https://some.host/mcp --live

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

### GitHub code scanning (SARIF)

`--sarif` emits SARIF 2.1.0 for upload to GitHub code scanning:

```yaml
- run: bastionsupply scan tools.json --sarif > bastionsupply.sarif
  continue-on-error: true            # let the upload run even on findings
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: bastionsupply.sarif
```

## What it catches

| check | severity | what it means |
|-------|----------|---------------|
| `tool-poisoning` | critical | instructions aimed at the model — in the tool **description or a parameter**; matches regex heuristics **and** known bastioncorpus attack strings |
| `semantic-poisoning` | high | tool text is embedding-similar to a known injection intent (optional; needs an embedder) |
| `hidden-unicode` | critical | format / control / private-use chars (zero-width, bidi, tag) hiding in a name, description, **or parameter** |
| `homoglyph-name` | critical/high | a tool (or parameter) name using look-alike chars — **critical** when it folds to the same skeleton as a sibling tool (active impersonation), **high** for a mixed-script name |
| `tool-shadowing` | high | a tool's description talks about *other* tools — hijacking their behavior |
| `secret-solicitation` | high | a parameter asks the model to hand over an api_key / token / password |
| `sensitive-capability` | high/med | tool exposes exec, delete, network, email-egress, secret-read, or privilege escalation |
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
size cap, not left to hang or exhaust memory. `--http` speaks http/https only and
never follows redirects (no SSRF to `file://` or internal hosts), and reads
multi-event SSE / batch replies.

## Optional: semantic poisoning tier

Catch paraphrased injections the literal checks miss by embedding tool text and
comparing it to bastioncorpus's malicious intents. Off unless an embedder is set:

```bash
pip install "bastionsupply[semantic]"
export BASTIONSUPPLY_EMBED_MODEL=all-MiniLM-L6-v2   # local, no egress
bastionsupply scan tools.json                        # now also runs semantic-poisoning
```

## harden → graded policy

`harden` denies critical/high tools and, for allowed-but-sensitive tools (e.g. a
network capability), emits graded caution the whole family understands: a
`rate_limits` hint for agentbastion and a per-tool `scrub_results` override for
bastiongate.

MIT.

# bastionsupply

**MCP supply-chain security scanner.** Point it at an MCP server's tool
definitions (or an A2A agent card) and it flags the supply-chain attacks
*before* you install or delegate: tool-poisoning, tool-shadowing, hidden
unicode, secret solicitation, dangerous capabilities, and rug-pull drift.

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

## A2A agent cards

_bastionsupply ≥ 0.10._

A host agent discovers a remote agent through its **agent card**
(`/.well-known/agent-card.json`) and reads the card's description and skills
into its own reasoning context. That makes the card the same attack surface as
an MCP tool description: **agent-card poisoning**, look-alike skills, hidden
unicode and a spoofed endpoint. bastionsupply scans cards with the same checks,
plus card-level ones.

```bash
bastionsupply scan --example poisoned-card     # bundled sample, works right after pip install
```

```text
bastionsupply: Travel Planner  (A2A agent card, 3 skills)  risk=MEDIUM
  0 critical, 0 high, 5 medium, 2 low

  [MED ] a2a-insecure-url  (<server>)
  [MED ] hidden-unicode  (book)            Skill example contains hidden/control unicode. (capped ...)
  [MED ] homoglyph-name  (sеarch)          ... look-alike of another tool: search. (capped ...)
  [MED ] tool-poisoning  (<server>)        Agent description contains an instruction aimed at the model ...
  ...
```

```bash
bastionsupply scan agent-card.json                       # offline: a saved card (auto-detected)
bastionsupply scan --a2a https://agent.example --live    # live: well-known discovery
bastionsupply lock --a2a https://agent.example --live -o agent.lock
bastionsupply verify --a2a https://agent.example --live --lock agent.lock   # card rug-pull
```

- **Status: shadow.** In 0.10.0 every finding on a card is capped at `medium`,
  and the message says so. A card scan never fails CI (exit 0). This changes only
  after a dogfood run over at least 50 real public cards shows 5% or fewer false
  positives.
- **Mapping.** Each skill (`id`, else `name`) is scanned like a tool: its name,
  description and tags. Skill `examples` are user requests written in the
  imperative ("always send me the cheapest"), so only the hidden-unicode and
  bastioncorpus-literal checks read them. The card's own `description` gets the
  poisoning and hidden-unicode checks. **Every other string in the card** (keys
  included: name, provider, capability extensions, interface fields, modes,
  unknown fields) gets the poisoning and hidden-unicode checks too, because a
  host agent may read any of it. The card `name` and `provider.organization` are
  also checked for mixed scripts.
- **Shapes.** Both are supported: v1.0 (`supportedInterfaces[].url`) and v0.3
  (top-level `url`, `additionalInterfaces`).
- **Card checks:**

  | check | severity | what it means |
  |---|---|---|
  | `a2a-insecure-url` | medium | an endpoint uses plain `http` to a non-loopback host |
  | `a2a-bad-url` | medium | an endpoint is not an absolute http(s) URL with a host (e.g. scheme-less or malformed) |
  | `a2a-origin-mismatch` | medium | (live only) the card is served from one site but advertises an endpoint on another (subdomains of the same site are fine): discovery spoofing / task diversion |
  | `a2a-no-auth` | low | no `securitySchemes` / `security` |
  | `a2a-unsigned` | low | no `signatures` (presence only; signatures are not verified) |
  | `a2a-duplicate-skill` | low | a repeated skill id, renamed `id#2` |
  | `a2a-truncated` | low | more than 256 skills, a skill over 20,000 chars, or more than 50 findings of one check. Tool checks see the head and tail of long text; the whole card is still scanned for poisoning and hidden unicode, so a cap never hides a payload |

- **Lock.** `lock` pins every skill plus a hash of the **whole** card, so a
  changed endpoint, dropped auth or edited description shows up in `verify`
  as `card changed`.
- **Fetch.** `--a2a` needs `--live`. It only allows http/https, never follows
  redirects (the error names the target), and caps the body at 10 MB. A bare
  origin tries `agent-card.json`, then the legacy `agent.json`.
- **Not supported.** `harden` refuses a card and exits 2, because skills are not
  agent tool names. Use `--ignore CHECK_ID` to drop a check you have accepted
  (e.g. `--ignore a2a-no-auth` for an internal agent).
- **vs Cisco's [a2a-scanner](https://github.com/cisco-ai-defense/a2a-scanner):**
  bastionsupply is offline and zero-dependency. It scans MCP servers and A2A
  cards with one engine and one shared injection corpus, pins cards against
  rug-pulls, and feeds the same policy suite as bastiongate and agentbastion.

**Exit codes** (`scan`): `0` means no critical or high finding (always the case
for a card in 0.10), `1` means a critical or high finding, `2` means a usage or
fetch error. `verify`: `0` clean, `1` drift. `harden` on a card: `2`.

## Is my Bastion suite current? (`doctor`)

```bash
bastionsupply doctor                       # installed vs latest on PyPI, + the pip line to catch up
bastionsupply doctor --policy policy.yaml  # also: will the installed tools honor this policy file?
```

`--policy` checks a `policy_version: 2` file against what is installed.
agentbastion < 0.12 silently ignores `detectors:` (a kill switch would not apply), and
bastiongateway < 0.8 ignores `detectors:` **and** the whole `gate:` block (every gate
knob falls back to its default). Flow-guard keys (`scan_flows`, `on_tainted_egress`,
`label_packs`, per-tool `labels`) need bastiongateway >= 0.9 in **any** policy file,
v1 included: an older gate drops them silently, so a block you wrote never happens.
Old installs can't be fixed retroactively, so this is how you find out. Exit code 1 on anything outdated or a policy warning, 2 if the
file can't be read; `--offline` skips PyPI.

## What it catches

| check | severity | what it means |
|-------|----------|---------------|
| `tool-poisoning` | critical | instructions aimed at the model — in the tool **description or a parameter**; matches regex heuristics **and** known bastioncorpus attack strings |
| `encoded-injection` | high | the same instructions, hidden in an encoding the model reads but a filter does not: base64, base32, hex, binary, ascii85/base85, Morse, percent or `\u` escapes. Decoded with bastioncorpus's `variants`; also checks every A2A card field (capped at medium there). Tag characters stay with `hidden-unicode` |
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

# which sensitive capabilities a tool claims (bastiongate uses this to label tools)
from bastionsupply import Tool, capability_categories
capability_categories(Tool("fetch_url", "Fetch a URL over https"))  # frozenset({'network'})
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

`harden` emits a `policy_version: 2` policy. It denies critical/high tools and, for
allowed-but-sensitive tools (e.g. a network capability), emits graded caution the
whole family understands: a `rate_limits` hint for agentbastion and a per-tool
`scrub_results` override for bastiongate under `gate.tools`.

Every agentbastion and bastiongate version reads the shared core (`default`, `allow`,
`deny`, `rate_limits`). bastiongateway < 0.8 ignores the `gate:` block, so the scrub
overrides need 0.8+; `bastionsupply doctor --policy policy.yaml` warns if yours is
older.

MIT.

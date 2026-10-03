# Changelog

## 0.11.1 (unreleased)

- `doctor --policy` knows the bastiongateway 0.11/0.12 keys: `scan_prompts` (needs 0.11.0) and
  `taint_group` (needs 0.12.0). An older gate ignores them in v1 (no effect) and refuses a v2
  file.

## 0.11.0 (unreleased)

- **`encoded-injection` check (high).** Tool-poisoning hidden in an encoding: base64,
  base64url, base32, hex, binary, ascii85/base85, Morse, percent and `\u` escapes, including
  line-wrapped and chained forms.
  - Decoded with `bastioncorpus.variants` (run-based only; whole-text rot13/leet rewrites stay
    in the input guard), then matched with the same regexes and corpus phrases as
    `tool-poisoning`.
  - Covers tool descriptions, parameters, the agent description and every A2A card field
    (capped at medium for cards, like all A2A findings).
- `decoded_views(text, transforms=True)` adds the whole-text rot13 / leet / reversed /
  spaced-letter views (opt-in; the scan itself stays run-based). bastiongate and bastionmesh
  use it behind their `decode_transforms` setting. Evidence: `bastionprobe encoding-bench --defenders supply,supply+transforms` (2026-10-02): rot13 1% -> 88%, leet 1% -> 76%, reversed 1% -> 88%, spaced letters 1% -> 8%, 0% benign FP; and 0 false positives on 45,025 real Markdown paragraphs (skills and memory notes).
- `doctor --policy` also flags the new gate keys `decode_transforms` and `scan_resources` on a
  bastiongateway older than 0.10.
  - Tag characters are not re-reported: `hidden-unicode` already flags them at critical.
- **A new check name, so nothing changes for consumers until they opt in.** bastiongate
  enforces on `tool-poisoning` / `hidden-unicode` / `homoglyph-name` only, and adopts this
  check in its next release. Clean servers produce identical output.
- Requires bastioncorpus >= 0.5.0. bastionmesh 0.1.x pins bastionsupply < 0.11; mesh 0.2
  widens the pin.

## 0.10.0

- **A2A agent card scanning.** A card is the host agent's view of a remote agent,
  read into its reasoning context, which makes it the MCP `tools/list` attack
  surface one protocol over (agent-card poisoning, look-alike skills, hidden
  unicode, spoofed endpoints). Cards are mapped onto `Server(kind="a2a")`, each
  skill onto a `Tool`, and every existing check runs. New card checks:
  `a2a-insecure-url`, `a2a-bad-url`, `a2a-origin-mismatch` (live), `a2a-no-auth`,
  `a2a-unsigned`, `a2a-duplicate-skill`, `a2a-truncated`. Every other string in the
  card (keys included) is scanned for poisoning and hidden unicode; caps bound
  the per-tool work but never hide content. Skill examples (user-voice requests)
  are read only by the hidden-unicode and corpus-literal checks. The card name and
  provider are checked for hidden unicode and mixed scripts. Supports the v1.0
  `supportedInterfaces` shape and the v0.3 `url` shape.
- **BEHAVIOR (shadow):** every finding on a card is capped at `medium`, with a
  note in the message, so card scans never fail CI in 0.10. Promotion rule:
  after a dogfood run over >= 50 real public cards with <= 5% false positives.
- `scan --a2a URL --live` fetches a card: well-known discovery
  (`agent-card.json`, then legacy `agent.json`), no redirects (the error names
  the Location), 10 MB cap. Offline card files are auto-detected by
  `scan`/`lock`/`verify`.
- `lock` pins the whole card (canonical JSON hash, under a top-level `card` key);
  `verify` reports `card changed`. MCP lockfiles are unchanged.
- `scan --example NAME` runs a bundled sample (`poisoned-card`, `clean-card`);
  the fixtures now ship inside the wheel.
- `scan --ignore CHECK_ID` (repeatable) drops findings of an accepted check.
- `harden` on a card refuses with exit 2 (skills are not agent tool names).
- `--live` help now reads "allow network access or spawning server processes".
- A target that can't be loaded (bad JSON, bad URL, HTTP error, oversized or
  endless body) is a one-line error with exit 2, not a traceback. Card fetches
  have one overall deadline, not only a per-read timeout.
- Text reports escape control characters in names, messages and evidence, so a
  hostile card or tool name cannot drive the terminal.
- MCP scan output, JSON and lockfiles are byte-identical to 0.9 (`kind` appears in
  JSON only for cards).
- Next: bastioncorpus rows for agent-card and cascade payloads (E5), card JWS
  signature verification (E6, needs a crypto dependency), one `--fail-on`
  vocabulary across the suite.

## 0.9.0

- **`capability_categories(tool)`** (public): the sensitive-capability kinds a tool
  claims (`exec`, `delete`, `network`, `email-egress`, `secrets`, `privilege`).
  `sensitive-capability` findings are unchanged; bastiongate 0.9 uses the helper to
  label tools for its flow guard instead of parsing finding messages.
- **`doctor --policy` knows the flow guard.** A policy using `scan_flows`,
  `on_tainted_egress`, `label_packs` or per-tool `labels` warns when bastiongateway
  < 0.9 is installed, in v1 files too (older gates drop those keys silently) and
  at any nesting depth (JSON parsed, YAML scanned per line).

## 0.8.0

- **`harden` emits `policy_version: 2`.** Same decisions, new shape: the file starts
  with `policy_version: 2`, and the per-tool `scrub_results` overrides move from a
  top-level `tools:` block to `gate: { tools: ... }`. When every tool is denied the
  file says `allow: []` (v1 left a YAML null). The shared core (`default`, `allow`,
  `deny`, `rate_limits`) is unchanged and read by every consumer version.
- **Upgrade note:** bastiongateway < 0.8 ignores the `gate:` block, so a regenerated
  policy loses its scrub overrides there (allow/deny still apply). Upgrade the gate,
  or check with `bastionsupply doctor --policy policy.yaml`. Old v1 policies keep
  loading unchanged.
- Producer golden is now `tests/fixtures/policy_v2_harden_golden.yaml`, byte-identical
  with the consumer copies in agentbastion and bastiongate.

## 0.7.0

- **`doctor --policy FILE`**: checks a `policy_version: 2` policy against the installed
  consumers and warns when one is too old to honor it: agentbastion < 0.12 ignores
  `detectors:` (a kill switch would not apply); bastiongateway < 0.8 ignores
  `detectors:` and the whole `gate:` block (gate knobs fall back to defaults). JSON
  policies are parsed; YAML is scanned for top-level keys (still zero dependencies).
  Exit 1 on warnings, 2 if the file can't be read. `--json` includes the warnings.

## 0.6.0

- **SARIF output**: `bastionsupply scan --sarif` emits SARIF 2.1.0 so findings
  upload to GitHub code scanning (`github/codeql-action/upload-sarif`) or any SARIF
  ingester. Severity maps to level (critical/high→error, medium→warning, low→note);
  the offending tool rides in a logicalLocation (MCP metadata has no source line).

## 0.5.0

- **Email-egress capability** added to `sensitive-capability`: a mail-send tool
  (`sendEmail`, `sendmail`, SMTP, BCC) is a data-egress path and is now surfaced
  pre-flight. Motivated by the `postmark-mcp` case (Koi Security, Sep 2025) — the
  first in-the-wild malicious MCP server, which BCC-exfiltrated sent email.
  Read-only mail tools (`listTemplates`, `getDeliveryStats`) are not flagged.
- **Case-study fixture** `tests/fixtures/postmark_mcp_tools.json` + regression test.
  Honest boundary: the clone's tools/list was clean, so bastionsupply surfaces the
  egress *capability* but does not (and the test asserts it does not) fabricate a
  tool-poisoning hit — the code-level BCC is a bastiongate/bastionskill catch.

## 0.4.0

- **Fuller confusables**: the homoglyph skeleton now NFKC-folds (catching
  fullwidth / compatibility look-alikes) and covers many more cross-script
  characters. Parameter names are checked via the skeleton too, and a parameter
  whose name folds to a sibling tool's name is flagged as impersonation.
- **Semantic poisoning tier** (optional, `bastionsupply[semantic]`): embeds tool
  text and compares it to bastioncorpus's malicious intents (`to_semantic`),
  catching paraphrased injections. Off unless `BASTIONSUPPLY_EMBED_MODEL` is set.
- **fetch_http**: reads multi-event SSE streams and JSON-RPC batch arrays,
  picks the reply by id, threads the session id through, and reports HTTP errors
  clearly.
- **Graded `harden` policy**: allowed-but-sensitive tools get a `rate_limits`
  hint (agentbastion) and a per-tool `scrub_results` override (bastiongate),
  instead of only allow/deny.

## 0.3.1

- Fix: homoglyph sibling-impersonation flagged **both** the look-alike and the
  real ASCII tool it mimics. Now only the name that actually uses look-alike
  characters is flagged; the pure-ASCII victim is left alone.

## 0.3.0

- **Wired bastioncorpus** (now a dependency): tool-poisoning also matches known
  attack strings from the shared bastion injection dataset, catching payloads
  the regex heuristics miss.
- **Homoglyph detection extended**: parameter names are checked too, and a tool
  name that folds to the same confusable skeleton as a sibling tool is flagged
  **critical** (active impersonation) rather than just mixed-script high.
- **HTTP/SSE fetch** (`scan --http URL --live`): scan a remote MCP
  Streamable-HTTP server. http/https only, no redirect following (no SSRF),
  bounded response size.

## 0.2.0

Security + correctness hardening (found in a review pass):

- **Detection now covers parameters**, not just the tool description:
  `tool-poisoning` and `hidden-unicode` scan parameter names/descriptions too, so
  an injection or hidden char hidden in a parameter is no longer missed.
- **New `homoglyph-name` check**: a tool name mixing alphabetic scripts (e.g.
  Cyrillic + Latin) is flagged as look-alike impersonation of another tool.
- **Stronger hidden-unicode detection**: uses Unicode general category
  (format / control / private-use) instead of a hand-list — catches soft
  hyphen, variation-selector-adjacent format chars, and more.
- **Crash fixes on hostile input**: a non-dict `inputSchema` no longer crashes
  the scan; CLI output no longer crashes on non-ASCII (homoglyph) tool names on a
  legacy (cp1252) console.
- **Live-fetch hardening**: `fetch_stdio` now honors its timeout even when a
  server hangs mid-line, and caps per-message size — a hostile `--live` server
  can't hang the scanner or exhaust memory.

## 0.1.0

- Initial release: static MCP supply-chain scanner (tool-poisoning, hidden
  unicode, shadowing, secret solicitation, sensitive capability), rug-pull
  lockfiles, `harden` → agentbastion policy. Offline JSON or live stdio/config.

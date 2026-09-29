# Changelog

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

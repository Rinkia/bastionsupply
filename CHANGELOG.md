# Changelog

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

"""A2A agent cards: the MCP `tools/list` attack surface, one protocol over.

A host agent discovers a remote agent through its agent card
(`/.well-known/agent-card.json`) and reads the card's description and skills into
its own reasoning context. That makes the card the same target as an MCP tool
description: agent-card poisoning, look-alike skills, hidden unicode, a spoofed
endpoint. So a card maps onto the existing model and every MCP check runs on it:

    card.name / description      -> Server(kind="a2a").name / .description
    card.skills[]                -> Tool(name=id|name|skill#N, description=name+description+tags)
    card.skills[].examples       -> NOT a description: they are user-voice requests
                                    ("always send me the cheapest"), so only the
                                    hidden-unicode and corpus-literal checks read them
    every other string in the card -> poisoning + hidden-unicode (a payload can hide
                                    in any field the host agent may read)

plus card-level checks (`a2a-*`). Supports the v1.0 shape (`supportedInterfaces`)
and the v0.3 shape (top-level `url`, `additionalInterfaces`).

Status: shadow. Every finding on an A2A card is capped at medium in 0.10.0, so a
scan never fails CI on a card. Promotion: after a dogfood run over >= 50 real
public cards with <= 5% false positives.
"""

from __future__ import annotations

import ipaddress
import re
import unicodedata
import urllib.parse
from dataclasses import replace

from .corpus import poison_signatures
from .models import Finding, Server, Tool

# ponytail: caps bound the per-tool checks (shadowing is O(n^2) in skills); content
# past a cap is still read by the whole-card leaf walk, so a cap never hides a payload
MAX_SKILLS = 256
MAX_SKILL_TEXT = 20_000
MAX_FINDINGS_PER_CHECK = 50
_MAX_DEPTH = 32
_MAX_LEAVES = 100_000

CAP = "medium"
_CAP_NOTE = " (capped at medium: A2A checks are in shadow in 0.10.0)"
_SKILL_TOOL_FIELDS = ("id", "name", "description", "tags")  # read via the mapped Tool


def is_agent_card(obj) -> bool:
    """A dict with a skills list: an A2A agent card. MCP tools/list dumps never
    carry `skills`, and a stray `tools` key must not hide a card's skills."""
    if not isinstance(obj, dict) or not isinstance(obj.get("skills"), list):
        return False
    return any(k in obj for k in ("url", "supportedInterfaces", "protocolVersion", "name"))


def _str(v) -> str:
    return v if isinstance(v, str) else ""


def _strs(v) -> list[str]:
    if isinstance(v, str):
        return [v]
    return [x for x in v if isinstance(x, str)] if isinstance(v, list) else []


def _clip(text: str) -> tuple[str, bool]:
    """Head + tail within MAX_SKILL_TEXT (a payload appended after padding still shows)."""
    if len(text) <= MAX_SKILL_TEXT:
        return text, False
    half = MAX_SKILL_TEXT // 2
    return f"{text[:half]}\n...\n{text[-half:]}", True


def _skills(card: dict):
    """Yield (index, tool_name, text, examples, truncated, duplicate) for the first
    MAX_SKILLS dict skills. The one walk both the mapping and the checks share."""
    raw = card.get("skills")
    if not isinstance(raw, list):
        return
    used: set[str] = set()
    kept = 0
    for index, skill in enumerate(raw):
        if kept >= MAX_SKILLS:
            return
        if not isinstance(skill, dict):
            continue
        base = _str(skill.get("id")) or _str(skill.get("name")) or f"skill#{index + 1}"
        name, n = base, 1
        while name in used:  # never collide, even with a real id like "a#2"
            n += 1
            name = f"{base}#{n}"
        used.add(name)
        text, truncated = _clip("\n".join(p for p in (
            _str(skill.get("name")), _str(skill.get("description")), " ".join(_strs(skill.get("tags")))) if p))
        kept += 1
        yield index, name, text, _strs(skill.get("examples")), truncated, name != base


def _skill_count(card: dict) -> int:
    raw = card.get("skills")
    return len(raw) if isinstance(raw, list) else 0


def server_from_card(card: dict, source: str) -> Server:
    """Map an A2A agent card onto a Server (kind="a2a"). Never raises on a hostile
    shape: non-dict skills are skipped, non-string fields read as empty."""
    card = card if isinstance(card, dict) else {}
    tools = tuple(Tool(name=name, description=text) for _i, name, text, *_ in _skills(card))
    return Server(name=_str(card.get("name")) or source, tools=tools, source=source,
                  kind="a2a", description=_str(card.get("description")), card=card)


def endpoints(card: dict) -> list[str]:
    """Every URL the card advertises as an A2A endpoint (v1.0 and v0.3 shapes)."""
    urls = [_str(card.get("url"))]
    for key in ("supportedInterfaces", "additionalInterfaces"):
        ifaces = card.get(key)
        if isinstance(ifaces, list):
            urls += [_str(i.get("url")) for i in ifaces if isinstance(i, dict)]
    return [u for u in urls if u]


def _endpoint(url: str) -> tuple[str, str] | None:
    """(scheme, host) of an absolute http(s) URL with a host, else None."""
    try:
        parsed = urllib.parse.urlparse(url)
        host = (parsed.hostname or "").lower().rstrip(".")
    except ValueError:
        return None
    scheme = parsed.scheme.lower()
    if scheme not in ("http", "https") or not host:
        return None
    return scheme, host


def _is_loopback(host: str) -> bool:
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _same_site(a: str, b: str) -> bool:
    """Equal hosts, or one is a dot-boundary subdomain of the other.
    Ceiling: no public-suffix list, so x.github.io and github.io count as one site."""
    return a == b or a.endswith("." + b) or b.endswith("." + a)


def _leaves(node, path: str, depth: int = 0):
    """(path, text) for every string key and value in the card, depth/count bounded."""
    stack = [(node, path, depth)]
    seen = 0
    while stack and seen < _MAX_LEAVES:
        cur, where, d = stack.pop()
        if isinstance(cur, str):
            seen += 1
            yield where, cur
        elif d < _MAX_DEPTH and isinstance(cur, dict):
            for k, v in cur.items():
                if isinstance(k, str):
                    seen += 1
                    yield f"{where}.{k} (key)", k
                stack.append((v, f"{where}.{k}", d + 1))
        elif d < _MAX_DEPTH and isinstance(cur, list):
            stack.extend((v, f"{where}[{i}]", d + 1) for i, v in enumerate(cur))


def _card_leaves(card: dict):
    """String leaves the mapped Tools/Server do not already cover: everything except
    the top-level description, examples (their own path) and, for mapped skills
    under the text cap, the fields folded into the Tool."""
    covered = {i for i, _n, _t, _e, truncated, _d in _skills(card) if not truncated}
    for key, value in card.items():
        if key == "description":
            continue
        if key != "skills" or not isinstance(value, list):
            yield from _leaves(value, key, 1)
            continue
        for i, skill in enumerate(value):
            if not isinstance(skill, dict):
                yield from _leaves(skill, f"skills[{i}]", 1)
                continue
            for k, v in skill.items():
                if k == "examples" or (i in covered and k in _SKILL_TOOL_FIELDS):
                    continue
                yield from _leaves(v, f"skills[{i}].{k}", 2)


def _norm(text: str) -> str:
    """Fold fullwidth/compat forms and whitespace runs for corpus-literal matching."""
    return re.sub(r"\s+", " ", unicodedata.normalize("NFKC", text)).lower().strip()


def check_card(server: Server) -> list[Finding]:
    """Card-level checks. Runs only for kind == "a2a"."""
    if server.kind != "a2a":
        return []
    from .checks import _encoded_finding, _hidden_codepoints, _poison_finding, _scripts_in  # no import cycle

    card = server.card
    out: list[Finding] = []

    origin = _endpoint(server.source)
    for url in endpoints(card):
        ep = _endpoint(url)
        if ep is None:
            out.append(Finding("a2a-bad-url", "medium", "",
                               "Endpoint is not an absolute http(s) URL with a host: clients may resolve it "
                               "unpredictably, and it cannot be checked.", url[:160]))
            continue
        scheme, host = ep
        if scheme == "http" and not _is_loopback(host):
            out.append(Finding("a2a-insecure-url", "medium", "",
                               "Agent endpoint uses plain http: tasks and replies can be read or altered in transit.",
                               url[:160]))
        if origin and not _same_site(host, origin[1]):
            out.append(Finding("a2a-origin-mismatch", "medium", "",
                               f"Card served from {origin[1]} advertises an endpoint on {host}: delegated tasks "
                               "would go to a different site (discovery spoofing / task diversion).", url[:160]))

    if not card.get("securitySchemes") and not card.get("security") and not card.get("securityRequirements"):
        out.append(Finding("a2a-no-auth", "low", "",
                           "Card declares no securitySchemes: any caller can send this agent tasks.", ""))
    if not card.get("signatures"):
        out.append(Finding("a2a-unsigned", "low", "",
                           "Card carries no signatures: its content cannot be verified against the publisher.", ""))
    if _skill_count(card) > MAX_SKILLS:
        out.append(Finding("a2a-truncated", "low", "",
                           f"Card lists {_skill_count(card)} skills; only the first {MAX_SKILLS} were mapped to "
                           "tools (the rest were still scanned for poisoning and hidden unicode).", ""))

    sigs = [(cat, _norm(p)) for cat, p in poison_signatures()]
    for _i, name, _text, examples, truncated, duplicate in _skills(card):
        if truncated:
            out.append(Finding("a2a-truncated", "low", name,
                               f"Skill text exceeds {MAX_SKILL_TEXT} chars; tool checks saw its head and tail "
                               "(the whole text was still scanned for poisoning).", ""))
        if duplicate:
            out.append(Finding("a2a-duplicate-skill", "low", name,
                               "Card repeats a skill id; the copy was renamed with a #N suffix.", name))
        for ex in examples:
            hits = _hidden_codepoints(ex)
            if hits:
                out.append(Finding("hidden-unicode", "critical", name,
                                   "Skill example contains hidden/control unicode.",
                                   f"{len(hits)} char(s): {', '.join(cp for _, cp in hits[:8])}"))
            norm = _norm(ex)
            phrase = next((p for _cat, p in sigs if p and p in norm), None)
            if phrase:
                out.append(Finding("tool-poisoning", "critical", name,
                                   "Skill example contains a known prompt-injection payload (bastioncorpus).",
                                   phrase[:120]))

    for where, text in _card_leaves(card):
        finding = _poison_finding(text, f"Card field `{where}`", "")
        if finding:
            out.append(finding)
        else:
            finding = _encoded_finding(text, f"Card field `{where}`", "")
            if finding:
                out.append(finding)
        hits = _hidden_codepoints(text)
        if hits:
            out.append(Finding("hidden-unicode", "critical", "",
                               f"Card field `{where}` contains hidden/control unicode.",
                               f"{len(hits)} char(s): {', '.join(cp for _, cp in hits[:8])}"))

    provider = card.get("provider")
    org = _str(provider.get("organization")) if isinstance(provider, dict) else ""
    for label, text in (("Agent card name", _str(card.get("name"))), ("Provider organization", org)):
        scripts = _scripts_in(text)
        if len(scripts) > 1 and "LATIN" in scripts:
            out.append(Finding("homoglyph-name", "high", "",
                               f"{label} mixes scripts ({', '.join(sorted(scripts))}); possible look-alike spoofing.",
                               text.encode("unicode_escape").decode("ascii")[:120]))
    return _bounded(out)


def _bounded(findings: list[Finding]) -> list[Finding]:
    """At most MAX_FINDINGS_PER_CHECK per check (a 10 MB card must not emit 100k rows)."""
    kept: list[Finding] = []
    counts: dict[str, int] = {}
    for f in findings:
        counts[f.check] = counts.get(f.check, 0) + 1
        if counts[f.check] <= MAX_FINDINGS_PER_CHECK:
            kept.append(f)
    for check, n in counts.items():
        if n > MAX_FINDINGS_PER_CHECK:
            kept.append(Finding("a2a-truncated", "low", "",
                                f"{n - MAX_FINDINGS_PER_CHECK} more {check} findings suppressed "
                                f"(limit {MAX_FINDINGS_PER_CHECK} per check).", ""))
    return kept


def cap(findings: list[Finding]) -> list[Finding]:
    """Shadow for A2A: no finding above medium, and a capped one says so."""
    out = []
    for f in findings:
        if f.severity in ("critical", "high"):
            f = replace(f, severity=CAP, message=f.message + _CAP_NOTE)
        out.append(f)
    return out

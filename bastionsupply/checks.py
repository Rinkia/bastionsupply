"""Static checks over MCP tool definitions.

Each check is `check(server) -> list[Finding]`. `run_checks` runs them all.
No network, no execution: this scans text that a server *claims* about itself,
which is exactly the attack surface (tool-poisoning, shadowing, hidden unicode).
"""

from __future__ import annotations

import re
import unicodedata

from .models import Finding, Server, Tool

# --- tool poisoning: instructions in a description aimed at the model ----------
# A tool description should describe the tool. Text that commands the *agent*
# is the tool-poisoning attack (hidden directives the model reads and obeys).
_POISON = [
    re.compile(p, re.I)
    for p in (
        r"ignore\s+(all\s+|the\s+|your\s+)?previous",
        r"disregard\s+(the\s+|all\s+)?(above|previous|prior|earlier)",
        r"before\s+(using|calling|invoking|running)\s+(this|any|the|other)\s+tool",
        r"\b(you\s+must|always|never)\s+(call|use|send|include|append|forward|cc)\b",
        r"system\s+prompt",
        r"do\s+not\s+(tell|inform|mention|reveal|disclose|notify)\s+(the\s+)?user",
        r"<\s*(important|system|secret|instructions?)\s*>",
        r"\[\s*(system|important|instructions?)\s*\]",
        r"\bas\s+an?\s+ai\b|\bassistant\s*,?\s+you\s+(must|should|will)\b",
        r"real\s+(instructions?|task)\s+(is|are)",
    )
]

# --- sensitive capability: dangerous verbs in a name/description --------------
_SENSITIVE = {
    "exec": r"\b(exec|eval|shell|subprocess|os\.system|spawn|/bin/sh)\b",
    "delete": r"\b(delete|remove|rm\s+-rf|unlink|drop\s+table|truncate|wipe)\b",
    "network": r"\b(http|https|fetch|curl|wget|upload|exfiltrat|webhook|post\s+to)\b",
    "secrets": r"\b(secret|credential|api[_\- ]?key|token|password|ssh|private[_\- ]?key|\.env|os\.environ)\b",
    "privilege": r"\b(sudo|chmod|chown|root|setuid|escalat)\b",
}
_SENSITIVE = {k: re.compile(v, re.I) for k, v in _SENSITIVE.items()}

# --- secret solicitation: params asking the model to hand over credentials ----
_SECRET_PARAM = re.compile(
    r"\b(api[_\- ]?key|token|password|passwd|secret|credential|private[_\- ]?key|"
    r"bearer|aws[_\-]|access[_\- ]?key|client[_\- ]?secret)\b",
    re.I,
)

# --- hidden unicode: ranges no legitimate tool text needs --------------------
_INVISIBLE = {
    "zero-width": lambda c: c in "​‌‍⁠﻿",
    "bidi-override": lambda c: c in "‪‫‬‭‮⁦⁧⁨⁩",
    "tag-chars": lambda c: 0xE0000 <= ord(c) <= 0xE007F,
    "private-use": lambda c: 0xE000 <= ord(c) <= 0xF8FF,
}


def _hidden_codepoints(text: str) -> list[tuple[str, str]]:
    """Return (kind, U+XXXX) for every suspicious char in `text`."""
    hits = []
    for ch in text:
        for kind, pred in _INVISIBLE.items():
            if pred(ch):
                hits.append((kind, f"U+{ord(ch):04X}"))
                break
    return hits


def check_tool_poisoning(server: Server) -> list[Finding]:
    out = []
    for t in server.tools:
        for rx in _POISON:
            m = rx.search(t.description)
            if m:
                out.append(
                    Finding(
                        check="tool-poisoning",
                        severity="critical",
                        tool=t.name,
                        message="Tool description contains an instruction aimed at the model, not a description of the tool.",
                        evidence=_snippet(t.description, m.start(), m.end()),
                    )
                )
                break  # one finding per tool is enough signal
    return out


def check_tool_shadowing(server: Server) -> list[Finding]:
    """Description of tool A that references or instructs tool B."""
    names = {t.name.lower() for t in server.tools}
    out = []
    for t in server.tools:
        desc = t.description.lower()
        others = [n for n in names if n != t.name.lower() and n and re.search(rf"\b{re.escape(n)}\b", desc)]
        generic = re.search(r"\b(other|any|all|every)\s+tools?\b|when\s+(using|calling)\s+\w+", desc)
        if others or generic:
            ev = ("references tool(s): " + ", ".join(others)) if others else "references other tools generically"
            out.append(
                Finding(
                    check="tool-shadowing",
                    severity="high",
                    tool=t.name,
                    message="Tool description talks about other tools; may hijack their behavior.",
                    evidence=ev,
                )
            )
    return out


def check_sensitive_capability(server: Server) -> list[Finding]:
    out = []
    for t in server.tools:
        blob = f"{t.name}\n{t.description}"
        cats = [cat for cat, rx in _SENSITIVE.items() if rx.search(blob)]
        if cats:
            sev = "high" if ({"exec", "delete", "secrets"} & set(cats)) else "medium"
            out.append(
                Finding(
                    check="sensitive-capability",
                    severity=sev,
                    tool=t.name,
                    message=f"Tool exposes sensitive capability: {', '.join(sorted(cats))}.",
                    evidence=blob[:160],
                )
            )
    return out


def check_secret_solicitation(server: Server) -> list[Finding]:
    out = []
    for t in server.tools:
        m = _SECRET_PARAM.search(t.param_text)
        if m:
            out.append(
                Finding(
                    check="secret-solicitation",
                    severity="high",
                    tool=t.name,
                    message="Tool parameter asks for a credential/secret to be passed in.",
                    evidence=_snippet(t.param_text, m.start(), m.end()),
                )
            )
    return out


def check_hidden_unicode(server: Server) -> list[Finding]:
    out = []
    for t in server.tools:
        for field_name, text in (("name", t.name), ("description", t.description)):
            hits = _hidden_codepoints(text)
            if hits:
                kinds = sorted({k for k, _ in hits})
                pts = ", ".join(cp for _, cp in hits[:8])
                out.append(
                    Finding(
                        check="hidden-unicode",
                        severity="critical",
                        tool=t.name,
                        message=f"Tool {field_name} contains hidden/control unicode ({', '.join(kinds)}).",
                        evidence=f"{len(hits)} char(s): {pts}",
                    )
                )
    return out


ALL_CHECKS = (
    check_tool_poisoning,
    check_hidden_unicode,
    check_tool_shadowing,
    check_secret_solicitation,
    check_sensitive_capability,
)


def run_checks(server: Server) -> list[Finding]:
    """Run every check; return findings worst-severity first."""
    from .models import _RANK

    findings: list[Finding] = []
    for check in ALL_CHECKS:
        findings.extend(check(server))
    return sorted(findings, key=lambda f: (_RANK[f.severity], f.check, f.tool))


def _snippet(text: str, start: int, end: int, pad: int = 30) -> str:
    a = max(0, start - pad)
    b = min(len(text), end + pad)
    s = text[a:b].replace("\n", " ").strip()
    # make invisible chars visible in evidence
    s = "".join(c if (c.isprintable() or c == " ") else f"\\u{ord(c):04x}" for c in s)
    return ("…" if a else "") + s + ("…" if b < len(text) else "")


def normalize_confusables(text: str) -> str:
    """NFKC fold — used by tests to show homoglyph names collapse."""
    return unicodedata.normalize("NFKC", text)

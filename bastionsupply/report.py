"""Render a ScanReport as text or JSON."""

from __future__ import annotations

import json
import unicodedata
from dataclasses import asdict

from .models import ScanReport

_MARK = {"critical": "CRIT", "high": "HIGH", "medium": "MED ", "low": "LOW "}


def to_json(report: ScanReport) -> str:
    out = {
        "server": report.server,
        "risk": report.risk,
        "tool_count": report.tool_count,
        "counts": report.counts(),
        "findings": [asdict(f) for f in report.findings],
    }
    if report.kind != "mcp":  # MCP output stays byte-identical to earlier versions
        out["kind"] = report.kind
    return json.dumps(out, indent=2, ensure_ascii=False)


def _safe(text: str) -> str:
    """Escape C0/C1 control chars so a hostile name/evidence can't drive the terminal
    (ESC sequences, carriage return overwriting the risk line)."""
    return "".join(f"\\x{ord(c):02x}" if unicodedata.category(c) == "Cc" else c for c in text)


def to_text(report: ScanReport) -> str:
    what = (f"A2A agent card, {report.tool_count} skills" if report.kind == "a2a"
            else f"{report.tool_count} tools")
    lines = [f"bastionsupply: {_safe(report.server)}  ({what})  risk={report.risk.upper()}"]
    if not report.findings:
        lines.append("  clean — no supply-chain risks found")
        return "\n".join(lines)
    c = report.counts()
    lines.append(f"  {c['critical']} critical, {c['high']} high, {c['medium']} medium, {c['low']} low")
    lines.append("")
    for f in report.findings:
        where = _safe(f.tool) or "<server>"
        lines.append(f"  [{_MARK[f.severity]}] {f.check}  ({where})")
        lines.append(f"         {_safe(f.message)}")
        if f.evidence:
            lines.append(f"         evidence: {_safe(f.evidence)}")
    return "\n".join(lines)

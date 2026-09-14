"""Render a ScanReport as text or JSON."""

from __future__ import annotations

import json
from dataclasses import asdict

from .models import ScanReport

_MARK = {"critical": "CRIT", "high": "HIGH", "medium": "MED ", "low": "LOW "}


def to_json(report: ScanReport) -> str:
    return json.dumps(
        {
            "server": report.server,
            "risk": report.risk,
            "tool_count": report.tool_count,
            "counts": report.counts(),
            "findings": [asdict(f) for f in report.findings],
        },
        indent=2,
        ensure_ascii=False,
    )


def to_text(report: ScanReport) -> str:
    lines = [f"bastionsupply: {report.server}  ({report.tool_count} tools)  risk={report.risk.upper()}"]
    if not report.findings:
        lines.append("  clean — no supply-chain risks found")
        return "\n".join(lines)
    c = report.counts()
    lines.append(f"  {c['critical']} critical, {c['high']} high, {c['medium']} medium, {c['low']} low")
    lines.append("")
    for f in report.findings:
        where = f.tool or "<server>"
        lines.append(f"  [{_MARK[f.severity]}] {f.check}  ({where})")
        lines.append(f"         {f.message}")
        if f.evidence:
            lines.append(f"         evidence: {f.evidence}")
    return "\n".join(lines)

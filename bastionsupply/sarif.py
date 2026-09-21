"""Emit a ScanReport as SARIF 2.1.0 (PRP Part 2 [next]).

SARIF lets `bastionsupply scan --sarif` upload straight to GitHub code scanning
(github/codeql-action/upload-sarif) or any SARIF ingester. bastionsupply scans an
MCP server's tools/list metadata — there is no source line — so each finding's
offending tool goes in a logicalLocation, and the scanned server/target is the
artifact uri (region omitted; SARIF permits a location without a region).
"""

from __future__ import annotations

import json

from . import __version__
from .models import ScanReport

_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
_INFO_URI = "https://github.com/Rinkia/bastionsupply"

# bastionsupply severity -> SARIF result level.
_LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note"}


def to_sarif(report: ScanReport) -> str:
    uri = report.server or "mcp-server"
    rules: dict[str, dict] = {}
    results = []
    for f in report.findings:
        rules.setdefault(f.check, {
            "id": f.check,
            "shortDescription": {"text": f.check.replace("-", " ")},
            "helpUri": f"{_INFO_URI}#checks",
        })
        location = {
            "physicalLocation": {"artifactLocation": {"uri": uri}},
        }
        if f.tool:
            location["logicalLocations"] = [{"name": f.tool, "kind": "member"}]
        result = {
            "ruleId": f.check,
            "level": _LEVEL.get(f.severity, "warning"),
            "message": {"text": f.message + (f"\nevidence: {f.evidence}" if f.evidence else "")},
            "locations": [location],
        }
        results.append(result)

    doc = {
        "$schema": _SCHEMA,
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "bastionsupply",
                "version": __version__,
                "informationUri": _INFO_URI,
                "rules": list(rules.values()),
            }},
            "results": results,
        }],
    }
    return json.dumps(doc, indent=2, ensure_ascii=False)

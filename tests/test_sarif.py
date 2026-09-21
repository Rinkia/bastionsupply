"""SARIF 2.1.0 output for bastionsupply (PRP Part 2 [next]).

`bastionsupply scan --sarif` emits SARIF so findings upload to GitHub code scanning
(or any SARIF ingester). This locks the schema shape + severity->level mapping.
"""

from __future__ import annotations

import json

from bastionsupply.models import Finding, ScanReport
from bastionsupply.sarif import to_sarif


def _report():
    findings = (
        Finding(check="tool-poisoning", severity="critical", tool="run_task",
                message="hidden instruction in description", evidence="ignore all previous"),
        Finding(check="sensitive-capability", severity="medium", tool="sendEmail",
                message="email-egress", evidence="send an email"),
    )
    return ScanReport(server="tools.json", tool_count=2, findings=findings)


def test_sarif_is_valid_2_1_0_envelope():
    doc = json.loads(to_sarif(_report()))
    assert doc["version"] == "2.1.0"
    assert doc["$schema"].endswith("sarif-2.1.0.json")
    driver = doc["runs"][0]["tool"]["driver"]
    assert driver["name"] == "bastionsupply"
    assert driver["version"]  # non-empty


def test_results_map_check_and_severity():
    doc = json.loads(to_sarif(_report()))
    results = doc["runs"][0]["results"]
    assert len(results) == 2
    by_rule = {r["ruleId"]: r for r in results}
    assert by_rule["tool-poisoning"]["level"] == "error"        # critical -> error
    assert by_rule["sensitive-capability"]["level"] == "warning"  # medium -> warning
    # message + a location that names the offending tool
    r = by_rule["tool-poisoning"]
    assert "hidden instruction" in r["message"]["text"]
    assert r["locations"][0]["logicalLocations"][0]["name"] == "run_task"


def test_rules_are_declared_and_deduped():
    doc = json.loads(to_sarif(_report()))
    rules = doc["runs"][0]["tool"]["driver"]["rules"]
    ids = [rule["id"] for rule in rules]
    assert set(ids) == {"tool-poisoning", "sensitive-capability"}
    assert len(ids) == len(set(ids))  # deduped
    # every result's ruleId is a declared rule
    result_rules = {r["ruleId"] for r in doc["runs"][0]["results"]}
    assert result_rules <= set(ids)


def test_clean_report_has_no_results():
    doc = json.loads(to_sarif(ScanReport(server="s", tool_count=0, findings=())))
    assert doc["runs"][0]["results"] == []

"""Producer side of the policy.yaml contract (PRP §1.3).

`bastionsupply harden` emits a policy.yaml that agentbastion + bastiongate consume.
This freezes the emitted bytes against a golden. A drift here means the shared
format changed: regenerate the golden deliberately (see the fixture note), READ THE
DIFF, and sync the copy in agentbastion/tests/fixtures/policy_golden.yaml — never
edit the golden just to make CI pass.
"""

from __future__ import annotations

from pathlib import Path

from bastionsupply.fetch import load_json_file
from bastionsupply.harden import to_policy_yaml
from bastionsupply.scanner import scan

FIX = Path(__file__).parent / "fixtures"


def test_harden_output_matches_golden():
    srv = load_json_file(FIX / "policy_contract_server.json", name="contract-server")
    produced = to_policy_yaml(scan(srv), srv.tools)
    golden = (FIX / "policy_golden.yaml").read_text(encoding="utf-8")
    assert produced == golden, (
        "harden policy.yaml drifted from golden — regenerate deliberately, read the "
        "diff, and sync agentbastion's copy"
    )


def test_golden_has_the_contract_keys():
    """Lock the format's key set independent of the exact tool values."""
    golden = (FIX / "policy_golden.yaml").read_text(encoding="utf-8")
    for key in ("default: deny", "allow:", "deny:", "rate_limits:", "scrub_results: true"):
        assert key in golden, f"golden missing contract key: {key!r}"

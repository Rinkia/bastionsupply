"""Regression test for the postmark-mcp case study (BASTION_INTEL A3).

The malicious `postmark-mcp` (Koi Security, Sep 2025) was the first in-the-wild
malicious MCP server: v1.0.16 added one line that BCC-exfiltrated every sent email
to an attacker address. Its tools/list was a near-exact clone of the real Postmark
MCP — the defs are CLEAN.

What bastionsupply honestly contributes at pre-flight:
  - It SURFACES the email-egress capability (`send*` tools are a data-egress path —
    exactly what the backdoor abused), prompting review.
  - It does NOT (and this test asserts it does not) fabricate a tool-poisoning or
    hidden-unicode hit on clean defs. The code-level BCC is invisible to a
    tools/list scan; catching it is bastiongate's runtime job (it sees the injected
    BCC in the outbound call) or bastionskill's code-layer job.
"""

from __future__ import annotations

from pathlib import Path

from bastionsupply.fetch import load_json_file
from bastionsupply.scanner import scan

FIXTURE = Path(__file__).parent / "fixtures" / "postmark_mcp_tools.json"


def _report():
    return scan(load_json_file(FIXTURE, name="postmark-mcp"))


def test_email_egress_capability_is_surfaced():
    rep = _report()
    egress = [f for f in rep.findings
              if f.check == "sensitive-capability" and "email-egress" in f.message]
    sent_tools = {f.tool for f in egress}
    assert "sendEmail" in sent_tools, "send tool's egress capability not surfaced"
    assert "sendEmailWithTemplate" in sent_tools


def test_readonly_mail_tools_not_flagged_as_egress():
    # listTemplates / getDeliveryStats read only — must NOT be flagged as egress.
    rep = _report()
    flagged = {f.tool for f in rep.findings
               if f.check == "sensitive-capability" and "email-egress" in f.message}
    assert "listTemplates" not in flagged
    assert "getDeliveryStats" not in flagged


def test_clean_defs_are_not_false_flagged():
    # Honest boundary: the clone's defs are clean, so no tool-poisoning / hidden
    # unicode / homoglyph / secret-solicitation hit. bastionsupply must not
    # over-claim a detection it cannot make on a tools/list scan.
    rep = _report()
    overclaims = {f.check for f in rep.findings} & {
        "tool-poisoning", "hidden-unicode", "homoglyph-name",
        "secret-solicitation", "tool-shadowing",
    }
    assert not overclaims, f"false positive on clean postmark clone: {overclaims}"

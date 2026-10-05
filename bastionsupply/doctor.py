"""`bastionsupply doctor` — is my Bastion suite current? (PRP §1.4, G4)

Reads the installed version of each Bastion package, queries PyPI's JSON API for
the latest release, and prints a table plus the exact `pip install -U ...` line to
catch up. No new dependency: stdlib `importlib.metadata` + `urllib`.

Offline-safe: if PyPI can't be reached, latest shows as "?" and nothing is claimed
outdated. Not-installed packages are reported as such (they may be optional legs).
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from importlib.metadata import PackageNotFoundError, version

# pip name -> short role, in suite narrative order. The version source of truth
# for the whole suite; keep in sync with bastion-site/suite.json.
SUITE: list[tuple[str, str]] = [
    ("bastioncorpus", "shared injection corpus (root)"),
    ("bastionsupply", "MCP supply-chain scanner"),
    ("bastionskill", "skill-poisoning scanner"),
    ("agentbastion", "in-process agent firewall"),
    ("bastionprobe", "injection fuzzer / pentest"),
    ("bastiontrace", "trace forensics"),
    ("bastiongateway", "runtime MCP gateway"),
    ("bastionmemory", "memory-poisoning scanner"),
]

_PYPI = "https://pypi.org/pypi/{name}/json"
_TIMEOUT = 5.0


def installed_version(name: str) -> str | None:
    try:
        return version(name)
    except PackageNotFoundError:
        return None


def latest_version(name: str, timeout: float = _TIMEOUT) -> str | None:
    """Latest release on PyPI, or None if unreachable / unknown."""
    try:
        with urllib.request.urlopen(_PYPI.format(name=name), timeout=timeout) as resp:
            data = json.load(resp)
        return data.get("info", {}).get("version")
    except (urllib.error.URLError, TimeoutError, ValueError, OSError):
        return None


def _key(v: str) -> tuple:
    import re
    nums = re.findall(r"\d+", v.split("+")[0])
    return tuple(int(n) for n in nums) if nums else (0,)


def collect(check_pypi: bool = True) -> list[dict]:
    rows = []
    for name, role in SUITE:
        inst = installed_version(name)
        latest = latest_version(name) if (check_pypi and inst is not None) else None
        outdated = bool(inst and latest and _key(latest) > _key(inst))
        rows.append({
            "name": name, "role": role, "installed": inst,
            "latest": latest, "outdated": outdated,
        })
    return rows


def render(rows: list[dict]) -> tuple[str, int]:
    """Return (text_report, n_outdated)."""
    width = max(len(r["name"]) for r in rows)
    lines = [f"{'package'.ljust(width)}  installed  latest    status"]
    lines.append("-" * (width + 30))
    outdated = []
    for r in rows:
        inst = r["installed"] or "-"
        latest = r["latest"] or "?"
        if r["installed"] is None:
            status = "not installed"
        elif r["outdated"]:
            status = "OUTDATED"
            outdated.append(r["name"])
        elif r["latest"] is None:
            status = "unknown (offline?)"
        else:
            status = "up to date"
        lines.append(f"{r['name'].ljust(width)}  {inst:<9}  {latest:<8}  {status}")
    report = "\n".join(lines)
    if outdated:
        report += "\n\nUpgrade:\n  pip install -U " + " ".join(outdated)
    return report, len(outdated)


# --- doctor --policy ---------------------------------------------------------
# Versions that understand a policy_version 2 file. Older consumers load one
# without error but silently drop what they don't know, and no release can reach
# back into already-installed code, so this check is how an operator finds out.
_V2_FLOORS = {"agentbastion": "0.12.0", "bastiongateway": "0.8.0"}


def _v2_features(text: str) -> tuple[bool, bool, bool]:
    """(is_v2, has_detectors, has_gate_block) of a policy file. JSON (as `harden`
    can emit) is parsed properly; YAML is scanned for top-level (column 0) keys,
    which is all this check needs and keeps bastionsupply dependency-free."""
    try:
        data = json.loads(text)
    except ValueError:
        data = None
    if isinstance(data, dict):
        return data.get("policy_version") == 2, "detectors" in data, "gate" in data
    import re

    def top_level(key: str) -> bool:
        return re.search(rf"^{key}\s*:", text, re.M) is not None

    is_v2 = re.search(r"""^policy_version\s*:\s*["']?2["']?\s*(#.*)?$""", text, re.M) is not None
    return is_v2, top_level("detectors"), top_level("gate")


# Flow-guard knobs (bastiongateway 0.9). Unlike v2 keys these can appear in a v1
# file (top-level or under a per-tool `tools:` entry), where an older gate drops
# them silently: a block the operator wrote would never happen.
_FLOW_FLOOR = "0.9.0"
_FLOW_KEYS = ("scan_flows", "on_tainted_egress", "label_packs", "labels")


def _flow_keys(text: str) -> list[str]:
    """Flow-guard keys present anywhere in the file (any nesting depth)."""
    try:
        data = json.loads(text)
    except ValueError:
        data = None
    if isinstance(data, (dict, list)):
        found: set[str] = set()
        stack = [data]
        while stack:
            node = stack.pop()
            if isinstance(node, dict):
                found.update(k for k in node if k in _FLOW_KEYS)
                stack.extend(node.values())
            elif isinstance(node, list):
                stack.extend(node)
        return sorted(found)
    import re

    return sorted(k for k in _FLOW_KEYS if re.search(rf"^\s*{k}\s*:", text, re.M))


# Knobs added in bastiongateway 0.10: an older gate drops them silently from a v1 file
# and refuses a v2 file that sets them (unknown key).
_ENCODED_FLOOR = "0.13.0"  # gateway 0.10-0.12 were never published: 0.13.0 is the first
_ENCODED_KEYS = ("on_encoded_result", "decode_transforms", "scan_resources")
# later gate keys, each with the first bastiongateway that knows it
_GATE_KEY_FLOORS = {"scan_prompts": "0.13.0", "taint_group": "0.13.0"}
# Detector added in agentbastion 0.14: an older agentbastion refuses a v2 file naming it.
_DETECTOR_FLOORS = {"bastion.decoded_payload": "0.14.0"}


def _keys_present(text: str, keys) -> list[str]:
    """Which of `keys` appear as KEYS (any nesting depth), not in comments or values."""
    try:
        data = json.loads(text)
    except ValueError:
        data = None
    if isinstance(data, (dict, list)):
        found: set[str] = set()
        stack = [data]
        while stack:
            node = stack.pop()
            if isinstance(node, dict):
                found.update(k for k in node if k in keys)
                stack.extend(node.values())
            elif isinstance(node, list):
                stack.extend(node)
        return sorted(found)
    import re

    return sorted(k for k in keys if re.search(rf"^[ \t-]*['\"]?{re.escape(k)}['\"]?\s*:", text, re.M))


def policy_warnings(text: str, installed=installed_version) -> list[str]:
    """Warnings for installed consumers too old for this policy file."""
    warnings = []
    gw = installed("bastiongateway")
    encoded = _keys_present(text, _ENCODED_KEYS)
    if encoded and gw and _key(gw)[:3] < _key(_ENCODED_FLOOR):
        warnings.append(
            f"bastiongateway {gw} does not know {', '.join(encoded)}: it ignores them in a v1 policy "
            "(encoded injections in tool results and injections in resource content will NOT be "
            f"blocked) and refuses to load a policy_version 2 file. Needs >= {_ENCODED_FLOOR}: "
            "pip install -U bastiongateway"
        )
    for key in _keys_present(text, tuple(_GATE_KEY_FLOORS)):
        floor = _GATE_KEY_FLOORS[key]
        if gw and _key(gw)[:3] < _key(floor):
            warnings.append(
                f"bastiongateway {gw} does not know {key}: it ignores it in a v1 policy (the setting "
                f"has NO effect) and refuses to load a policy_version 2 file. Needs >= {floor}: "
                "pip install -U bastiongateway"
            )
    ab_now = installed("agentbastion")
    for det_id in _keys_present(text, tuple(_DETECTOR_FLOORS)):
        floor = _DETECTOR_FLOORS[det_id]
        if ab_now and _key(ab_now)[:3] < _key(floor):
            warnings.append(
                f"agentbastion {ab_now} does not know detector {det_id} and refuses to load this "
                f"policy (unknown detector). Needs >= {floor}: pip install -U agentbastion"
            )
    flow = _flow_keys(text)
    if flow and gw and _key(gw)[:3] < _key(_FLOW_FLOOR):
        warnings.append(
            f"bastiongateway {gw} ignores the flow-guard key(s) {', '.join(flow)} in this "
            "policy: tainted egress will NOT be warned about or blocked. "
            f"Needs >= {_FLOW_FLOOR}: pip install -U bastiongateway"
        )
    is_v2, has_detectors, has_gate_block = _v2_features(text)
    if not is_v2:
        return warnings
    ab = installed("agentbastion")
    if has_detectors and ab and _key(ab)[:3] < _key(_V2_FLOORS["agentbastion"]):
        warnings.append(
            f"agentbastion {ab} ignores `detectors:` in this policy_version 2 file: the kill "
            f"switch / shadow modes will NOT apply. Needs >= {_V2_FLOORS['agentbastion']}: "
            "pip install -U agentbastion"
        )
    if (has_detectors or has_gate_block) and gw and _key(gw)[:3] < _key(_V2_FLOORS["bastiongateway"]):
        warnings.append(
            f"bastiongateway {gw} ignores `detectors:` and the whole `gate:` block in this "
            "policy_version 2 file: every gate knob silently falls back to its defaults. "
            f"Needs >= {_V2_FLOORS['bastiongateway']}: pip install -U bastiongateway"
        )
    return warnings


def run(as_json: bool = False, check_pypi: bool = True, policy: str | None = None) -> int:
    rows = collect(check_pypi=check_pypi)
    policy_notes: list[str] = []
    if policy is not None:
        from pathlib import Path

        try:
            text = Path(policy).read_text(encoding="utf-8")
        except OSError as e:
            print(f"doctor: cannot read policy file {policy}: {e.strerror or e}")
            return 2
        policy_notes = policy_warnings(text, installed_version)
    if as_json:
        print(json.dumps({"packages": rows, "policy_warnings": policy_notes} if policy else rows, indent=2))
        return 1 if any(r["outdated"] for r in rows) or policy_notes else 0
    report, n_outdated = render(rows)
    print(report)
    if policy is not None:
        print(f"\nPolicy {policy}:")
        print("\n".join(f"  WARNING: {w}" for w in policy_notes) if policy_notes
              else "  ok: installed consumers understand this policy file")
    return 1 if n_outdated or policy_notes else 0

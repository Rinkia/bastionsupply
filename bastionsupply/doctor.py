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


def run(as_json: bool = False, check_pypi: bool = True) -> int:
    rows = collect(check_pypi=check_pypi)
    if as_json:
        print(json.dumps(rows, indent=2))
        return 1 if any(r["outdated"] for r in rows) else 0
    report, n_outdated = render(rows)
    print(report)
    return 1 if n_outdated else 0

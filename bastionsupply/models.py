"""Immutable data model for MCP supply-chain scanning.

A `Server` holds the tool definitions returned by an MCP server's `tools/list`.
Checks read a `Server` and emit `Finding`s; a `ScanReport` collects them.
"""

from __future__ import annotations

from dataclasses import dataclass, field

SEVERITIES = ("critical", "high", "medium", "low")
_RANK = {s: i for i, s in enumerate(SEVERITIES)}  # 0 = worst


@dataclass(frozen=True)
class Tool:
    """One MCP tool definition (a row of `tools/list`)."""

    name: str
    description: str = ""
    input_schema: dict = field(default_factory=dict)

    @property
    def param_text(self) -> str:
        """Flat text of every param name + description, for scanning."""
        props = (self.input_schema or {}).get("properties", {})
        parts = []
        for pname, spec in props.items():
            parts.append(str(pname))
            if isinstance(spec, dict) and spec.get("description"):
                parts.append(str(spec["description"]))
        return "\n".join(parts)


@dataclass(frozen=True)
class Server:
    """A named MCP server and the tools it advertises."""

    name: str
    tools: tuple[Tool, ...] = ()
    source: str = ""  # command line, url, or file path it came from


@dataclass(frozen=True)
class Finding:
    """One risk detected by a check."""

    check: str  # check id, e.g. "tool-poisoning"
    severity: str  # one of SEVERITIES
    tool: str  # tool name, or "" for server-level
    message: str
    evidence: str = ""

    def __post_init__(self) -> None:
        if self.severity not in _RANK:
            raise ValueError(f"bad severity {self.severity!r}")


@dataclass(frozen=True)
class ScanReport:
    """Result of scanning one server."""

    server: str
    tool_count: int
    findings: tuple[Finding, ...] = ()

    @property
    def risk(self) -> str:
        """Worst severity present, or 'clean'."""
        if not self.findings:
            return "clean"
        return min((f.severity for f in self.findings), key=lambda s: _RANK[s])

    @property
    def ok(self) -> bool:
        """True when nothing critical or high was found."""
        return self.risk in ("clean", "medium", "low")

    def counts(self) -> dict[str, int]:
        out = {s: 0 for s in SEVERITIES}
        for f in self.findings:
            out[f.severity] += 1
        return out

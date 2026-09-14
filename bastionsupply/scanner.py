"""Scan a Server into a ScanReport."""

from __future__ import annotations

from .checks import run_checks
from .models import ScanReport, Server


def scan(server: Server) -> ScanReport:
    findings = tuple(run_checks(server))
    return ScanReport(server=server.name, tool_count=len(server.tools), findings=findings)

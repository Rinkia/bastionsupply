"""bastionsupply command line.

    bastionsupply scan tools.json                 # offline scan of a tools dump
    bastionsupply scan --stdio "npx server" --live # spawn + scan a stdio server
    bastionsupply scan --config mcp.json --live    # scan every server in a config
    bastionsupply lock tools.json -o supply.lock   # pin tool hashes
    bastionsupply verify tools.json --lock f.lock  # detect rug-pull drift
    bastionsupply harden tools.json -o policy.yaml # emit agentbastion policy
"""

from __future__ import annotations

import argparse
import sys

from . import fetch, harden, lockfile, report
from .models import Server
from .scanner import scan


def _load(args) -> list[Server]:
    """Resolve a scan target into one or more Servers."""
    if args.config:
        if not args.live:
            _die("--config requires --live (it spawns each server to list tools)")
        servers = []
        for spec in fetch.discover_servers(args.config):
            if args.server and spec["name"] != args.server:
                continue
            servers.append(
                fetch.fetch_stdio(spec["command"], spec["args"], spec["env"], name=spec["name"])
            )
        if not servers:
            _die("no matching stdio servers in config")
        return servers
    if args.stdio:
        if not args.live:
            _die("--stdio requires --live (it spawns the server)")
        cmd, cmd_args = fetch.parse_stdio_spec(args.stdio)
        return [fetch.fetch_stdio(cmd, cmd_args, name=args.name or "")]
    if args.http:
        if not args.live:
            _die("--http requires --live (it contacts a remote server)")
        return [fetch.fetch_http(args.http, name=args.name or "")]
    if not args.target:
        _die("give a tools.json path, or --stdio/--config with --live")
    return [fetch.load_json_file(args.target, name=args.name)]


def _add_target_flags(p) -> None:
    p.add_argument("target", nargs="?", help="path to a tools/list JSON dump")
    p.add_argument("--stdio", help='live: spawn "command arg1 arg2" and scan it')
    p.add_argument("--http", help="live: a remote MCP Streamable-HTTP server URL")
    p.add_argument("--config", help="live: an mcp.json / Claude config to enumerate")
    p.add_argument("--server", help="with --config: only this server name")
    p.add_argument("--live", action="store_true", help="allow spawning server processes")
    p.add_argument("--name", help="override server name label")


def _make_output_unicode_safe() -> None:
    # tool names/evidence can carry non-ASCII (that's the homoglyph attack we
    # report); a cp1252 console must not crash printing them.
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="backslashreplace")
        except (AttributeError, ValueError):
            pass


def main(argv=None) -> int:
    _make_output_unicode_safe()
    ap = argparse.ArgumentParser(prog="bastionsupply", description=__doc__)
    sub = ap.add_subparsers(dest="cmd", required=True)

    ps = sub.add_parser("scan", help="scan MCP tools for supply-chain risks")
    _add_target_flags(ps)
    ps.add_argument("--json", action="store_true", help="emit JSON")
    ps.add_argument("--sarif", action="store_true", help="emit SARIF 2.1.0 (GitHub code scanning)")

    pl = sub.add_parser("lock", help="write a lockfile of tool hashes")
    _add_target_flags(pl)
    pl.add_argument("-o", "--out", required=True)

    pv = sub.add_parser("verify", help="detect rug-pull drift vs a lockfile")
    _add_target_flags(pv)
    pv.add_argument("--lock", required=True)

    ph = sub.add_parser("harden", help="emit an agentbastion tool policy")
    _add_target_flags(ph)
    ph.add_argument("-o", "--out", help="write policy.yaml (default: stdout)")

    pd = sub.add_parser("doctor", help="check installed Bastion tools against PyPI")
    pd.add_argument("--json", action="store_true", help="emit JSON")
    pd.add_argument("--offline", action="store_true",
                    help="skip PyPI, just list installed versions")

    args = ap.parse_args(argv)

    if args.cmd == "scan":
        return _cmd_scan(args)
    if args.cmd == "lock":
        return _cmd_lock(args)
    if args.cmd == "verify":
        return _cmd_verify(args)
    if args.cmd == "harden":
        return _cmd_harden(args)
    if args.cmd == "doctor":
        from . import doctor
        return doctor.run(as_json=args.json, check_pypi=not args.offline)
    return 2


def _cmd_scan(args) -> int:
    worst_ok = True
    for i, server in enumerate(_load(args)):
        rep = scan(server)
        if args.sarif:
            from . import sarif
            print(sarif.to_sarif(rep))
        elif args.json:
            print(report.to_json(rep))
        else:
            if i:
                print()
            print(report.to_text(rep))
        worst_ok = worst_ok and rep.ok
    return 0 if worst_ok else 1


def _cmd_lock(args) -> int:
    server = _load(args)[0]
    lockfile.write_lock(server, args.out)
    print(f"locked {len(server.tools)} tools -> {args.out}")
    return 0


def _cmd_verify(args) -> int:
    server = _load(args)[0]
    drift = lockfile.verify(server, lockfile.load_lock(args.lock))
    if drift.clean:
        print(f"verify: {server.name} matches lockfile ({len(server.tools)} tools)")
        return 0
    print(f"verify: DRIFT in {server.name}")
    if drift.changed:
        print(f"  CHANGED (possible rug-pull): {', '.join(drift.changed)}")
    if drift.added:
        print(f"  added:   {', '.join(drift.added)}")
    if drift.removed:
        print(f"  removed: {', '.join(drift.removed)}")
    return 1


def _cmd_harden(args) -> int:
    server = _load(args)[0]
    rep = scan(server)
    yaml = harden.to_policy_yaml(rep, server.tools)
    if args.out:
        from pathlib import Path

        Path(args.out).write_text(yaml, encoding="utf-8")
        print(f"wrote policy -> {args.out}")
    else:
        sys.stdout.write(yaml)
    return 0


def _die(msg: str) -> None:
    print(f"bastionsupply: {msg}", file=sys.stderr)
    raise SystemExit(2)


if __name__ == "__main__":
    raise SystemExit(main())

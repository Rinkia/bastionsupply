"""bastionsupply command line.

    bastionsupply scan tools.json                 # offline scan of a tools dump
    bastionsupply scan --stdio "npx server" --live # spawn + scan a stdio server
    bastionsupply scan --config mcp.json --live    # scan every server in a config
    bastionsupply lock tools.json -o supply.lock   # pin tool hashes
    bastionsupply verify tools.json --lock f.lock  # detect rug-pull drift
    bastionsupply harden tools.json -o policy.yaml # emit agentbastion policy
    bastionsupply scan --a2a https://agent.example --live  # scan a remote A2A agent card
    bastionsupply scan --example poisoned-card     # try it on a bundled sample
"""

from __future__ import annotations

import argparse
import sys
from dataclasses import replace

from . import fetch, harden, lockfile, report
from .models import Server
from .scanner import scan


def _load(args) -> list[Server]:
    """Resolve a scan target into one or more Servers; a bad target is exit 2, not a traceback."""
    try:
        return _load_target(args)
    except (OSError, ValueError, RuntimeError, RecursionError) as e:
        _die(f"cannot load target: {type(e).__name__}: {e}")
        raise  # unreachable: _die exits


def _load_target(args) -> list[Server]:
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
    if args.a2a:
        if not args.live:
            _die("--a2a requires --live (it contacts a remote agent)")
        return [fetch.fetch_agent_card(args.a2a, name=args.name or "")]
    if args.example:
        return [fetch.load_json_file(_example_path(args.example), name=args.name)]
    if not args.target:
        _die("give a tools.json or agent-card path, --example NAME, or --stdio/--config/--http/--a2a with --live")
    return [fetch.load_json_file(args.target, name=args.name)]


def _add_target_flags(p) -> None:
    p.add_argument("target", nargs="?", help="path to a tools/list JSON dump")
    p.add_argument("--stdio", help='live: spawn "command arg1 arg2" and scan it')
    p.add_argument("--http", help="live: a remote MCP Streamable-HTTP server URL")
    p.add_argument("--config", help="live: an mcp.json / Claude config to enumerate")
    p.add_argument("--server", help="with --config: only this server name")
    p.add_argument("--a2a", metavar="URL", help="live: a remote A2A agent (origin or agent-card URL)")
    p.add_argument("--example", metavar="NAME",
                   help="a bundled sample: " + ", ".join(_example_names()))
    p.add_argument("--live", action="store_true",
                   help="allow network access or spawning server processes")
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
    ps.add_argument("--ignore", action="append", default=[], metavar="CHECK_ID",
                    help="drop findings of this check (repeatable), e.g. --ignore a2a-no-auth")

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
    pd.add_argument("--policy", metavar="FILE",
                    help="also check that installed consumers understand this policy file "
                         "(policy_version 2 needs agentbastion>=0.12, bastiongateway>=0.8)")

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
        return doctor.run(as_json=args.json, check_pypi=not args.offline, policy=args.policy)
    return 2


def _cmd_scan(args) -> int:
    worst_ok = True
    ignore = set(args.ignore)
    for i, server in enumerate(_load(args)):
        rep = scan(server)
        if ignore:
            rep = replace(rep, findings=tuple(f for f in rep.findings if f.check not in ignore))
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
    if drift.card_changed:
        print("  card changed (auth, endpoints or text differ from the pinned card)")
    return 1


def _cmd_harden(args) -> int:
    server = _load(args)[0]
    if server.kind == "a2a":
        print("harden: A2A skills are not agent tool names; nothing to emit. "
              "Use lock/verify to pin the card.", file=sys.stderr)
        return 2
    rep = scan(server)
    yaml = harden.to_policy_yaml(rep, server.tools)
    if args.out:
        from pathlib import Path

        Path(args.out).write_text(yaml, encoding="utf-8")
        print(f"wrote policy -> {args.out}")
    else:
        sys.stdout.write(yaml)
    return 0


def _example_dir():
    from importlib.resources import files

    return files("bastionsupply") / "fixtures"


def _example_names() -> list[str]:
    return sorted(p.name[:-5] for p in _example_dir().iterdir() if p.name.endswith(".json"))


def _example_path(name: str):
    path = _example_dir() / f"{name}.json"
    if not path.is_file():
        _die(f"no example {name!r}; available: {', '.join(_example_names())}")
    return path


def _die(msg: str) -> None:
    print(f"bastionsupply: {msg}", file=sys.stderr)
    raise SystemExit(2)


if __name__ == "__main__":
    raise SystemExit(main())

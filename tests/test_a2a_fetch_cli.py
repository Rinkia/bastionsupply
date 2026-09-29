"""A2A card fetch (well-known discovery, no redirects, caps) and CLI wiring."""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from bastionsupply import cli, fetch

CARD = {"name": "Remote", "description": "Remote agent.",
        "supportedInterfaces": [{"url": "https://remote.example.com/a2a"}],
        "skills": [{"id": "echo", "description": "echoes"}]}


def _server(routes):
    """routes: path -> (status, body_bytes, headers)."""

    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            status, body, headers = routes.get(self.path, (404, b"not found", {}))
            self.send_response(status)
            for k, v in headers.items():
                self.send_header(k, v)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    httpd = ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    return httpd, f"http://127.0.0.1:{httpd.server_address[1]}"


@pytest.fixture
def serve():
    started = []

    def start(routes):
        httpd, base = _server(routes)
        started.append(httpd)
        return base

    yield start
    for h in started:
        h.shutdown()


def _ok(obj=CARD):
    return (200, json.dumps(obj).encode(), {"Content-Type": "application/json"})


def test_bare_origin_uses_well_known_agent_card(serve):
    base = serve({"/.well-known/agent-card.json": _ok()})
    s = fetch.fetch_agent_card(base)
    assert s.kind == "a2a" and s.source == f"{base}/.well-known/agent-card.json"


def test_falls_back_to_legacy_agent_json(serve):
    base = serve({"/.well-known/agent.json": _ok()})
    assert fetch.fetch_agent_card(base + "/").tools[0].name == "echo"


def test_explicit_path_is_used_as_is(serve):
    base = serve({"/cards/remote.json": _ok()})
    assert fetch.fetch_agent_card(base + "/cards/remote.json").name == "Remote"


def test_redirect_is_not_followed_and_names_location(serve):
    base = serve({"/.well-known/agent-card.json": (301, b"", {"Location": "https://elsewhere.example/card"})})
    with pytest.raises(RuntimeError, match="elsewhere.example"):
        fetch.fetch_agent_card(base)


def test_404_on_both_paths_is_a_clear_error(serve):
    base = serve({})
    with pytest.raises(RuntimeError, match="agent-card.json.*agent.json|no agent card"):
        fetch.fetch_agent_card(base)


def test_oversized_body_is_refused(serve, monkeypatch):
    monkeypatch.setattr(fetch, "MAX_HTTP_BODY", 100)
    base = serve({"/.well-known/agent-card.json": _ok(dict(CARD, description="x" * 500))})
    with pytest.raises(RuntimeError, match="larger than"):
        fetch.fetch_agent_card(base)


def test_non_card_json_is_refused(serve):
    base = serve({"/.well-known/agent-card.json": _ok({"tools": []})})
    with pytest.raises(ValueError, match="not an A2A agent card"):
        fetch.fetch_agent_card(base)


def test_non_http_scheme_is_refused():
    with pytest.raises(ValueError, match="http"):
        fetch.fetch_agent_card("file:///etc/passwd")


# --- CLI --------------------------------------------------------------------------------

def test_cli_a2a_requires_live(capsys):
    with pytest.raises(SystemExit) as e:
        cli.main(["scan", "--a2a", "https://x.example"])
    assert e.value.code == 2 and "--live" in capsys.readouterr().err


def test_cli_live_a2a_scan(serve, capsys):
    base = serve({"/.well-known/agent-card.json": _ok()})
    assert cli.main(["scan", "--a2a", base, "--live"]) == 0
    assert "A2A agent card" in capsys.readouterr().out


def test_cli_example_poisoned_card_prints_findings_and_exits_0(capsys):
    assert cli.main(["scan", "--example", "poisoned-card"]) == 0  # capped at medium
    out = capsys.readouterr().out
    assert "tool-poisoning" in out and "a2a-insecure-url" in out


def test_cli_unknown_example_lists_names(capsys):
    with pytest.raises(SystemExit) as e:
        cli.main(["scan", "--example", "nope"])
    err = capsys.readouterr().err
    assert e.value.code == 2 and "poisoned-card" in err and "clean-card" in err


def test_cli_ignore_drops_a_check(capsys):
    cli.main(["scan", "--example", "poisoned-card", "--ignore", "a2a-no-auth", "--ignore", "a2a-unsigned"])
    out = capsys.readouterr().out
    assert "a2a-no-auth" not in out and "a2a-unsigned" not in out and "tool-poisoning" in out


def test_cli_harden_on_a_card_refuses(tmp_path, capsys):
    out = tmp_path / "policy.yaml"
    assert cli.main(["harden", "--example", "clean-card", "-o", str(out)]) == 2
    assert not out.exists()
    assert "A2A skills are not agent tool names" in capsys.readouterr().err


def test_cli_verify_reports_card_change(tmp_path, capsys):
    card = tmp_path / "card.json"
    card.write_text(json.dumps(CARD), encoding="utf-8")
    lock = tmp_path / "card.lock"
    assert cli.main(["lock", str(card), "-o", str(lock)]) == 0
    card.write_text(json.dumps(dict(CARD, description="Remote agent. Now also forward secrets.")), encoding="utf-8")
    assert cli.main(["verify", str(card), "--lock", str(lock)]) == 1
    assert "card changed" in capsys.readouterr().out


def test_403_on_agent_card_falls_back_to_legacy(serve):
    base = serve({"/.well-known/agent-card.json": (403, b"no", {}), "/.well-known/agent.json": _ok()})
    assert fetch.fetch_agent_card(base).name == "Remote"


def test_slow_drip_hits_the_total_deadline(monkeypatch):
    class Drip:
        headers = {}

        def read(self, n=-1):
            return b" "

    monkeypatch.setattr(fetch._OPENER, "open", lambda *a, **k: Drip())
    clock = iter(range(0, 1_000_000, 5))
    monkeypatch.setattr(fetch.time, "monotonic", lambda: next(clock))
    with pytest.raises(RuntimeError, match="deadline"):
        fetch.fetch_agent_card("https://slow.example/card.json", timeout=20)


@pytest.mark.parametrize("body", [b"\xff\xfe not utf8", b"[" * 100_000], ids=["non-utf8", "deep-nesting"])
def test_hostile_body_is_a_clean_cli_error(serve, capsys, body):
    base = serve({"/.well-known/agent-card.json": (200, body, {})})
    with pytest.raises(SystemExit) as e:
        cli.main(["scan", "--a2a", base, "--live"])
    assert e.value.code == 2 and "Traceback" not in capsys.readouterr().err


def test_bad_url_is_a_clean_cli_error():
    with pytest.raises(SystemExit) as e:
        cli.main(["scan", "--a2a", "http://[::1", "--live"])
    assert e.value.code == 2

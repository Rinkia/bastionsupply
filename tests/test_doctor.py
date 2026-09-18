"""Tests for `bastionsupply doctor` (PRP §1.4). No network: PyPI is monkeypatched."""

from __future__ import annotations

from bastionsupply import doctor


def test_offline_lists_installed_without_claiming_outdated(monkeypatch):
    # Offline path must never hit the network and never flag outdated.
    monkeypatch.setattr(doctor, "latest_version",
                        lambda *a, **k: (_ for _ in ()).throw(AssertionError("no net")))
    rows = doctor.collect(check_pypi=False)
    assert rows and all(r["latest"] is None for r in rows)
    assert not any(r["outdated"] for r in rows)


def test_outdated_detected_and_upgrade_line_rendered(monkeypatch):
    monkeypatch.setattr(doctor, "installed_version",
                        lambda name: "0.1.0" if name == "bastionsupply" else None)
    monkeypatch.setattr(doctor, "latest_version", lambda name, **k: "0.4.0")
    rows = doctor.collect(check_pypi=True)
    supply = next(r for r in rows if r["name"] == "bastionsupply")
    assert supply["outdated"] is True
    report, n = doctor.render(rows)
    assert n == 1
    assert "pip install -U bastionsupply" in report


def test_up_to_date_not_flagged(monkeypatch):
    monkeypatch.setattr(doctor, "installed_version",
                        lambda name: "0.4.0" if name == "bastionsupply" else None)
    monkeypatch.setattr(doctor, "latest_version", lambda name, **k: "0.4.0")
    rows = doctor.collect(check_pypi=True)
    supply = next(r for r in rows if r["name"] == "bastionsupply")
    assert supply["outdated"] is False
    _, n = doctor.render(rows)
    assert n == 0


def test_offline_latest_returns_none(monkeypatch):
    import urllib.error

    def boom(*a, **k):
        raise urllib.error.URLError("offline")

    monkeypatch.setattr(doctor.urllib.request, "urlopen", boom)
    assert doctor.latest_version("bastionsupply") is None


def test_version_key_orders():
    assert doctor._key("0.10.0") > doctor._key("0.9.9")

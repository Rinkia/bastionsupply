"""Rug-pull detection: pin tool definitions, detect later drift.

A server can advertise benign tools, earn trust, then silently change a tool's
description to a poisoned one. `lock` snapshots a hash per tool; `verify` diffs a
current scan against the snapshot and flags added / removed / mutated tools.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path

from .models import Server, Tool


def _tool_hash(t: Tool) -> str:
    payload = json.dumps(
        {"name": t.name, "description": t.description, "inputSchema": t.input_schema},
        sort_keys=True,
        ensure_ascii=False,
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _card_hash(card: dict) -> str:
    """The WHOLE card, canonical: dropping securitySchemes or adding an endpoint is drift."""
    # ensure_ascii escapes everything, lone surrogates included (hostile JSON can carry them)
    payload = json.dumps(card, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(payload.encode("ascii")).hexdigest()


def make_lock(server: Server) -> dict:
    lock = {
        "server": server.name,
        "source": server.source,
        "tools": {t.name: _tool_hash(t) for t in server.tools},
    }
    if server.kind == "a2a":
        lock["card"] = {"sha256": _card_hash(server.card)}
    return lock


def write_lock(server: Server, path: str | Path) -> None:
    Path(path).write_text(json.dumps(make_lock(server), indent=2), encoding="utf-8")


def load_lock(path: str | Path) -> dict:
    return json.loads(Path(path).read_text(encoding="utf-8"))


@dataclass(frozen=True)
class Drift:
    added: tuple[str, ...]
    removed: tuple[str, ...]
    changed: tuple[str, ...]
    card_changed: bool = False  # A2A: anything in the card changed (auth, endpoints, text)

    @property
    def clean(self) -> bool:
        return not (self.added or self.removed or self.changed or self.card_changed)


def verify(server: Server, lock: dict) -> Drift:
    old = lock.get("tools", {})
    new = {t.name: _tool_hash(t) for t in server.tools}
    added = tuple(sorted(n for n in new if n not in old))
    removed = tuple(sorted(n for n in old if n not in new))
    changed = tuple(sorted(n for n in new if n in old and new[n] != old[n]))
    pinned = lock.get("card")
    old_card = pinned.get("sha256") if isinstance(pinned, dict) else pinned
    new_card = _card_hash(server.card) if server.kind == "a2a" else None
    return Drift(added=added, removed=removed, changed=changed, card_changed=old_card != new_card)

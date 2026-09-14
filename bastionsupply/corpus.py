"""Shared prompt-injection signatures from bastioncorpus.

bastioncorpus is the one canonical injection dataset the whole bastion family
consumes. Here we use its malicious rows as extra literal signatures for the
tool-poisoning check: if a tool description/parameter contains a known attack
string verbatim, that's a strong signal the regex heuristics might miss.

Degrades gracefully: if the corpus can't load, returns no signatures and the
regex heuristics still run.
"""

from __future__ import annotations

from functools import lru_cache

_MIN_LEN = 20  # only distinctive phrases, to avoid false positives


@lru_cache(maxsize=1)
def poison_signatures() -> tuple[tuple[str, str], ...]:
    """(category, lowercased phrase) for each distinctive malicious corpus row."""
    try:
        from bastioncorpus import load_corpus
    except Exception:
        return ()
    sigs: list[tuple[str, str]] = []
    seen: set[str] = set()
    for row in load_corpus():
        if not getattr(row, "is_malicious", False):
            continue
        phrase = row.stripped().lower()  # canary placeholder removed
        if len(phrase) >= _MIN_LEN and phrase not in seen:
            seen.add(phrase)
            sigs.append((row.category, phrase))
    return tuple(sigs)

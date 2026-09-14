"""Optional semantic poisoning tier.

Embeds a tool's text and compares it to the distinct malicious *intents* from
bastioncorpus (`to_semantic`). Catches paraphrased injections the literal
regex/substring checks miss. Off unless an embedder is configured:

    BASTIONSUPPLY_EMBED_MODEL   a local sentence-transformers model (no egress)
    BASTIONSUPPLY_SEMANTIC_THRESHOLD   cosine cutoff (default 0.60)

Install the extra:  pip install "bastionsupply[semantic]"
"""

from __future__ import annotations

import math
import os
from functools import lru_cache


@lru_cache(maxsize=1)
def _templates() -> tuple[str, ...]:
    from bastioncorpus import load_corpus, to_semantic

    return tuple(to_semantic(load_corpus())["templates"])


@lru_cache(maxsize=1)
def build_detector():
    """Return `score(text) -> float` (max cosine vs malicious intents), or None
    when no embedder is configured."""
    model_name = os.environ.get("BASTIONSUPPLY_EMBED_MODEL")
    if not model_name:
        return None
    embed = _local_embedder(model_name)
    tvecs = embed(list(_templates()))

    def score(text: str) -> float:
        vec = embed([text])[0]
        return max((_cosine(vec, t) for t in tvecs), default=0.0)

    return score


def _local_embedder(model_name: str):
    model = _load_st_model(model_name)

    def embed(texts):
        vecs = model.encode(list(texts), normalize_embeddings=True)
        return vecs.tolist() if hasattr(vecs, "tolist") else [list(v) for v in vecs]

    return embed


def _load_st_model(model_name: str):
    try:
        from sentence_transformers import SentenceTransformer
    except ImportError as e:
        raise RuntimeError(
            'BASTIONSUPPLY_EMBED_MODEL needs sentence-transformers: '
            'pip install "bastionsupply[semantic]"'
        ) from e
    return SentenceTransformer(model_name)


def _cosine(a, b) -> float:
    dot = sum(x * y for x, y in zip(a, b))
    na = math.sqrt(sum(x * x for x in a))
    nb = math.sqrt(sum(y * y for y in b))
    return dot / (na * nb) if na and nb else 0.0


def threshold() -> float:
    return float(os.environ.get("BASTIONSUPPLY_SEMANTIC_THRESHOLD", "0.60"))

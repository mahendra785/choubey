"""Text embeddings for the RAG bot.

Preferred: sentence-transformers ``all-MiniLM-L6-v2`` (as specified). If that optional package is not
installed we fall back to a deterministic hashed bag-of-words embedder so the app and tests still run.
The fallback is clearly named so results never silently claim MiniLM was used.
"""
from __future__ import annotations

import hashlib
import re
from typing import Protocol

import numpy as np


class Embedder(Protocol):
    name: str

    def encode(self, texts: list[str]) -> np.ndarray: ...


class HashingEmbedder:
    """Hashed bag-of-words + bigrams, L2-normalised. Deterministic, dependency-free."""

    name = "hashing-bow-512"

    def __init__(self, dim: int = 512) -> None:
        self.dim = dim

    def encode(self, texts: list[str]) -> np.ndarray:
        out = np.zeros((len(texts), self.dim), dtype=np.float32)
        for i, t in enumerate(texts):
            words = re.findall(r"[a-z0-9]+", t.lower())
            for tok in words + [a + "_" + b for a, b in zip(words, words[1:])]:
                h = int.from_bytes(hashlib.md5(tok.encode()).digest()[:4], "little")
                out[i, h % self.dim] += 1.0
            n = np.linalg.norm(out[i])
            if n:
                out[i] /= n
        return out


class SentenceTransformerEmbedder:
    name = "sentence-transformers/all-MiniLM-L6-v2"

    def __init__(self) -> None:
        from sentence_transformers import SentenceTransformer  # optional heavy dependency

        self._model = SentenceTransformer("sentence-transformers/all-MiniLM-L6-v2", device="cpu")

    def encode(self, texts: list[str]) -> np.ndarray:
        return np.asarray(self._model.encode(texts, normalize_embeddings=True), dtype=np.float32)


_default: Embedder | None = None


def default_embedder() -> Embedder:
    global _default
    if _default is None:
        try:
            _default = SentenceTransformerEmbedder()
        except Exception:  # ImportError, or model download unavailable offline
            _default = HashingEmbedder()
    return _default

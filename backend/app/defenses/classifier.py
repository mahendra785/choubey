"""Stage-1 detector: P(injection | text).

Two interchangeable back-ends behind one protocol:
  * DebertaClassifier - fine-tuned microsoft/deberta-v3-small (the specified model), CPU inference.
  * TfidfClassifier   - TF-IDF + logistic regression (scikit-learn). A fast, weaker fallback that lets the whole
                        pipeline (and the conformal machinery) run without a GPU or torch; also a useful ablation.
Both are trained by ml/train_detector.py and loaded from the artifacts directory.
"""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Protocol

import numpy as np

from app.defenses.base import Action, Decision, Defense, DefenseContext, Timer

CHUNK_CHARS = 1200  # texts longer than this are scored in overlapping chunks (max over chunks)
CHUNK_STRIDE = 800


class InjectionClassifier(Protocol):
    name: str

    def predict_proba(self, texts: list[str]) -> np.ndarray:
        """P(injection) for each text, shape (n,)."""
        ...


def chunk(text: str) -> list[str]:
    if len(text) <= CHUNK_CHARS:
        return [text]
    return [text[i:i + CHUNK_CHARS] for i in range(0, len(text) - CHUNK_CHARS + CHUNK_STRIDE, CHUNK_STRIDE)]


def score_text(clf: InjectionClassifier, text: str) -> float:
    """Score one (possibly long) text. Long documents: an injection hidden at the end must not be diluted."""
    parts = chunk(text)
    return float(np.max(clf.predict_proba(parts)))


class DebertaClassifier:
    def __init__(self, model_dir: str | Path, max_length: int = 192, batch_size: int = 16) -> None:
        import torch  # heavy optional dependency, imported lazily
        from transformers import AutoModelForSequenceClassification, AutoTokenizer

        self._torch = torch
        self.name = f"deberta-v3-small@{Path(model_dir).name}"
        self.tok = AutoTokenizer.from_pretrained(str(model_dir))
        self.model = AutoModelForSequenceClassification.from_pretrained(str(model_dir)).to("cpu").eval()
        self.max_length, self.batch_size = max_length, batch_size

    def predict_proba(self, texts: list[str]) -> np.ndarray:
        out: list[np.ndarray] = []
        with self._torch.no_grad():
            for i in range(0, len(texts), self.batch_size):
                enc = self.tok(texts[i:i + self.batch_size], truncation=True, max_length=self.max_length,
                               padding=True, return_tensors="pt")
                logits = self.model(**enc).logits
                out.append(self._torch.softmax(logits, dim=-1)[:, 1].numpy())
        return np.concatenate(out) if out else np.zeros(0)


class TfidfClassifier:
    def __init__(self, path: str | Path) -> None:
        import joblib

        self.name = "tfidf-logreg"
        self.pipe = joblib.load(path)

    def predict_proba(self, texts: list[str]) -> np.ndarray:
        return self.pipe.predict_proba(texts)[:, 1]


def load_classifier(artifacts_dir: str | Path, prefer: str = "deberta") -> InjectionClassifier | None:
    d = Path(artifacts_dir)
    deberta, tfidf = d / "deberta", d / "tfidf.joblib"
    order = [("deberta", deberta), ("tfidf", tfidf)] if prefer == "deberta" else [("tfidf", tfidf), ("deberta", deberta)]
    for kind, path in order:
        if path.exists():
            try:
                return DebertaClassifier(path) if kind == "deberta" else TfidfClassifier(path)
            except Exception:  # missing optional dependency etc. -> try the next back-end
                continue
    return None


def load_calibration(artifacts_dir: str | Path, name: str = "calibration.json") -> tuple[np.ndarray, np.ndarray, dict] | None:
    """Calibration set predictions saved by ml/calibrate.py: (P(injection), labels, metadata)."""
    f = Path(artifacts_dir) / name
    if not f.exists():
        return None
    data = json.loads(f.read_text())
    return np.asarray(data["probs"], float), np.asarray(data["labels"], int), {k: v for k, v in data.items() if k not in ("probs", "labels")}


class ClassifierDefense(Defense):
    """Plain classifier at a fixed probability threshold (the non-conformal baseline)."""

    name = "classifier"

    def __init__(self, clf: InjectionClassifier, threshold: float = 0.5) -> None:
        self.clf, self.threshold = clf, threshold

    def inspect_input(self, text: str, source: str = "user", ctx: DefenseContext | None = None) -> Decision:
        with Timer() as t:
            p = score_text(self.clf, text)
        return Decision(Action.block if p >= self.threshold else Action.allow, p, f"P(injection)={p:.3f} vs threshold {self.threshold}",
                        t.ms, self.name, extra={"p": p, "model": self.clf.name})

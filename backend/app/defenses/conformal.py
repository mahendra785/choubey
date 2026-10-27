"""Split conformal prediction with Mondrian (class-conditional) calibration - written by hand.

THE MATH (binary task: y=0 benign, y=1 injection; the classifier outputs p1 = P(injection | x)):

* Nonconformity score of a labelled example: s(x, y) = 1 - p_y(x), where p_0 = 1 - p1 and p_1 = p1.
  A LARGE score means "the model finds label y surprising for x".
* Calibration (split conformal): hold out a calibration set the classifier was NOT trained on. Because we
  want a guarantee *per class* (Mondrian), for each class y we collect the scores of calibration examples whose
  true label is y: S_y = { s(x_i, y_i) : y_i = y }, n_y = |S_y|.
* Threshold: q_y = the ceil((n_y + 1)(1 - alpha))-th smallest value of S_y. This is the (1-alpha) empirical
  quantile with the *finite-sample correction* (n+1 instead of n). If ceil(...) > n_y the class has too few
  calibration points for this alpha and we set q_y = +inf (the class is then always included, i.e. we
  stay safe by becoming less decisive).
* Prediction set for a new x:  C(x) = { y : s(x, y) <= q_y } = { y : 1 - p_y(x) <= q_y }.

THE GUARANTEE: if the calibration points of class y and a fresh test point of class y are EXCHANGEABLE
(roughly: drawn from the same distribution, order irrelevant), then
        P( y_true in C(X) | Y = y )  >=  1 - alpha        for each class y,
marginally over the draw of the calibration set. In particular the miss rate on the INJECTION class is
at most alpha - the property a plain 0.5-threshold classifier does not have. The guarantee is only as good as
the exchangeability assumption: it can fail under distribution shift (new attack styles) - which is why
we test on a held-out OOD split and report the empirical coverage honestly.

Sets can be {benign}, {injection}, {benign, injection} (model torn -> escalate) or {} (neither class is
plausible at the chosen alpha -> also escalate).
"""
from __future__ import annotations

import math
from dataclasses import dataclass

import numpy as np

BENIGN, INJECTION = 0, 1


def quantile_rank(n: int, alpha: float) -> int:
    """1-based rank k = ceil((n+1)(1-alpha)) of the conformal quantile among n sorted scores."""
    return math.ceil((n + 1) * (1.0 - alpha))


@dataclass
class MondrianConformal:
    alpha: float = 0.1
    qhat: dict[int, float] | None = None
    n_cal: dict[int, int] | None = None

    def calibrate(self, probs: np.ndarray, labels: np.ndarray, alpha: float) -> "MondrianConformal":
        """Fit the per-class thresholds from calibration data.

        probs  : P(injection | x) for each calibration example, shape (n,)
        labels : true labels (0 benign / 1 injection), shape (n,)
        """
        if not 0.0 < alpha < 1.0:
            raise ValueError("alpha must be in (0, 1)")
        probs = np.asarray(probs, dtype=float)
        labels = np.asarray(labels, dtype=int)
        if probs.shape != labels.shape:
            raise ValueError("probs and labels must have the same shape")
        p_true = np.where(labels == INJECTION, probs, 1.0 - probs)  # p_y(x_i) for the TRUE label
        scores = 1.0 - p_true
        qhat: dict[int, float] = {}
        counts: dict[int, int] = {}
        for y in (BENIGN, INJECTION):
            s = np.sort(scores[labels == y])
            n = len(s)
            counts[y] = n
            k = quantile_rank(n, alpha)
            qhat[y] = float(s[k - 1]) if 1 <= k <= n else math.inf
        self.alpha, self.qhat, self.n_cal = alpha, qhat, counts
        return self

    def _require_fit(self) -> dict[int, float]:
        if self.qhat is None:
            raise RuntimeError("call calibrate() first")
        return self.qhat

    def predict_set(self, prob_injection: float) -> frozenset[int]:
        """Prediction set for one example, given its P(injection)."""
        q = self._require_fit()
        members = set()
        if 1.0 - prob_injection <= q[INJECTION]:  # s(x, injection) = 1 - p1
            members.add(INJECTION)
        if prob_injection <= q[BENIGN]:  # s(x, benign) = 1 - (1 - p1) = p1
            members.add(BENIGN)
        return frozenset(members)

    def predict_sets(self, probs: np.ndarray) -> list[frozenset[int]]:
        return [self.predict_set(float(p)) for p in probs]

    @staticmethod
    def evaluate(sets: list[frozenset[int]], labels: np.ndarray) -> dict[str, float]:
        """Empirical coverage (overall + per class), average set size, and share of ambiguous sets."""
        labels = np.asarray(labels, dtype=int)
        covered = np.array([int(y) in s for s, y in zip(sets, labels)])
        out = {
            "coverage": float(covered.mean()) if len(labels) else float("nan"),
            "avg_set_size": float(np.mean([len(s) for s in sets])) if sets else float("nan"),
            "escalation_rate": float(np.mean([len(s) != 1 for s in sets])) if sets else float("nan"),
        }
        for y, name in ((BENIGN, "benign"), (INJECTION, "injection")):
            m = labels == y
            out[f"coverage_{name}"] = float(covered[m].mean()) if m.any() else float("nan")
        return out

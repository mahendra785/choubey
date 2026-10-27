"""Compute and save the detector's predictions needed by the conformal layer.

Writes ml/artifacts/<name>:
  calibration.json   P(injection) + labels on the CALIBRATION split (the only data the conformal quantiles use)
  predictions.json   P(injection) + labels + texts on the TEST and OOD splits (for the alpha sweep), plus the
                     model's single-text CPU latency (the cost of stage 1).
The conformal thresholds themselves are cheap and are recomputed at run time for any alpha
(backend/app/defenses/conformal.py), so one calibration file serves the whole alpha sweep.

  python ml/calibrate.py --backbone deberta
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import numpy as np

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))
from app.defenses.classifier import load_classifier  # noqa: E402

DATA, ART = ROOT / "ml" / "data", ROOT / "ml" / "artifacts"


def read(name: str) -> list[dict]:
    return [json.loads(l) for l in (DATA / f"{name}.jsonl").read_text(encoding="utf-8").split(chr(10)) if l.strip()]


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--backbone", choices=["deberta", "tfidf"], default="deberta")
    args = ap.parse_args()
    clf = load_classifier(ART, prefer=args.backbone)
    if clf is None:
        sys.exit("no trained detector found in ml/artifacts - run ml/train_detector.py first")
    meta = {"model": clf.name, "created": datetime.now(timezone.utc).isoformat(timespec="seconds")}

    cal = read("cal")
    cal_probs = clf.predict_proba([r["text"] for r in cal])
    (ART / "calibration.json").write_text(json.dumps({**meta, "n": len(cal), "probs": cal_probs.tolist(), "labels": [r["label"] for r in cal]}))

    preds = {}
    for split in ("test", "ood"):
        rows = read(split)
        preds[split] = {"texts": [r["text"] for r in rows], "labels": [r["label"] for r in rows],
                        "categories": [r.get("category") for r in rows], "probs": clf.predict_proba([r["text"] for r in rows]).tolist()}
    sample = preds["test"]["texts"][:100]
    clf.predict_proba(sample[:4])  # warm-up
    t0 = time.perf_counter()
    for t in sample:
        clf.predict_proba([t])
    latency = (time.perf_counter() - t0) * 1000 / max(1, len(sample))
    (ART / "predictions.json").write_text(json.dumps({**meta, "clf_latency_ms_single": latency, "splits": preds}))
    print(f"calibration n={len(cal)}; test n={len(preds['test']['labels'])}; ood n={len(preds['ood']['labels'])}; single-text CPU latency {latency:.1f} ms ({clf.name})")


if __name__ == "__main__":
    main()

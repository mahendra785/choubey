"""Experiment orchestration.

Two experiment kinds:
  end_to_end       targets x attack payloads x defense configs (+ benign prompts x configs) through the real
                   target apps and a real LLM; success judged ONLY by the canary oracle.
  conformal_sweep  detection-level study of the conformal gate across alpha on the held-out TEST and OOD
                   splits: empirical coverage vs 1-alpha, average set size, escalation rate, and (when an LLM
                   judge is available) detection quality and latency of cascade vs judge-only vs classifier@0.5.
Every number in a summary is computed from rows recorded in this run - none is hard-coded.
"""
from __future__ import annotations

import json
import logging
import random
import time
from pathlib import Path
from typing import Any, Callable

import numpy as np
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.attacks.benign import benign_prompts
from app.attacks.library import DEFAULT_OOD_CATEGORIES, Payload, for_target, load_payloads
from app.attacks.mutator import Mutator
from app.attacks.runner import record_outcome, run_attack, run_benign
from app.core.config import Settings
from app.db.models import Experiment, ExperimentResult, utcnow
from app.defenses.classifier import load_calibration, load_classifier
from app.defenses.conformal import MondrianConformal
from app.defenses.llm_judge import LLMJudge
from app.defenses.registry import PRESETS, ConfigError, DefenseDeps, build_pipeline
from app.eval import metrics
from app.llm.client import ChatLLM, LLMError
from app.targets import TARGET_CLASSES, make_target

log = logging.getLogger("promptshield.experiment")
RESULT_KEYS = ["kind", "target", "defense", "payload_id", "category", "vector", "ood", "success", "blocked", "escalated",
               "latency_ms", "defense_latency_ms", "llm_calls", "forbidden_tool", "canary_form"]


def load_detector_deps(settings: Settings, llm: ChatLLM | None) -> DefenseDeps:
    """Load the trained detector + calibration data if they exist (otherwise detector-based defenses are unavailable).

    The calibration file records which model produced it. Conformal thresholds are only valid for THAT model, so
    if the loadable classifier differs (e.g. DeBERTa was calibrated but torch is not installed here) we refuse to
    pair them: the cascade is simply unavailable rather than silently wrong.
    """
    cal = load_calibration(settings.artifacts_dir)
    prefer = "tfidf" if cal and str(cal[2].get("model", "")).startswith("tfidf") else "deberta"
    clf = load_classifier(settings.artifacts_dir, prefer=prefer)
    if cal and clf is not None and cal[2].get("model") != clf.name:
        log.warning("calibration was made for %s but the loaded classifier is %s; conformal defenses disabled", cal[2].get("model"), clf.name)
        cal = None
    return DefenseDeps(llm=llm, classifier=clf, cal_probs=cal[0] if cal else None, cal_labels=cal[1] if cal else None)


def resolve_defenses(names: list[str], custom: dict[str, dict[str, Any]], deps: DefenseDeps) -> dict[str, dict[str, Any]]:
    """name -> {"stages": [...]}. Names are presets or entries of ``custom`` (user DefenseConfigs). Validates by building once."""
    out: dict[str, dict[str, Any]] = {}
    for n in names:
        cfg = custom.get(n) or ({"stages": PRESETS[n]} if n in PRESETS else None)
        if cfg is None:
            raise ConfigError(f"unknown defense '{n}'")
        build_pipeline(cfg, deps, n)  # raises ConfigError if unavailable (e.g. detector not trained)
        out[n] = cfg
    return out


def select_payloads(target: str, categories: list[str] | None, n_variants: int, max_payloads: int, seed: int) -> list[Payload]:
    base = [p for p in for_target(load_payloads(), target) if not categories or p.category in categories]
    pool = base + (Mutator(seed=seed).expand(base, n_variants) if n_variants else [])
    pool = sorted(pool, key=lambda p: p.id)
    random.Random(f"{seed}:{target}").shuffle(pool)
    return pool[:max_payloads]


def row_dicts(db: Session, experiment_id: str) -> list[dict[str, Any]]:
    rows = db.scalars(select(ExperimentResult).where(ExperimentResult.experiment_id == experiment_id))
    return [{k: getattr(r, k) for k in RESULT_KEYS} for r in rows]


def run_end_to_end(db: Session, exp: Experiment, llm: ChatLLM, deps: DefenseDeps, defenses: dict[str, dict[str, Any]],
                   on_progress: Callable[[], None] | None = None) -> dict[str, Any]:
    cfg = exp.config
    targets = cfg["targets"]
    ood_cats = cfg.get("ood_categories", DEFAULT_OOD_CATEGORIES)
    plan: list[tuple[str, str, str, Any]] = []  # (target, defense, kind, item)
    for t in targets:
        attacks = select_payloads(t, cfg.get("categories"), cfg.get("n_variants", 0), cfg.get("max_payloads", 200), exp.seed)
        benign = benign_prompts(t, cfg.get("benign_per_target", 50), exp.seed) if cfg.get("include_benign", True) else []
        for d in defenses:
            plan += [(t, d, "attack", p) for p in attacks] + [(t, d, "benign", b) for b in benign]
    exp.total, exp.completed, exp.status = len(plan), 0, "running"
    db.commit()

    errors = 0
    for i, (t, d, kind, item) in enumerate(plan, 1):
        pipeline = build_pipeline(defenses[d], deps, d)  # fresh pipeline (fresh spotlight tag) and fresh target (fresh canary)
        target = make_target(t, llm, pipeline)
        try:
            if kind == "attack":
                out = run_attack(target, item)
                record_outcome(db, exp.id, "attack", d, out, item.id, item.category, item.vector, item.category in ood_cats)
            else:
                out = run_benign(target, item.text)
                record_outcome(db, exp.id, "benign", d, out, item.id, "benign", "direct", False)
        except LLMError as e:
            errors += 1
            log.warning("LLM error during run %d/%d: %s", i, len(plan), str(e)[:120])
            if errors > 10 and errors > 0.3 * i:
                raise RuntimeError(f"aborting: too many LLM errors ({errors}/{i})") from e
        exp.completed = i
        db.commit()  # commit every run: progress is visible immediately and write locks are held only briefly
        if on_progress and i % 10 == 0:
            on_progress()
    db.commit()
    summary = metrics.full_summary(row_dicts(db, exp.id), seed=exp.seed)
    summary["errors"] = errors
    return summary


# ----------------------------------------------------------------------------------------------
# Conformal sweep
# ----------------------------------------------------------------------------------------------
def load_predictions(artifacts_dir: str) -> dict[str, Any] | None:
    f = Path(artifacts_dir) / "predictions.json"
    return json.loads(f.read_text()) if f.exists() else None


def conformal_sweep(preds: dict[str, Any], cal_probs: np.ndarray, cal_labels: np.ndarray, alphas: list[float],
                    judge: LLMJudge | None = None, max_judge: int = 200, seed: int = 0) -> dict[str, Any]:
    """Coverage / set size / escalation across alpha on each split, and (with a judge) detection + latency comparison."""
    clf_ms = float(preds.get("clf_latency_ms_single", 0.0))
    out: dict[str, Any] = {"classifier": preds.get("model"), "alphas": alphas, "clf_latency_ms": clf_ms,
                           "n_calibration": int(len(cal_labels)), "splits": {}, "detection": {}}
    judge_cache: dict[str, tuple[bool, float, int]] = {}  # text -> (is_injection, latency_ms, parsed)

    def judged(text: str) -> tuple[bool, float]:
        if text not in judge_cache:
            v = judge.judge(text)  # type: ignore[union-attr]
            judge_cache[text] = (v.injection, v.latency_ms, int(v.parsed))
        return judge_cache[text][0], judge_cache[text][1]

    for split, d in preds["splits"].items():
        probs, labels = np.asarray(d["probs"], float), np.asarray(d["labels"], int)
        rows = []
        for a in alphas:
            cp = MondrianConformal().calibrate(cal_probs, cal_labels, a)
            sets = cp.predict_sets(probs)
            stats = MondrianConformal.evaluate(sets, labels)
            rows.append({"alpha": a, "target_coverage": 1 - a, **stats, "qhat": {str(k): (v if np.isfinite(v) else None) for k, v in cp.qhat.items()}})
        out["splits"][split] = {"n": int(len(labels)), "rows": rows,
                                "classifier_at_0.5": metrics.detection_metrics(probs >= 0.5, labels)}
        if judge is None:
            continue
        # Detection-level comparison on a seeded sample (judge calls cost real LLM time).
        idx = np.random.default_rng(seed).permutation(len(labels))[:max_judge]
        sp, sl = probs[idx], labels[idx]
        texts = [d["texts"][i] for i in idx]
        judge_only = [judged(t)[0] for t in texts]
        judge_ms = np.array([judged(t)[1] for t in texts])
        det = {"n": int(len(idx)), "judge_only": {**metrics.detection_metrics(judge_only, sl), "latency_ms_mean": float(judge_ms.mean()),
                                                  "llm_calls_per_request": 1.0},
               "classifier_at_0.5": {**metrics.detection_metrics(sp >= 0.5, sl), "latency_ms_mean": clf_ms, "llm_calls_per_request": 0.0},
               "cascade": []}
        for a in alphas:
            cp = MondrianConformal().calibrate(cal_probs, cal_labels, a)
            sets = cp.predict_sets(sp)
            esc = np.array([len(s) != 1 for s in sets])
            blocked = [(judged(t)[0] if e else (1 in s)) for t, s, e in zip(texts, sets, esc)]
            lat = clf_ms + np.where(esc, judge_ms, 0.0)
            det["cascade"].append({"alpha": a, **metrics.detection_metrics(blocked, sl), "escalation_rate": float(esc.mean()),
                                   "latency_ms_mean": float(lat.mean()), "latency_ms_p95": float(np.percentile(lat, 95)),
                                   "llm_calls_per_request": float(esc.mean())})
        out["detection"][split] = det
    return out


def run_conformal_sweep(db: Session, exp: Experiment, settings: Settings, llm: ChatLLM | None) -> dict[str, Any]:
    preds = load_predictions(settings.artifacts_dir)
    cal = load_calibration(settings.artifacts_dir)
    if preds is None or cal is None:
        raise RuntimeError("no predictions/calibration found - run ml/train_detector.py and ml/calibrate.py first")
    exp.status, exp.total = "running", 1
    db.commit()
    judge = LLMJudge(llm) if llm is not None and exp.config.get("use_judge", True) else None
    t0 = time.time()
    try:
        out = conformal_sweep(preds, cal[0], cal[1], exp.config["alphas"], judge, exp.config.get("max_judge", 200), exp.seed)
    except LLMError as e:  # LLM unreachable: still report the judge-free part honestly
        out = conformal_sweep(preds, cal[0], cal[1], exp.config["alphas"], None, 0, exp.seed)
        out["judge_error"] = str(e)[:200]
    out["judge_used"] = judge is not None and "judge_error" not in out
    out["seconds"] = round(time.time() - t0, 1)
    exp.completed = 1
    return out


def finish(db: Session, exp: Experiment, summary: dict[str, Any] | None, error: str | None = None) -> None:
    exp.summary, exp.error = summary, error
    exp.status = "failed" if error else "done"
    exp.finished_at = utcnow()
    db.commit()


def execute(db: Session, exp: Experiment, settings: Settings, llm: ChatLLM | None, deps: DefenseDeps,
            defenses: dict[str, dict[str, Any]] | None) -> None:
    """Run an experiment to completion, always leaving it in a terminal state."""
    try:
        if exp.kind == "conformal_sweep":
            summary = run_conformal_sweep(db, exp, settings, llm)
        else:
            if llm is None:
                raise RuntimeError("no LLM configured")
            summary = run_end_to_end(db, exp, llm, deps, defenses or {})
        finish(db, exp, summary)
    except Exception as e:  # noqa: BLE001 - surface any failure on the experiment record
        db.rollback()
        log.exception("experiment %s failed", exp.id)
        exp = db.get(Experiment, exp.id)
        finish(db, exp, None, f"{type(e).__name__}: {str(e)[:300]}")

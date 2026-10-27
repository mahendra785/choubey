"""Build defense pipelines from plain-dict configs (so they can live in the DB / come from the API).

Config shape:
    {"stages": [{"type": "sanitizer"}, {"type": "spotlighting"}, {"type": "cascade", "alpha": 0.1},
                {"type": "output_guard", "use_known_secrets": false}]}
Only whitelisted stage types and parameters are accepted - the config is attacker-influenced input.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import numpy as np

from app.defenses.base import Defense
from app.defenses.cascade import ConformalCascade
from app.defenses.classifier import ClassifierDefense, InjectionClassifier
from app.defenses.conformal import MondrianConformal
from app.defenses.llm_judge import LLMJudge
from app.defenses.output_guard import OutputGuard
from app.defenses.pipeline import DefensePipeline
from app.defenses.sanitizer import Sanitizer
from app.defenses.spotlighting import Spotlighting
from app.llm.client import ChatLLM

ALPHAS = [0.01, 0.05, 0.1, 0.2]

PRESETS: dict[str, list[dict[str, Any]]] = {
    "none": [],
    "sanitizer": [{"type": "sanitizer"}],
    "spotlighting": [{"type": "spotlighting"}],
    "output_guard": [{"type": "output_guard"}],
    "classifier_0.5": [{"type": "classifier", "threshold": 0.5}],
    "llm_judge": [{"type": "llm_judge"}],
    **{f"cascade_a{a}": [{"type": "cascade", "alpha": a}] for a in ALPHAS},
    "full_stack": [{"type": "sanitizer"}, {"type": "spotlighting"}, {"type": "cascade", "alpha": 0.1}, {"type": "output_guard"}],
}
_ALLOWED_PARAMS = {
    "sanitizer": {"threshold"}, "spotlighting": {"datamark"}, "output_guard": {"use_known_secrets"},
    "classifier": {"threshold"}, "llm_judge": set(), "cascade": {"alpha"},
}
NEEDS_DETECTOR = {"classifier", "cascade"}
NEEDS_LLM = {"llm_judge", "cascade"}


@dataclass
class DefenseDeps:
    """Shared, expensive-to-build resources (created once per experiment, not per request)."""

    llm: ChatLLM | None = None
    classifier: InjectionClassifier | None = None
    cal_probs: np.ndarray | None = None
    cal_labels: np.ndarray | None = None


class ConfigError(ValueError):
    pass


def validate_config(config: dict[str, Any]) -> list[dict[str, Any]]:
    stages = config.get("stages")
    if not isinstance(stages, list) or len(stages) > 8:
        raise ConfigError("config.stages must be a list of at most 8 stages")
    for st in stages:
        if not isinstance(st, dict) or st.get("type") not in _ALLOWED_PARAMS:
            raise ConfigError(f"unknown stage type: {st.get('type') if isinstance(st, dict) else st!r}")
        extra = set(st) - {"type"} - _ALLOWED_PARAMS[st["type"]]
        if extra:
            raise ConfigError(f"unknown parameters for {st['type']}: {sorted(extra)}")
        for key in ("alpha", "threshold"):
            if key in st and not (isinstance(st[key], (int, float)) and 0 < st[key] < 1):
                raise ConfigError(f"{key} must be a number in (0, 1)")
    return stages


def build_pipeline(config: dict[str, Any], deps: DefenseDeps, name: str = "custom") -> DefensePipeline:
    defenses: list[Defense] = []
    for st in validate_config(config):
        kind = st["type"]
        if kind in NEEDS_DETECTOR and (deps.classifier is None):
            raise ConfigError(f"'{kind}' needs a trained detector (run ml/train_detector.py and ml/calibrate.py)")
        if kind == "cascade" and deps.cal_probs is None:
            raise ConfigError("'cascade' needs calibration data (run ml/calibrate.py)")
        if kind in NEEDS_LLM and deps.llm is None and kind == "llm_judge":
            raise ConfigError("'llm_judge' needs an LLM client")
        if kind == "sanitizer":
            defenses.append(Sanitizer(**{k: v for k, v in st.items() if k != "type"}))
        elif kind == "spotlighting":
            defenses.append(Spotlighting(**{k: v for k, v in st.items() if k != "type"}))
        elif kind == "output_guard":
            defenses.append(OutputGuard(**{k: v for k, v in st.items() if k != "type"}))
        elif kind == "classifier":
            defenses.append(ClassifierDefense(deps.classifier, st.get("threshold", 0.5)))  # type: ignore[arg-type]
        elif kind == "llm_judge":
            defenses.append(LLMJudge(deps.llm))  # type: ignore[arg-type]
        elif kind == "cascade":
            alpha = float(st.get("alpha", 0.1))
            conf = MondrianConformal().calibrate(deps.cal_probs, deps.cal_labels, alpha)  # type: ignore[arg-type]
            judge = LLMJudge(deps.llm) if deps.llm is not None else None
            defenses.append(ConformalCascade(deps.classifier, conf, judge, alpha))  # type: ignore[arg-type]
    return DefensePipeline(defenses, name=name)


def preset_pipeline(name: str, deps: DefenseDeps) -> DefensePipeline:
    if name not in PRESETS:
        raise ConfigError(f"unknown defense preset '{name}'")
    return build_pipeline({"stages": PRESETS[name]}, deps, name=name)


def preset_available(name: str, deps: DefenseDeps) -> bool:
    try:
        preset_pipeline(name, deps)
        return True
    except ConfigError:
        return False

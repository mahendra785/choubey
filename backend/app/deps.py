"""Shared FastAPI dependencies for heavyweight resources (overridable in tests via app.dependency_overrides)."""
from __future__ import annotations

from functools import lru_cache

from sqlalchemy.orm import sessionmaker

from app.core.config import get_settings
from app.db.session import SessionLocal
from app.defenses.registry import DefenseDeps
from app.eval.experiment import load_detector_deps
from app.llm.client import ChatLLM, client_from_settings


@lru_cache
def get_llm() -> ChatLLM:
    """One pooled client per process (creating it does not contact the server)."""
    return client_from_settings(get_settings())


@lru_cache
def _detector_deps_cached() -> DefenseDeps:
    return load_detector_deps(get_settings(), None)


def get_defense_deps() -> DefenseDeps:
    """Detector + calibration are loaded once; the LLM is attached per request."""
    base = _detector_deps_cached()
    return DefenseDeps(llm=get_llm(), classifier=base.classifier, cal_probs=base.cal_probs, cal_labels=base.cal_labels)


def get_session_factory() -> sessionmaker:
    """Background jobs open their own sessions (a request session closes when the response is sent)."""
    return SessionLocal

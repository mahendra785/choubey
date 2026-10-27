"""Target app registry."""
from __future__ import annotations

from app.defenses.pipeline import DefensePipeline
from app.llm.client import ChatLLM
from app.targets.base import RunContext, TargetApp, TargetResponse
from app.targets.email_agent import EmailAgent
from app.targets.rag_bot import RagBot
from app.targets.support_bot import SupportBot

TARGET_CLASSES: dict[str, type[TargetApp]] = {
    "rag_bot": RagBot,
    "email_agent": EmailAgent,
    "support_bot": SupportBot,
}


def make_target(name: str, llm: ChatLLM, pipeline: DefensePipeline | None = None, canary: str | None = None, **kw) -> TargetApp:
    """Build a FRESH target (new random canary unless one is given)."""
    if name not in TARGET_CLASSES:
        raise KeyError(f"unknown target '{name}'")
    return TARGET_CLASSES[name](llm, canary=canary, pipeline=pipeline, **kw)


__all__ = ["TARGET_CLASSES", "make_target", "RunContext", "TargetApp", "TargetResponse"]

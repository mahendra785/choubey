"""Attack payload library: loads + validates the YAML files in ``payloads/``."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field

from app.attacks.transforms import expand_directives

PAYLOAD_DIR = Path(__file__).parent / "payloads"
CATEGORIES = ["direct_override", "role_play", "indirect_injection", "obfuscation", "payload_splitting",
              "multi_turn_escalation", "tool_hijack", "prompt_extraction"]
# Categories held out of detector training to measure generalisation (see ml/prepare_data.py).
DEFAULT_OOD_CATEGORIES = ["obfuscation", "payload_splitting"]
ALL_TARGETS = ["rag_bot", "email_agent", "support_bot"]


class PayloadSpec(BaseModel):
    """Schema of one YAML entry. Unknown keys are an error so typos cannot silently drop data."""

    model_config = ConfigDict(extra="forbid")
    id: str = Field(max_length=64)
    category: Literal[tuple(CATEGORIES)]  # type: ignore[valid-type]
    technique: str
    vector: Literal["direct", "indirect"]
    text: str
    multi_turn: list[str] | None = None
    target_compat: list[str]
    user_query: str | None = None  # indirect only: the benign request that makes the app read the planted content


@dataclass(frozen=True)
class Payload:
    id: str
    category: str
    technique: str
    vector: str
    text: str
    multi_turn: tuple[str, ...] | None
    target_compat: tuple[str, ...]
    user_query: str | None = None
    parent_id: str | None = None  # set on mutated variants
    mutation: str | None = None

    @property
    def turns(self) -> list[str]:
        return list(self.multi_turn) if self.multi_turn else [self.text]

    @property
    def is_ood(self) -> bool:
        return self.category in DEFAULT_OOD_CATEGORIES


def load_payloads(directory: Path = PAYLOAD_DIR) -> list[Payload]:
    out: list[Payload] = []
    seen: set[str] = set()
    for f in sorted(directory.glob("*.yaml")):
        entries = yaml.safe_load(f.read_text(encoding="utf-8")) or []
        for raw in entries:
            spec = PayloadSpec(**raw)
            if spec.id in seen:
                raise ValueError(f"duplicate payload id {spec.id}")
            seen.add(spec.id)
            bad = set(spec.target_compat) - set(ALL_TARGETS)
            if bad:
                raise ValueError(f"{spec.id}: unknown target_compat {bad}")
            out.append(Payload(
                id=spec.id, category=spec.category, technique=spec.technique, vector=spec.vector,
                text=expand_directives(spec.text.strip()),
                multi_turn=tuple(expand_directives(t.strip()) for t in spec.multi_turn) if spec.multi_turn else None,
                target_compat=tuple(spec.target_compat), user_query=spec.user_query,
            ))
    return out


def for_target(payloads: list[Payload], target: str) -> list[Payload]:
    return [p for p in payloads if target in p.target_compat]

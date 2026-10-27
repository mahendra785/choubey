"""Request/response models. Every request model forbids unknown fields and bounds every string."""
from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

EMAIL_PATTERN = r"^[^@\s]{1,64}@[^@\s]{1,189}\.[^@\s]{2,}$"


class StrictModel(BaseModel):
    """Base for all request bodies: unknown fields are an error, not silently ignored."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    @model_validator(mode="before")
    @classmethod
    def reject_nul(cls, data: Any) -> Any:
        """PostgreSQL cannot store NUL characters in text; reject them up front (422) instead of failing with a 500."""
        def walk(v: Any) -> None:
            if isinstance(v, str) and chr(0) in v:
                raise ValueError("NUL characters are not allowed")
            if isinstance(v, dict):
                for k, x in v.items():
                    walk(k)
                    walk(x)
            elif isinstance(v, list):
                for x in v:
                    walk(x)

        walk(data)
        return data


# ---------- auth / users ----------
class LoginRequest(StrictModel):
    email: str = Field(max_length=254, pattern=EMAIL_PATTERN)
    password: str = Field(min_length=1, max_length=128)

    @field_validator("email")
    @classmethod
    def lower(cls, v: str) -> str:
        return v.lower()


class UserOut(BaseModel):
    id: str
    email: str
    role: str
    is_active: bool


class LoginResponse(BaseModel):
    user: UserOut
    csrf_token: str


class CreateUserRequest(StrictModel):
    email: str = Field(max_length=254, pattern=EMAIL_PATTERN)
    password: str = Field(min_length=12, max_length=128)
    role: Literal["admin", "researcher", "viewer"] = "viewer"

    @field_validator("email")
    @classmethod
    def lower(cls, v: str) -> str:
        return v.lower()


class ChangeRoleRequest(StrictModel):
    role: Literal["admin", "researcher", "viewer"]


class SetActiveRequest(StrictModel):
    is_active: bool


class AuditOut(BaseModel):
    seq: int
    ts: str
    actor_id: str | None
    action: str
    detail: str
    hash: str


class AuditVerifyOut(BaseModel):
    valid: bool
    checked: int
    broken_at_seq: int | None = None
    reason: str | None = None


# ---------- targets / attacks ----------
class RunRequest(StrictModel):
    target: str = Field(min_length=1, max_length=48)
    payload_id: str | None = Field(default=None, max_length=80)
    custom_text: str | None = Field(default=None, max_length=4000)
    defense: str = Field(default="none", max_length=64)
    alpha: float | None = Field(default=None, ge=0.001, le=0.5)
    vector: Literal["direct", "indirect"] = "direct"
    user_query: str | None = Field(default=None, max_length=1000)


class DefenseConfigRequest(StrictModel):
    name: str = Field(min_length=1, max_length=80)
    config: dict[str, Any]


class ExperimentRequest(StrictModel):
    name: str = Field(min_length=1, max_length=120)
    kind: Literal["end_to_end", "conformal_sweep"] = "end_to_end"
    targets: list[str] = Field(default_factory=lambda: ["support_bot"], max_length=3)
    defenses: list[str] = Field(default_factory=lambda: ["none"], max_length=20)
    include_benign: bool = True
    n_variants: int = Field(default=0, ge=0, le=5)
    max_payloads: int = Field(default=200, ge=1, le=1000)
    benign_per_target: int = Field(default=50, ge=0, le=500)
    categories: list[str] | None = Field(default=None, max_length=12)
    alphas: list[float] = Field(default_factory=lambda: [0.01, 0.05, 0.1, 0.2], max_length=8)
    seed: int = Field(default=1234, ge=0, le=2**31 - 1)


class SharedRequest(StrictModel):
    shared: bool

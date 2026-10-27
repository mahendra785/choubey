"""Password hashing, JWT access tokens, refresh tokens, CSRF tokens.

Design choices (each is a viva question):
* argon2id - memory-hard, the OWASP-recommended password hash.
* Short-lived (15 min) stateless JWT access token: a stolen token expires quickly.
* Long-lived refresh token is *opaque random bytes*, stored server-side only as a SHA-256 hash,
  and rotated on every use. Re-use of an already-rotated token revokes the whole token family
  (that is the signature of theft). See app/api/auth.py.
* CSRF: double-submit cookie. SameSite=Strict is the first line; the token check is defence in depth.
"""
from __future__ import annotations

import hashlib
import hmac
import secrets
from datetime import datetime, timedelta, timezone

import jwt
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError

from app.core.config import Settings

# argon2-cffi's PasswordHasher defaults to the argon2id variant.
_hasher = PasswordHasher()
# Verified against when the e-mail is unknown, so "no such user" costs the same time as "wrong password".
_DUMMY_HASH = _hasher.hash("dummy-password-for-timing-equalisation")

JWT_ALGORITHM = "HS256"
JWT_ISSUER = "promptshield"


def hash_password(password: str) -> str:
    return _hasher.hash(password)


def verify_password(password_hash: str | None, password: str) -> bool:
    try:
        return _hasher.verify(password_hash or _DUMMY_HASH, password) and password_hash is not None
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def password_needs_rehash(password_hash: str) -> bool:
    return _hasher.check_needs_rehash(password_hash)


def create_access_token(settings: Settings, user_id: str, role: str, now: datetime | None = None) -> str:
    now = now or datetime.now(timezone.utc)
    claims = {
        "sub": user_id,
        "role": role,
        "type": "access",
        "iss": JWT_ISSUER,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=settings.access_token_minutes)).timestamp()),
        "jti": secrets.token_hex(8),
    }
    return jwt.encode(claims, settings.jwt_secret, algorithm=JWT_ALGORITHM)


def decode_access_token(settings: Settings, token: str) -> dict | None:
    """Return claims, or None for any invalid/expired/wrong-type token. Never raises."""
    try:
        # Pin the algorithm list: prevents "alg: none" / algorithm-confusion attacks.
        claims = jwt.decode(
            token,
            settings.jwt_secret,
            algorithms=[JWT_ALGORITHM],
            issuer=JWT_ISSUER,
            options={"require": ["exp", "sub", "iss"]},
        )
    except jwt.PyJWTError:
        return None
    return claims if claims.get("type") == "access" else None


def new_opaque_token() -> str:
    return secrets.token_urlsafe(48)


def hash_token(token: str) -> str:
    """Deterministic hash for lookup. SHA-256 is fine because the input is 384 bits of randomness."""
    return hashlib.sha256(token.encode()).hexdigest()


def new_csrf_token() -> str:
    return secrets.token_urlsafe(32)


def tokens_match(a: str | None, b: str | None) -> bool:
    if not a or not b:
        return False
    return hmac.compare_digest(a.encode(), b.encode())

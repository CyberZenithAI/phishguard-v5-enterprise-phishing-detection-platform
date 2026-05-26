# app/auth.py

from datetime import datetime, timedelta, timezone
from typing import Optional, Dict, Any
import uuid

import jwt
from fastapi import Header, HTTPException, Depends

from app.core.config import settings


# =========================================================
# 🔐 SECURITY ENFORCEMENT (NO OVERRIDES ALLOWED)
# =========================================================

ALGORITHM = "HS512"

if settings.JWT_ALGORITHM != ALGORITHM:
    raise RuntimeError("Insecure JWT algorithm detected. Only HS512 is allowed.")


# =========================================================
# 🧠 TOKEN STORAGE (IN-MEMORY SAFE DEFAULT)
# NOTE: Replace with Redis in production cluster
# =========================================================

class TokenStore:
    """
    Handles refresh token rotation + revocation tracking.
    Designed for async-safe, low-latency operations.
    """

    def __init__(self):
        self._revoked_jti = set()
        self._refresh_store: Dict[str, dict] = {}

    def revoke(self, jti: str):
        self._revoked_jti.add(jti)

    def is_revoked(self, jti: str) -> bool:
        return jti in self._revoked_jti

    def save_refresh(self, jti: str, data: dict):
        self._refresh_store[jti] = data

    def get_refresh(self, jti: str) -> Optional[dict]:
        return self._refresh_store.get(jti)

    def delete_refresh(self, jti: str):
        self._refresh_store.pop(jti, None)


token_store = TokenStore()


# =========================================================
# 🔐 CORE JWT UTILITIES
# =========================================================

def _now():
    return datetime.now(timezone.utc)


def _generate_jti() -> str:
    return str(uuid.uuid4())


def _base_claims(subject: str) -> dict:
    now = _now()
    return {
        "sub": subject,
        "iat": now,
        "nbf": now,
        "iss": settings.JWT_ISSUER,
        "aud": settings.JWT_AUDIENCE,
        "jti": _generate_jti(),
    }


# =========================================================
# 🚀 TOKEN CREATION
# =========================================================

def create_access_token(subject: str) -> str:
    expire = _now() + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)

    payload = _base_claims(subject)
    payload.update({"exp": expire, "type": "access"})

    return jwt.encode(payload, settings.SECRET_KEY, algorithm=ALGORITHM)


def create_refresh_token(subject: str) -> str:
    expire = _now() + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)

    payload = _base_claims(subject)
    payload.update({"exp": expire, "type": "refresh"})

    token = jwt.encode(payload, settings.SECRET_KEY, algorithm=ALGORITHM)

    decoded = jwt.decode(token, settings.SECRET_KEY, algorithms=[ALGORITHM], audience=settings.JWT_AUDIENCE)

    token_store.save_refresh(decoded["jti"], decoded)

    return token


# =========================================================
# 🔍 TOKEN VALIDATION CORE
# =========================================================

def _decode_token(token: str) -> dict:
    try:
        return jwt.decode(
            token,
            settings.SECRET_KEY,
            algorithms=[ALGORITHM],
            issuer=settings.JWT_ISSUER,
            audience=settings.JWT_AUDIENCE,
            options={
                "require": ["exp", "iat", "nbf", "sub", "jti", "iss", "aud"],
            },
        )

    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="token_expired")

    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="invalid_token")


def verify_access_token(token: str) -> dict:
    payload = _decode_token(token)

    if payload.get("type") != "access":
        raise HTTPException(status_code=401, detail="invalid_token_type")

    if token_store.is_revoked(payload["jti"]):
        raise HTTPException(status_code=401, detail="token_revoked")

    return payload


def verify_refresh_token(token: str) -> dict:
    payload = _decode_token(token)

    if payload.get("type") != "refresh":
        raise HTTPException(status_code=401, detail="invalid_token_type")

    if token_store.is_revoked(payload["jti"]):
        raise HTTPException(status_code=401, detail="refresh_token_revoked")

    stored = token_store.get_refresh(payload["jti"])
    if not stored:
        raise HTTPException(status_code=401, detail="refresh_token_not_found")

    return payload


# =========================================================
# 🔁 REFRESH TOKEN ROTATION (ANTI-REPLAY)
# =========================================================

def rotate_refresh_token(refresh_token: str) -> Dict[str, str]:
    payload = verify_refresh_token(refresh_token)

    old_jti = payload["jti"]

    # revoke old token (anti-replay)
    token_store.revoke(old_jti)
    token_store.delete_refresh(old_jti)

    new_access = create_access_token(payload["sub"])
    new_refresh = create_refresh_token(payload["sub"])

    return {
        "access_token": new_access,
        "refresh_token": new_refresh,
    }


# =========================================================
# 🚫 TOKEN REVOCATION
# =========================================================

def revoke_token(jti: str):
    token_store.revoke(jti)


# =========================================================
# 🔐 FASTAPI DEPENDENCY (ZERO TRUST ENTRY POINT)
# =========================================================

async def verify(authorization: Optional[str] = Header(None)) -> dict:
    if not authorization:
        raise HTTPException(status_code=401, detail="missing_authorization_header")

    token = authorization.replace("Bearer ", "").strip()
    return verify_access_token(token)


# =========================================================
# 👤 CURRENT USER DEPENDENCY
# =========================================================

async def get_current_user(payload: dict = Depends(verify)) -> str:
    return payload["sub"]

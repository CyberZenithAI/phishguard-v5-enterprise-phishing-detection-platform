# app/security/jwt_hardening.py

from __future__ import annotations

import os
import secrets
from datetime import UTC, datetime, timedelta
from typing import Any

import jwt


class JWTHardening:

    MIN_SECRET_LENGTH = 64

    def __init__(self) -> None:

        self.secret = os.getenv("JWT_SECRET")

        if not self.secret:
            raise RuntimeError("missing_jwt_secret")

        if len(self.secret) < self.MIN_SECRET_LENGTH:
            raise RuntimeError("weak_jwt_secret")

        self.algorithm = "HS512"

    @staticmethod
    def generate_secret() -> str:
        return secrets.token_hex(64)

    def encode(
        self,
        payload: dict[str, Any],
        expires_minutes: int = 30,
    ) -> str:

        now = datetime.now(UTC)

        payload.update(
            {
                "iat": now,
                "nbf": now,
                "exp": now + timedelta(minutes=expires_minutes),
                "iss": "phishguard",
                "aud": "phishguard-users",
            }
        )

        return jwt.encode(
            payload,
            self.secret,
            algorithm=self.algorithm,
        )

    def decode(self, token: str) -> dict[str, Any]:

        return jwt.decode(
            token,
            self.secret,
            algorithms=[self.algorithm],
            audience="phishguard-users",
            issuer="phishguard",
        )

import jwt
import time
from app.security.secret_manager import SecretManager


class JWTService:
    def __init__(self, secret_manager: SecretManager):
        self.sm = secret_manager

    async def _get_secret(self):
        return await self.sm.get_secret(
            "jwt_secret",
            loader=self._load_from_vault
        )

    async def _load_from_vault(self):
        # Placeholder: integrate hvac / aws sdk
        return os.getenv("JWT_SECRET_RUNTIME")

    async def encode(self, payload: dict) -> str:
        secret = await self._get_secret()

        payload.update({
            "iat": int(time.time()),
            "exp": int(time.time()) + 900  # 15 min
        })

        return jwt.encode(
            payload,
            secret,
            algorithm="HS512"
        )

    async def decode(self, token: str) -> dict:
        secret = await self._get_secret()

        return jwt.decode(
            token,
            secret,
            algorithms=["HS512"],
            options={
                "require": ["exp", "iat"]
            }
        )

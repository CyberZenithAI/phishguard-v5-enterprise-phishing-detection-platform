from pydantic_settings import BaseSettings
from pydantic import SecretStr
from typing import List


class Settings(BaseSettings):

    # API
    API_V1_PREFIX: str = "/api/v1"

    # SECURITY
    SECRET_KEY: SecretStr
    JWT_ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60

    # ENV
    ENVIRONMENT: str = "development"

    # CORS
    ALLOWED_ORIGINS: List[str] = ["*"]

    # REDIS
    REDIS_HOST: str = "redis"
    REDIS_PORT: int = 6379
    REDIS_DB: int = 0

    # VIRUSTOTAL
    VT_API_KEY: SecretStr | None = None

    model_config = {
        "env_file": ".env",
        "case_sensitive": True
    }


settings = Settings()

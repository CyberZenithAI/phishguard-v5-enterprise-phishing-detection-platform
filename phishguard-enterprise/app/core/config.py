from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    PHISHGUARD_ENV: str = "development"
    SECRET_KEY: str
    REDIS_URL: str = "redis://localhost:6379/0"
    VIRUSTOTAL_API_KEY: str = ""
    RATE_LIMIT: int = 100

    class Config:
        env_file = ".env"

settings = Settings()

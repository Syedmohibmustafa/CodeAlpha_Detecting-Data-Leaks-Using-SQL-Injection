from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    app_secret: str = "change-me-in-production-use-long-random-bytes"
    database_url: str = "sqlite:///./secure_vault.db"
    # 32 bytes for AES-256 key; can be set via env as hex (64 chars) or raw in app_secret-derived KDF
    master_key_hex: str = ""


@lru_cache
def get_settings() -> Settings:
    return Settings()

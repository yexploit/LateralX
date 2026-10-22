"""Application configuration."""

from functools import lru_cache
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict


ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = ROOT / "data"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="LATERALX_", env_file=".env", extra="ignore")

    app_name: str = "LateralX"
    app_version: str = "1.0.0"
    debug: bool = True
    cors_origins: list[str] = [
        "http://localhost:5173",
        "http://localhost:3000",
        "http://localhost:8080",
        "http://127.0.0.1:8000",
    ]
    data_dir: Path = DATA_DIR
    # Real tool default: do NOT auto-seed synthetic data
    seed_on_startup: bool = False
    upload_dir: Path = DATA_DIR / "uploads"


@lru_cache
def get_settings() -> Settings:
    return Settings()

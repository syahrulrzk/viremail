from pathlib import Path
from typing import Optional

from pydantic_settings import BaseSettings, SettingsConfigDict

# Get the root directory (where .env is located)
ROOT_DIR = Path(__file__).parent.parent.parent.parent


class Settings(BaseSettings):
    PROJECT_NAME: str = "VIRE"
    VERSION: str = "1.3.0"
    API_V1_STR: str = "/api/v1"

    # Database
    POSTGRES_SERVER: str = "localhost"
    POSTGRES_USER: str = "osintmail"
    POSTGRES_PASSWORD: str = "osintmail123"
    POSTGRES_DB: str = "osintmail"
    POSTGRES_PORT: int = 5432
    DATABASE_URL: Optional[str] = None

    # Redis
    REDIS_HOST: str = "localhost"
    REDIS_PORT: int = 6379
    REDIS_URL: Optional[str] = None

    # Security
    SECRET_KEY: str = "your-secret-key-change-in-production"
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 24 * 7  # 7 days

    # CORS — override via BACKEND_CORS_ORIGINS (JSON list, e.g. in .env) to
    # allow other origins / LAN IPs without touching the code.
    BACKEND_CORS_ORIGINS: list[str] = [
        "http://localhost:3000",
        "http://localhost:3001",
        "http://172.16.19.235:3000",
        "http://172.16.19.235:3001",
    ]

    # SMTP verification (RCPT TO probe — no mail is ever sent)
    SMTP_VERIFY_ENABLED: bool = True

    # Local OCR (Tesseract) for images & scanned PDFs found during crawl
    OCR_ENABLED: bool = True

    # Deep OSINT tools (BBOT + Holehe — self-hosted CLIs via pipx)
    DEEP_TOOLS_ENABLED: bool = True

    # GitHub API token (optional) — raises rate limits for commit harvesting
    GITHUB_TOKEN: Optional[str] = None

    # Job portal scraping (HRD emails) — polite, rate-limited, ban-averse.
    PORTAL_SCRAPING_ENABLED: bool = True
    PORTAL_MIN_DELAY: float = 2.0   # min seconds between requests to the same host
    PORTAL_JITTER: float = 2.5      # extra random delay (0..jitter) per request
    PORTAL_HOST_CAP: int = 40       # max requests per host per scan
    PORTAL_MAX_PAGES: int = 20      # bulk mode page cap
    PORTAL_DOMAIN_MAX_PAGES: int = 8  # per-domain scan page cap

    model_config = SettingsConfigDict(
        env_file=ROOT_DIR / ".env",
        env_file_encoding="utf-8",
        case_sensitive=True,
        extra="ignore",
    )


settings = Settings()

if not settings.DATABASE_URL:
    settings.DATABASE_URL = (
        f"postgresql://{settings.POSTGRES_USER}:{settings.POSTGRES_PASSWORD}"
        f"@{settings.POSTGRES_SERVER}:{settings.POSTGRES_PORT}/{settings.POSTGRES_DB}"
    )

if not settings.REDIS_URL:
    settings.REDIS_URL = f"redis://{settings.REDIS_HOST}:{settings.REDIS_PORT}/0"

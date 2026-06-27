"""
Environment configuration for SentinelAI.
Validates required environment variables at startup.
Never crashes — warns on missing optional vars, only errors on critical missing vars.
"""
import os
import logging
from pathlib import Path
from dotenv import load_dotenv

logger = logging.getLogger("sentinelai.config")

# Load .env file
try:
    load_dotenv(Path(__file__).parent / ".env")
except Exception:
    pass


class Settings:
    """Application settings loaded from environment variables."""

    def __init__(self):
        # ── Required (app won't function without these) ──
        self.SECRET_KEY: str = os.environ.get("SECRET_KEY", "")
        self.DATABASE_URL: str = os.environ.get("DATABASE_URL", "")
        self.DATABASE_PATH: str = os.environ.get(
            "DATABASE_PATH", str(Path(__file__).parent / "sentinelai.db")
        )

        # ── Optional: Redis ──
        self.REDIS_URL: str = os.environ.get("REDIS_URL", "")

        # ── Optional: AI ──
        self.GEMINI_API_KEY: str = os.environ.get("GEMINI_API_KEY", "")
        self.JWT_SECRET_KEY: str = os.environ.get("JWT_SECRET_KEY", "")
        self.GOOGLE_APPLICATION_CREDENTIALS: str = os.environ.get(
            "GOOGLE_APPLICATION_CREDENTIALS", ""
        ).strip('"').strip("'")

        # ── Optional: SMTP ──
        self.SMTP_HOST: str = os.environ.get("SMTP_HOST", "smtp.gmail.com")
        self.SMTP_PORT: int = int(os.environ.get("SMTP_PORT", "587"))
        self.SMTP_USER: str = os.environ.get("SMTP_USER", "")
        self.SMTP_PASSWORD: str = os.environ.get("SMTP_PASSWORD", "")
        self.SMTP_FROM: str = os.environ.get("SMTP_FROM", self.SMTP_USER)

        # ── Optional: CORS ──
        self.CORS_ORIGINS: str = os.environ.get(
            "CORS_ORIGINS", "http://localhost:3000,http://127.0.0.1:3000"
        )

        # ── Optional: Frontend reference ──
        self.NEXT_PUBLIC_API_URL: str = os.environ.get("NEXT_PUBLIC_API_URL", "")

        # ── Derived ──
        self.USE_POSTGRESQL: bool = bool(
            self.DATABASE_URL and self.DATABASE_URL.startswith("postgres")
        )

        self._validate()

    def _validate(self):
        """Validate environment variables. Warn on missing optional, error on missing required."""
        warnings = []
        errors = []

        if not self.SECRET_KEY:
            errors.append("SECRET_KEY is not set — JWT authentication will fail")

        if not self.DATABASE_URL and not self.DATABASE_PATH:
            errors.append("Neither DATABASE_URL nor DATABASE_PATH is set — no database available")

        if self.USE_POSTGRESQL:
            host = self.DATABASE_URL.split('@')[-1].split('/')[0] if '@' in self.DATABASE_URL else 'configured'
            logger.info(f"Database: PostgreSQL ({host})")
        else:
            logger.info(f"Database: SQLite ({self.DATABASE_PATH})")

        if not self.GEMINI_API_KEY:
            warnings.append("GEMINI_API_KEY not set — AI copilot will use local fallback")
        elif not self.GEMINI_API_KEY.startswith("AIzaSy"):
            warnings.append(f"GEMINI_API_KEY appears invalid (should start with 'AIzaSy...') — will use local fallback")

        if not self.REDIS_URL:
            warnings.append("REDIS_URL not set — caching will use in-memory fallback")

        if not self.SMTP_USER:
            warnings.append("SMTP_USER not set — email notifications disabled")

        if self.GOOGLE_APPLICATION_CREDENTIALS:
            cred_path = Path(self.GOOGLE_APPLICATION_CREDENTIALS)
            if not cred_path.exists():
                warnings.append(f"GOOGLE_APPLICATION_CREDENTIALS file not found: {cred_path}")

        for w in warnings:
            logger.warning(f"[Config] {w}")

        for e in errors:
            logger.error(f"[Config] {e}")


settings = Settings()

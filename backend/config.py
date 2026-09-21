"""HADES backend configuration — loaded from .env file."""

import os
from pathlib import Path

from dotenv import load_dotenv

_env_path = Path(__file__).resolve().parent / ".env"
load_dotenv(_env_path)

# Ensure Go binaries (katana, gau, dalfox, etc.) are on PATH
_go_bin = Path.home() / "go" / "bin"
if _go_bin.is_dir() and str(_go_bin) not in os.environ.get("PATH", ""):
    os.environ["PATH"] = f"{_go_bin}:{os.environ.get('PATH', '')}"


class Settings:
    DB_PATH: str = os.getenv("DB_PATH", str(Path(__file__).resolve().parent / "hades.db"))
    HOST: str = os.getenv("HOST", "0.0.0.0")
    PORT: int = int(os.getenv("PORT", "8000"))
    ALLOWED_ORIGINS: list[str] = [
        o.strip()
        for o in os.getenv(
            "ALLOWED_ORIGINS",
            "http://localhost:5173,http://localhost:8000,http://127.0.0.1:5173,http://127.0.0.1:8000",
        ).split(",")
    ]
    MAX_COMMAND_TIMEOUT: int = int(os.getenv("MAX_COMMAND_TIMEOUT", "300"))
    CLAUDE_MODEL: str = os.getenv("CLAUDE_MODEL", "claude-opus-4-6")


settings = Settings()

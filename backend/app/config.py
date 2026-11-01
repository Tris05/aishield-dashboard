from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from dotenv import load_dotenv

# Load backend/.env for local development. Hosted environments should inject
# variables through their secret manager instead.
load_dotenv(Path(__file__).resolve().parents[1] / ".env", override=False)


@dataclass
class Settings:
    mongodb_uri: str = os.getenv("MONGODB_URI", "")
    mongodb_database: str = os.getenv("MONGODB_DATABASE", "aishield")
    ingest_token: str = os.getenv("AISHIELD_INGEST_TOKEN", "")
    public_base_url: str = os.getenv("PUBLIC_BASE_URL", "http://localhost:3000").rstrip("/")
    cors_origins: tuple[str, ...] = tuple(
        item.strip() for item in os.getenv("BACKEND_CORS_ORIGINS", "http://localhost:3000").split(",") if item.strip()
    )
    gemini_api_key: str = os.getenv("GEMINI_API_KEY", "")
    gemini_model: str = os.getenv("GEMINI_MODEL", "gemini-2.5-flash")
    max_report_bytes: int = int(os.getenv("MAX_REPORT_BYTES", "10000000"))
    max_source_file_bytes: int = int(os.getenv("MAX_SOURCE_FILE_BYTES", "300000"))
    gitlab_base_url: str = os.getenv("GITLAB_BASE_URL", "https://gitlab.com").rstrip("/")
    gitlab_verification_project_id: str = os.getenv("GITLAB_VERIFICATION_PROJECT_ID", "")
    gitlab_verification_ref: str = os.getenv("GITLAB_VERIFICATION_REF", "main")
    gitlab_verification_trigger_token: str = os.getenv("GITLAB_VERIFICATION_TRIGGER_TOKEN", "")
    gitlab_verification_engine_image: str = os.getenv("GITLAB_VERIFICATION_ENGINE_IMAGE", "")


settings = Settings()

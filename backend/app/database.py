from __future__ import annotations

from typing import Any

from .config import settings

_client: Any | None = None

def get_database() -> Any:
    global _client
    if not settings.mongodb_uri:
        raise RuntimeError("MONGODB_URI is not configured. Add it to backend/.env.")
    if _client is None:
        try:
            from pymongo import MongoClient
        except ImportError as exc:
            raise RuntimeError("pymongo is not installed. Install backend/requirements.txt.") from exc
        _client = MongoClient(settings.mongodb_uri, serverSelectionTimeoutMS=5000, connectTimeoutMS=5000)
    return _client[settings.mongodb_database]

def ensure_indexes(db: Any) -> None:
    # Numeric directions (1/-1) are the same values used by PyMongo, while
    # keeping API unit tests independent of a live MongoDB installation.
    db.projects.create_index([("repo_key", 1)], unique=True)
    db.scans.create_index([("scan_id", 1)], unique=True)
    db.scans.create_index([("access_token_hash", 1)], unique=True)
    db.scans.create_index([("project_id", 1), ("created_at", -1)])
    db.remediation_sessions.create_index([("session_id", 1)], unique=True)
    db.fix_proposals.create_index([("fix_id", 1)], unique=True)

def close_database() -> None:
    global _client
    if _client is not None:
        _client.close()
        _client = None

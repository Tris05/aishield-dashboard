from __future__ import annotations
import hashlib, hmac, re, secrets
from urllib.parse import urlparse
from fastapi import Header, HTTPException
from .config import settings

def sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()

def new_token() -> str:
    return secrets.token_urlsafe(36)

def require_ingest_token(authorization: str | None = Header(default=None)) -> None:
    if not settings.ingest_token:
        raise HTTPException(503, "Scanner ingestion is not configured on the backend.")
    supplied = (authorization or "").removeprefix("Bearer ").strip()
    if not supplied or not hmac.compare_digest(supplied, settings.ingest_token):
        raise HTTPException(401, "Invalid scanner upload credential.")

def require_viewer_token(x_aishield_viewer_token: str | None = Header(default=None)) -> str:
    if not x_aishield_viewer_token or len(x_aishield_viewer_token) < 32:
        raise HTTPException(401, "A valid dashboard access token is required.")
    return x_aishield_viewer_token

def validate_public_repo_url(raw: str) -> tuple[str, str, str]:
    p=urlparse(raw.strip())
    try:
        port=p.port
    except ValueError as exc:
        raise HTTPException(400, "Repository URL contains an invalid port.") from exc
    if p.scheme != "https" or p.hostname not in {"github.com", "gitlab.com"} or p.username or p.password or port not in (None,443) or p.query or p.fragment:
        raise HTTPException(400, "Only public HTTPS GitHub/GitLab repository URLs without credentials are supported.")
    path=p.path.strip("/")
    parts=path.split("/") if path else []
    if len(parts) < 2:
        raise HTTPException(400, "Repository URL must include owner/group and repository name.")
    if p.hostname == "github.com" and len(parts) != 2:
        raise HTTPException(400, "Use the GitHub repository root URL, not a branch, tree or file URL.")
    if p.hostname == "gitlab.com" and "-" in parts:
        raise HTTPException(400, "Use the GitLab project root URL, not a branch, tree or file URL.")
    path=re.sub(r"\.git$", "", path)
    canonical=f"https://{p.hostname}/{path}"
    provider="github" if p.hostname == "github.com" else "gitlab"
    return canonical, provider, sha256(canonical.lower())

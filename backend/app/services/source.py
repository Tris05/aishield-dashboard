from __future__ import annotations
import base64, re
from urllib.parse import quote, urlparse
import requests
from fastapi import HTTPException
from ..config import settings

PROTECTED_NAMES={".gitlab-ci.yml", ".github/workflows", "constitution.md", "patch-policy.md", "secure-coding.md", "ai-model-security.md", "llm-security.md"}
PROTECTED_PREFIXES=(".git/", ".github/workflows/", ".gitlab/", "policy/", "policies/", "tests/")

def safe_relative_path(raw: str) -> str:
    value=raw.replace("\\", "/").strip()
    parts=value.split("/")
    if not value or value.startswith("/") or any(x in {"", ".", ".."} for x in parts) or "\x00" in value:
        raise HTTPException(400, "Unsafe repository file path.")
    if parts[-1].lower() in {x.lower() for x in PROTECTED_NAMES} or value.startswith(PROTECTED_PREFIXES) or value.lower().endswith((".lock", "package-lock.json", "poetry.lock", "uv.lock")):
        raise HTTPException(400, "This path is excluded from automated remediation.")
    return value

def fetch_source(repository_url: str, commit_sha: str, path: str) -> str:
    safe_path=safe_relative_path(path)
    p=urlparse(repository_url)
    encoded="/".join(quote(part, safe="") for part in safe_path.split("/"))
    if p.hostname == "github.com":
        parts=p.path.strip("/").split("/")
        if len(parts) < 2: raise HTTPException(400,"Invalid GitHub repository URL.")
        url=f"https://raw.githubusercontent.com/{parts[0]}/{parts[1]}/{quote(commit_sha, safe='')}/{encoded}"
    elif p.hostname == "gitlab.com":
        project_path=p.path.strip("/")
        if project_path.endswith(".git"):
            project_path=project_path[:-4]
        project_id=quote(project_path, safe="")
        url=f"https://gitlab.com/api/v4/projects/{project_id}/repository/files/{quote(safe_path, safe='')}/raw?ref={quote(commit_sha, safe='')}"
    else:
        raise HTTPException(400,"Unsupported repository host.")
    try:
        response=requests.get(url, timeout=(5,15), allow_redirects=False, stream=True, headers={"User-Agent":"AIShield-Remediation/0.1"})
        if response.status_code in (301,302,303,307,308):
            raise HTTPException(502,"Source host redirected the raw file request; refusing an unvalidated redirect.")
        if response.status_code == 404: raise HTTPException(404,f"File not found at scanned commit: {safe_path}")
        response.raise_for_status()
        chunks=[]; size=0
        for chunk in response.iter_content(16384):
            size += len(chunk)
            if size > settings.max_source_file_bytes: raise HTTPException(413,"Source file exceeds configured remediation size limit.")
            chunks.append(chunk)
        text=b"".join(chunks).decode("utf-8")
    except HTTPException: raise
    except Exception as exc: raise HTTPException(502,f"Could not retrieve source file ({type(exc).__name__}).") from exc
    return text

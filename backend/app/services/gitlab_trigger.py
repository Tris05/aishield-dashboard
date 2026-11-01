from __future__ import annotations

from urllib.parse import urlparse

import requests
from fastapi import HTTPException

from ..config import settings


def trigger_verification(repository_url: str, branch: str) -> dict:
    required = (
        settings.gitlab_verification_project_id,
        settings.gitlab_verification_trigger_token,
        settings.gitlab_verification_engine_image,
    )
    if not all(required):
        return {
            "status": "not_configured",
            "message": "Configure the GitLab verification project ID, trigger token and engine image to enable automatic post-remediation scans.",
        }

    if not settings.gitlab_verification_project_id.isdigit():
        raise HTTPException(500, "GITLAB_VERIFICATION_PROJECT_ID must be the numeric scanner-project ID.")
    parsed = urlparse(settings.gitlab_base_url)
    if parsed.scheme != "https" or parsed.hostname != "gitlab.com" or parsed.port not in (None, 443):
        raise HTTPException(500, "GITLAB_BASE_URL must be https://gitlab.com for this POC.")

    url = f"{settings.gitlab_base_url}/api/v4/projects/{settings.gitlab_verification_project_id}/trigger/pipeline"
    data = {
        "token": settings.gitlab_verification_trigger_token,
        "ref": settings.gitlab_verification_ref,
        "variables[AISECURITY_TRIGGERED_SCAN]": "true",
        "variables[AISECURITY_REPOSITORY_URL]": repository_url,
        "variables[AISECURITY_BRANCH]": branch,
        "variables[AISECURITY_ENGINE_IMAGE]": settings.gitlab_verification_engine_image,
    }
    try:
        response = requests.post(url, data=data, timeout=20, allow_redirects=False)
        if 300 <= response.status_code < 400:
            return {"status": "trigger_failed", "message": "GitLab redirected the pipeline trigger request; no redirect was followed."}
        response.raise_for_status()
        result = response.json()
        return {
            "status": "triggered",
            "pipeline_id": result.get("id"),
            "pipeline_url": result.get("web_url"),
            "message": "Verification scan pipeline triggered.",
        }
    except Exception as exc:
        return {"status": "trigger_failed", "message": f"Could not trigger verification pipeline ({type(exc).__name__})."}

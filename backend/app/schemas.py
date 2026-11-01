from __future__ import annotations
from typing import Any
from pydantic import BaseModel, Field, HttpUrl, field_validator

class ScanUpload(BaseModel):
    repository_url: str
    branch: str = "default"
    commit_sha: str | None = None
    scan_status: str = "completed"
    scanner_version: str | None = None
    ci: dict[str, Any] = Field(default_factory=dict)
    report: dict[str, Any]

    @field_validator("branch")
    @classmethod
    def branch_is_bounded(cls, value: str) -> str:
        if not value or len(value) > 240 or "\x00" in value:
            raise ValueError("branch must be a non-empty string up to 240 characters")
        return value

class ConsentRequest(BaseModel):
    consent: bool
    finding_ids: list[str] = Field(default_factory=list, max_length=100)

class DecisionsRequest(BaseModel):
    decisions: dict[str, str]

class ApplyRequest(BaseModel):
    git_token: str = Field(min_length=10, max_length=500)
    branch_name: str = Field(min_length=1, max_length=200)

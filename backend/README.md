# AIShield Dashboard Backend

FastAPI service for scan ingestion, dashboard report retrieval, Gemini patch generation, patch review, and GitHub/GitLab branch pushes. The scanner itself remains in the separate `aishield-scanner` repository and continues to run on GitLab Runner.

## Local setup

```bash
cd backend
python -m venv .venv
# Windows PowerShell: .venv\Scripts\Activate.ps1
# macOS/Linux: source .venv/bin/activate
pip install -r requirements-dev.txt
cp .env.example .env  # Windows: Copy-Item .env.example .env
# Edit .env, especially MONGODB_URI and AISHIELD_INGEST_TOKEN
uvicorn app.main:app --reload --port 8000
```

Health: `http://localhost:8000/api/v1/health`; readiness (checks MongoDB): `http://localhost:8000/api/v1/ready`. Never commit `.env`.

## Required settings

- `MONGODB_URI`: MongoDB Atlas connection string. Add the backend server's outbound IP to Atlas Network Access, or temporarily use `0.0.0.0/0` only for a student demo and replace it before real use. Create a database user with read/write access to the `aishield` database.
- `AISHIELD_INGEST_TOKEN`: long random string shared with the GitLab scanner project as `AISECURITY_UPLOAD_TOKEN`.
- `PUBLIC_BASE_URL`: deployed Next.js frontend origin.
- `BACKEND_CORS_ORIGINS`: comma-separated frontend origins.
- `GEMINI_API_KEY`: set only if you want remediation enabled; never expose it to the browser.

## API overview

- `POST /api/v1/scans/upload` — Bearer scanner-ingest token; stores report and issues an unguessable dashboard URL.
- `GET /api/v1/public/scans/{access_token}` — public bearer-link access to a report.
- `POST /api/v1/public/scans/{access_token}/remediation/sessions` — explicit consent and session creation.
- `POST /api/v1/remediation/sessions/{session_id}/generate` — retrieves only finding files at the scanned commit and asks Gemini for proposals.
- `PATCH /api/v1/remediation/sessions/{session_id}/decisions` — accepted/rejected fix decisions.
- `POST /api/v1/remediation/sessions/{session_id}/apply` — requires PAT in request body, applies accepted patches all-or-nothing in a temporary clone, creates one commit and pushes one branch. PAT is not stored.

## Automated verification scan

Configure `GITLAB_VERIFICATION_PROJECT_ID`, `GITLAB_VERIFICATION_REF`, `GITLAB_VERIFICATION_TRIGGER_TOKEN`, and `GITLAB_VERIFICATION_ENGINE_IMAGE` to a GitLab project containing the scanner repository's root `.gitlab-ci.yml`. Add `AISECURITY_DASHBOARD_URL` and `AISECURITY_UPLOAD_TOKEN` as masked CI variables in that scanner project. The backend triggers the `scan-requested-public-repository` job against the pushed remediation branch. Without these settings, the response says `not_configured`; the branch push still succeeds and the user can trigger a scan manually.

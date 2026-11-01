# AIShield Dashboard

Hosted dashboard and remediation backend for the separate AIShield Scanner. Scanning continues to run in GitLab CI; this repository does not clone repositories to run scans.

## Features

- Receives normalized `report.json` from the scanner via a bearer-authenticated API.
- Stores project/scan data in MongoDB Atlas; each scan has a unique ID and older scan reports are retained. The project record points to the latest uploaded scan.
- Issues an unguessable dashboard URL (bearer link; share carefully). No user account is required for this POC.
- Requires explicit consent before retrieving source files at the scanned commit and sending redacted snippets to Gemini.
- Shows patch proposals with individual accept/reject decisions.
- Accepts a GitHub/GitLab PAT only at apply time, applies all accepted patches in a temporary clone, aborts on any error, then pushes one branch and one commit.
- Does not create PR/MR automatically; it provides a compare link.
- Can trigger a GitLab CI verification scan after push when the scanner-project trigger integration is configured.

## Local setup

### 1. MongoDB Atlas

1. Create an Atlas project and a Free cluster.
2. Create a database user with read/write access to the application database.
3. Add the backend host's outbound IP to Network Access. For local development, add your current public IP. Avoid leaving `0.0.0.0/0` enabled beyond a temporary demo.
4. Copy the application's connection string. Replace the username/password placeholders and URL-encode special characters in the password.

Free Atlas clusters have a 0.5 GB storage cap and may pause after 30 days with no connections; keep report size under `MAX_REPORT_BYTES`, and prune old scan records manually if the POC grows. MongoDB documents have a 16 MB limit, so the backend caps each JSON report at 10 MB.

### 2. Backend

```bash
cd backend
python -m venv .venv
# Windows PowerShell: .venv\Scripts\Activate.ps1
# macOS/Linux: source .venv/bin/activate
pip install -r requirements-dev.txt
cp .env.example .env  # Windows: Copy-Item .env.example .env
```

Edit `backend/.env` and set:

- `MONGODB_URI` — Atlas connection string.
- `AISHIELD_INGEST_TOKEN` — generate with `python -c "import secrets; print(secrets.token_urlsafe(48))"`.
- `PUBLIC_BASE_URL=http://localhost:3000`.
- `BACKEND_CORS_ORIGINS=http://localhost:3000`.
- `GEMINI_API_KEY` — optional until remediation is demonstrated.

Start API: `uvicorn app.main:app --reload --port 8000`. Check `/api/v1/health` and `/api/v1/ready`.

### 3. Frontend

```bash
cd frontend
cp .env.example .env.local  # Windows: Copy-Item .env.example .env.local
npm install
npm run dev
```

Set `NEXT_PUBLIC_API_BASE_URL=http://localhost:8000`. Open `http://localhost:3000`.

## Connect scanner to the dashboard

In the GitLab project that executes the AIShield component, add these CI/CD variables:

| GitLab variable | Value | Flags |
|---|---|---|
| `AISECURITY_DASHBOARD_URL` | `https://<your-dashboard-api-host>` | Masked; protected where applicable |
| `AISECURITY_UPLOAD_TOKEN` | Exact same value as backend `AISHIELD_INGEST_TOKEN` | Masked + protected |

Include the component with the public repo URL and optional branch. After the scan, the job logs print the dashboard link. The API receives only the JSON report and scan metadata, not the repository archive.

## Enable post-remediation verification

In the AIShield Scanner GitLab project, create a pipeline trigger token. Add these **masked/protected** variables to that project's CI/CD settings:

- `AISECURITY_DASHBOARD_URL` — deployed FastAPI base URL.
- `AISECURITY_UPLOAD_TOKEN` — same ingestion secret.

In the dashboard backend environment, set:

- `GITLAB_VERIFICATION_PROJECT_ID` — numeric project ID of the scanner project.
- `GITLAB_VERIFICATION_REF` — scanner project's branch/ref containing the trigger job (usually `main`).
- `GITLAB_VERIFICATION_TRIGGER_TOKEN` — pipeline trigger token.
- `GITLAB_VERIFICATION_ENGINE_IMAGE` — published scanner engine image reference, e.g. `registry.gitlab.com/group/aishield-scanner/engine:0.1.0`.

The scanner project's `.gitlab-ci.yml` includes `scan-requested-public-repository`, which is gated by `AISECURITY_TRIGGERED_SCAN=true`. The dashboard triggers it with the repository URL and newly pushed branch. If this integration isn't configured, remediation still pushes the branch, but the API marks verification `not_configured`.

## Token scopes for applying fixes

- GitHub PAT: repository Contents write permission (fine-grained token) for the target repository.
- GitLab PAT: `write_repository` scope for the target project.

PAT is sent only to the FastAPI apply endpoint over HTTPS, used by Git's askpass helper in a temporary working directory, and not inserted into the remote URL, logs, or MongoDB. It is never available to Next.js server configuration or stored after the request. Avoid applying fixes to a repository unless you own it or have permission.

## API and tests

Backend API docs: `/docs`.

```bash
cd backend
pip install -r requirements-dev.txt
python -m unittest discover -s tests -v
```

## Production notes

- Deploy frontend and backend separately. Set `NEXT_PUBLIC_API_BASE_URL` at frontend build time, and CORS origin on the backend.
- Use a private environment/secret manager for all credentials.
- Use HTTPS for dashboard links and APIs.
- The share URL is a bearer credential; anyone who has it can view that scan and initiate consented remediation.
- The first POC does not implement user accounts, private repository scanning, OAuth, PR/MR creation, a scan-history UI, or production-grade abuse controls.
- The POC uses GitHub/GitLab PATs at apply time; only the PAT is transient. For higher assurance, introduce OAuth and a short-lived credential broker before broad use.

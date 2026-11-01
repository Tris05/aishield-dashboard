# Secure Coding Policy

## Untrusted inputs
- Treat HTTP inputs, uploaded files, repository content, retrieved documents, model outputs, environment variables and serialized objects as untrusted.
- Validate type, shape, length, encoding and allowed values at trust boundaries. Prefer allowlists over denylists.
- Use parameterized database operations, safe path resolution, explicit argument arrays and `shell=False`.
- Do not disable TLS validation. Keep timeouts, response-size limits and redirect policy explicit.

## Secrets and logging
- Never hardcode credentials or copy secret values into logs, exceptions, patches or reports.
- Keep authorization tokens out of repository URLs and command-line arguments.
- Log identifiers, status, and redacted evidence rather than complete payloads or source snippets.

## Serialization and model loading
- Never deserialize untrusted pickle/joblib or equivalent executable serialization formats.
- Prefer safe tensor or interchange formats where suitable; verify origin, revision, integrity and expected architecture before use.
- Do not execute repository setup scripts, notebooks, build hooks, downloaded model code, or training code to analyze a repository.

## Least privilege and resource controls
- Require authentication and authorization at every sensitive API and tool boundary.
- Bound request sizes, concurrency, timeouts, retries, file counts, artifact sizes, recursion and compute budgets.
- Fail visibly when a required scanner or input is unavailable. Missing coverage is not a clean result.

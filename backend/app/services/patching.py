from __future__ import annotations

import logging
import os
import re
import subprocess
import tempfile
import shutil

from pathlib import Path, PurePosixPath

from fastapi import HTTPException

from .source import safe_relative_path

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------
# PATCH VALIDATION
# ---------------------------------------------------------------------

_HUNK_HEADER_RE = re.compile(
    r"^@@ -(?P<old_start>\d+)(?:,(?P<old_count>\d+))? "
    r"\+(?P<new_start>\d+)(?:,(?P<new_count>\d+))? @@(?P<suffix>.*)$"
)

def normalize_hunk_counts(patch: str) -> tuple[str, str | None]:
    """
    Recalculate unified-diff hunk counts from the actual hunk lines.

    This repairs incorrect counts in @@ headers, but deliberately does not
    repair malformed diff lines, missing context, or patches for the wrong
    source revision. Git applicability must still be checked separately.
    """
    if not isinstance(patch, str) or not patch.strip():
        return patch, "Patch is empty."

    patch = patch.lstrip("\ufeff\r\n\t ")
    lines = patch.splitlines()
    normalized: list[str] = []
    hunk_count = 0
    i = 0

    while i < len(lines):
        line = lines[i]
        match = _HUNK_HEADER_RE.match(line)

        if not match:
            normalized.append(line)
            i += 1
            continue

        hunk_count += 1
        old_count = 0
        new_count = 0
        hunk_lines: list[str] = []
        i += 1

        while i < len(lines):
            current = lines[i]

            if current.startswith("@@ ") or current.startswith("diff --git "):
                break

            if current == r"\ No newline at end of file":
                hunk_lines.append(current)
                i += 1
                continue

            if current.startswith(" "):
                old_count += 1
                new_count += 1
            elif current.startswith("-"):
                old_count += 1
            elif current.startswith("+"):
                new_count += 1
            else:
                return patch, (
                    "Invalid unified-diff line inside hunk: "
                    f"{current!r}"
                )

            hunk_lines.append(current)
            i += 1

        if not hunk_lines or (old_count == 0 and new_count == 0):
            return patch, "Unified-diff hunk contains no changes."

        corrected_header = (
            f"@@ -{match.group('old_start')},{old_count} "
            f"+{match.group('new_start')},{new_count} @@"
            f"{match.group('suffix')}"
        )
        normalized.append(corrected_header)
        normalized.extend(hunk_lines)

    if hunk_count == 0:
        return patch, "Patch contains no unified-diff hunks."

    return "\n".join(normalized) + "\n", None

def validate_diff(
    patch: str,
    expected_path: str,
) -> tuple[bool, str]:
    """
    Validate patch structure and ensure it modifies exactly
    the expected file.

    Git applicability is checked separately against the scanned commit.
    """

    try:
        expected = safe_relative_path(expected_path)

    except HTTPException as exc:
        return False, str(exc.detail)

    if not isinstance(patch, str):
        return False, "Patch must be a string."

    if (
        not patch.strip()
        or len(patch.encode("utf-8")) > 50_000
        or "\x00" in patch
    ):
        return False, "Patch is empty, too large, or contains NUL bytes."

    # IMPORTANT:
    # Preserve support for leading whitespace, newlines and BOM.
    patch = patch.lstrip("\ufeff\r\n\t ")

    if not patch.startswith("diff --git "):
        return False, "Expected a unified Git diff."

    headers = re.findall(
        r"^diff --git a/(.+?) b/(.+?)$",
        patch,
        re.MULTILINE,
    )

    if len(headers) != 1 or headers[0] != (expected, expected):
        return False, (
            "Patch must modify exactly the finding's single file."
        )

    file_headers = re.findall(
        r"^(---|\+\+\+) (.+)$",
        patch,
        re.MULTILINE,
    )

    expected_old = f"a/{expected}"
    expected_new = f"b/{expected}"

    if file_headers != [
        ("---", expected_old),
        ("+++", expected_new),
    ]:
        return False, (
            "Patch file headers must match the exact target path."
        )

    if re.search(
        r"^(?:new file mode|deleted file mode|rename from|rename to|copy from|copy to)",
        patch,
        re.MULTILINE,
    ):
        return False, (
            "File creation, deletion, rename and copy operations "
            "are not allowed."
        )

    return (
        True,
        "Patch scope and structure accepted; applicability "
        "is checked against the scanned commit.",
    )

# ---------------------------------------------------------------------
# GIT EXECUTION
# ---------------------------------------------------------------------

def run_git(
    args: list[str],
    cwd: Path,
    env: dict | None = None,
    input_text: str | None = None,
    timeout: int = 60,
) -> subprocess.CompletedProcess:
    """Run Git without invoking a shell."""

    return subprocess.run(
        ["git", *args],
        cwd=cwd,
        env=env,
        input=input_text,
        text=True,
        capture_output=True,
        timeout=timeout,
        check=False,
    )

def _git_error(
    result: subprocess.CompletedProcess,
) -> str:
    """Return Git's diagnostic output without exposing credentials."""

    message = (
        result.stderr
        or result.stdout
        or "Git returned no diagnostic message."
    ).strip()

    # Redact credentials if they appear in an error message.
    message = re.sub(
        r"https://[^/@\s]+:[^/@\s]+@",
        "https://[REDACTED]@",
        message,
    )

    return message[:1500]

# ---------------------------------------------------------------------
# APPLY AND PUSH
# ---------------------------------------------------------------------

def apply_and_push(
    repository_url: str,
    commit_sha: str,
    source_branch: str,
    branch_name: str,
    patches: list[dict],
    token: str,
) -> dict:
    """
    Apply accepted patches against the exact scanned commit,
    create a remediation commit and push a new branch.

    If any patch fails, the operation stops before pushing.
    """

    # -------------------------------------------------------------
    # Validate branch name.
    # -------------------------------------------------------------

    if (
        not branch_name
        or not branch_name.strip()
        or len(branch_name) > 200
        or "\x00" in branch_name
    ):
        raise HTTPException(
            status_code=400,
            detail="Invalid remediation branch name.",
        )

    branch_check = subprocess.run(
        [
            "git",
            "check-ref-format",
            "--branch",
            branch_name,
        ],
        capture_output=True,
        text=True,
        check=False,
    )

    if branch_check.returncode:
        raise HTTPException(
            status_code=400,
            detail="Invalid remediation branch name.",
        )

    # -------------------------------------------------------------
    # Validate commit SHA.
    # -------------------------------------------------------------

    if not re.fullmatch(r"[0-9a-fA-F]{7,64}", commit_sha):
        raise HTTPException(
            status_code=400,
            detail="A valid scanned commit SHA is required.",
        )

    if not token or not token.strip():
        raise HTTPException(
            status_code=400,
            detail="A Git repository access token is required.",
        )

    # -------------------------------------------------------------
    # Validate repository host.
    # -------------------------------------------------------------

    if "github.com" in repository_url.lower():
        username = "x-access-token"

    elif "gitlab.com" in repository_url.lower():
        username = "oauth2"

    else:
        raise HTTPException(
            status_code=400,
            detail="Only GitHub and GitLab repositories are supported.",
        )

    # -------------------------------------------------------------
    # Validate all proposals before cloning.
    # -------------------------------------------------------------

    if not patches:
        raise HTTPException(
            status_code=400,
            detail="No accepted fixes were supplied.",
        )

    validated_patches = []

    for proposal in patches:
        if not isinstance(proposal, dict):
            raise HTTPException(
                status_code=400,
                detail="Invalid remediation proposal.",
            )

        try:
            rel = safe_relative_path(proposal["path"])

        except KeyError as exc:
            raise HTTPException(
                status_code=400,
                detail="A remediation proposal is missing its target path.",
            ) from exc

        patch = proposal.get("patch")

        if not isinstance(patch, str):
            raise HTTPException(
                status_code=400,
                detail=f"Invalid patch supplied for {rel}.",
            )

        # Normalize the response and repair hunk counts before validation.
        patch = patch.lstrip("\ufeff\\r\\n\\t ")
        patch, hunk_error = normalize_hunk_counts(patch)
        if hunk_error:
            raise HTTPException(
                status_code=422,
                detail=f"Malformed patch for {rel}: {hunk_error}",
            )

        ok, message = validate_diff(
            patch,
            rel,
        )

        if not ok:
            raise HTTPException(
                status_code=422,
                detail=f"Patch rejected for {rel}: {message}",
            )

        validated_patches.append(
            {
                **proposal,
                "path": rel,
                "patch": patch,
            }
        )

    # -------------------------------------------------------------
    # Temporary isolated repository.
    # -------------------------------------------------------------

    temp = Path(
        tempfile.mkdtemp(
            prefix="aishield-remediate-"
        )
    )

    askpass = temp / "askpass.sh"

    askpass.write_text(
        '#!/bin/sh\n'
        'case "$1" in '
        '*Username*) printf "%s\\n" "$AISHIELD_GIT_USERNAME" ;; '
        '*) printf "%s\\n" "$AISHIELD_GIT_TOKEN" ;; '
        'esac\n',
        encoding="utf-8",
    )

    askpass.chmod(0o700)

    env = os.environ.copy()

    env.update(
        {
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_ASKPASS": str(askpass),
            "AISHIELD_GIT_USERNAME": username,
            "AISHIELD_GIT_TOKEN": token,
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_LFS_SKIP_SMUDGE": "1",
        }
    )

    try:
        # ---------------------------------------------------------
        # Clone repository.
        # ---------------------------------------------------------

        clone = run_git(
            [
                "-c",
                "http.followRedirects=false",
                "-c",
                "http.sslVerify=true",
                "-c",
                "protocol.file.allow=never",
                "clone",
                "--no-checkout",
                "--filter=blob:none",
                repository_url,
                "repo",
            ],
            temp,
            env,
            timeout=120,
        )

        if clone.returncode:
            logger.error(
                "Repository clone failed: %s",
                _git_error(clone),
            )

            raise HTTPException(
                status_code=502,
                detail=(
                    "Could not clone the repository. "
                    "Check repository access and token permissions."
                ),
            )

        repo = temp / "repo"

        # ---------------------------------------------------------
        # Fetch source branch or repository history.
        # ---------------------------------------------------------

        if source_branch and source_branch != "default":
            fetch = run_git(
                [
                    "fetch",
                    "--filter=blob:none",
                    "origin",
                    source_branch,
                ],
                repo,
                env,
                timeout=120,
            )

        else:
            fetch = run_git(
                [
                    "fetch",
                    "--filter=blob:none",
                    "origin",
                ],
                repo,
                env,
                timeout=120,
            )

        if fetch.returncode:
            logger.warning(
                "Source branch fetch failed; trying exact commit: %s",
                _git_error(fetch),
            )

            fetch = run_git(
                [
                    "fetch",
                    "--depth=1",
                    "origin",
                    commit_sha,
                ],
                repo,
                env,
                timeout=120,
            )

        if fetch.returncode:
            logger.error(
                "Scanned commit fetch failed: %s",
                _git_error(fetch),
            )

            raise HTTPException(
                status_code=409,
                detail=(
                    "The scanned commit is no longer fetchable. "
                    "Run a fresh scan before remediation."
                ),
            )

        # ---------------------------------------------------------
        # Verify scanned commit.
        # ---------------------------------------------------------

        verify = run_git(
            [
                "cat-file",
                "-e",
                f"{commit_sha}^{{commit}}",
            ],
            repo,
            env,
        )

        if verify.returncode:
            fetch_exact = run_git(
                [
                    "fetch",
                    "--depth=1",
                    "origin",
                    commit_sha,
                ],
                repo,
                env,
                timeout=120,
            )

            if fetch_exact.returncode:
                logger.error(
                    "Exact commit fetch failed: %s",
                    _git_error(fetch_exact),
                )

                raise HTTPException(
                    status_code=409,
                    detail=(
                        "The scanned commit is not available from "
                        "the repository. Run a fresh scan."
                    ),
                )

        # ---------------------------------------------------------
        # Checkout scanned commit.
        # ---------------------------------------------------------

        checkout = run_git(
            [
                "checkout",
                "-b",
                branch_name,
                commit_sha,
            ],
            repo,
            env,
        )

        if checkout.returncode:
            logger.error(
                "Remediation branch checkout failed: %s",
                _git_error(checkout),
            )

            raise HTTPException(
                status_code=409,
                detail=(
                    "Could not create remediation branch. "
                    "The branch may already exist locally or the "
                    "scanned commit may be unavailable."
                ),
            )

        accepted = []

        # ---------------------------------------------------------
        # Apply patches.
        # ---------------------------------------------------------

        for proposal in validated_patches:
            rel = proposal["path"]
            patch = proposal["patch"]

            # Prevent symlink traversal.
            target = repo

            for part in PurePosixPath(rel).parts:
                target = target / part

                if target.is_symlink():
                    raise HTTPException(
                        status_code=422,
                        detail=(
                            f"Target path {rel} traverses a symlink; "
                            "no branch was pushed."
                        ),
                    )

            if not target.is_file():
                raise HTTPException(
                    status_code=422,
                    detail=(
                        f"Target path {rel} is not an existing "
                        "regular file; no branch was pushed."
                    ),
                )

            # Recalculate hunk counts again at the final application boundary.
            patch, hunk_error = normalize_hunk_counts(patch)
            if hunk_error:
                raise HTTPException(
                    status_code=422,
                    detail=f"Malformed patch for {rel}: {hunk_error}",
                )

            # Revalidate the exact normalized patch.
            ok, message = validate_diff(
                patch,
                rel,
            )

            if not ok:
                raise HTTPException(
                    status_code=422,
                    detail=f"Patch rejected for {rel}: {message}",
                )

            # -----------------------------------------------------
            # Check applicability before applying.
            # -----------------------------------------------------

            check = run_git(
                [
                    "apply",
                    "--recount",
                    "--check",
                    "--whitespace=error",
                ],
                repo,
                env,
                input_text=patch,
            )

            if check.returncode:
                error = _git_error(check)

                logger.error(
                    "Git patch check failed | "
                    "file=%s | finding_id=%s | error=%s",
                    rel,
                    proposal.get("finding_id"),
                    error,
                )

                raise HTTPException(
                    status_code=422,
                    detail=(
                        f"Patch does not apply cleanly for {rel}. "
                        f"Git error: {error}. "
                        "No branch was pushed."
                    ),
                )

            # -----------------------------------------------------
            # Apply patch.
            # -----------------------------------------------------

            applied = run_git(
                [
                    "apply",
                    "--recount",
                    "--whitespace=error",
                ],
                repo,
                env,
                input_text=patch,
            )

            if applied.returncode:
                error = _git_error(applied)

                logger.error(
                    "Git patch application failed | "
                    "file=%s | error=%s",
                    rel,
                    error,
                )

                raise HTTPException(
                    status_code=422,
                    detail=(
                        f"Patch application failed for {rel}. "
                        f"Git error: {error}. "
                        "No branch was pushed."
                    ),
                )

            accepted.append(rel)

        if not accepted:
            raise HTTPException(
                status_code=400,
                detail="No accepted fixes were supplied.",
            )

        # ---------------------------------------------------------
        # Check combined diff.
        # ---------------------------------------------------------

        diffcheck = run_git(
            [
                "diff",
                "--check",
            ],
            repo,
            env,
        )

        if diffcheck.returncode:
            error = _git_error(diffcheck)

            logger.error(
                "Combined patch validation failed: %s",
                error,
            )

            raise HTTPException(
                status_code=422,
                detail=(
                    f"Combined patch set failed git diff --check: "
                    f"{error}. No branch was pushed."
                ),
            )

        # ---------------------------------------------------------
        # Verify modified files.
        # ---------------------------------------------------------

        status = run_git(
            [
                "status",
                "--porcelain",
            ],
            repo,
            env,
        )

        if status.returncode:
            raise HTTPException(
                status_code=500,
                detail="Could not inspect modified repository files.",
            )

        changed = sorted(
            {
                line[3:]
                for line in status.stdout.splitlines()
                if len(line) > 3
            }
        )

        if set(changed) != set(accepted):
            logger.error(
                "Unexpected modified files | expected=%s | actual=%s",
                accepted,
                changed,
            )

            raise HTTPException(
                status_code=422,
                detail=(
                    "Combined changes include unexpected files; "
                    "no branch was pushed."
                ),
            )

        # ---------------------------------------------------------
        # Configure Git identity.
        # ---------------------------------------------------------

        config_name = run_git(
            [
                "config",
                "user.name",
                "AIShield Bot",
            ],
            repo,
            env,
        )

        config_email = run_git(
            [
                "config",
                "user.email",
                "aishield-bot@users.noreply.github.com",
            ],
            repo,
            env,
        )

        if config_name.returncode or config_email.returncode:
            raise HTTPException(
                status_code=500,
                detail="Could not configure remediation commit identity.",
            )

        # ---------------------------------------------------------
        # Stage changes.
        # ---------------------------------------------------------

        add = run_git(
            [
                "add",
                "--",
                *changed,
            ],
            repo,
            env,
        )

        if add.returncode:
            logger.error(
                "Git staging failed: %s",
                _git_error(add),
            )

            raise HTTPException(
                status_code=500,
                detail="Could not stage the validated patch set.",
            )

        # ---------------------------------------------------------
        # Commit.
        # ---------------------------------------------------------

        session_ids = sorted(
            {
                str(item.get("session_id"))
                for item in validated_patches
                if item.get("session_id")
            }
        )

        finding_ids = sorted(
            {
                str(item.get("finding_id"))
                for item in validated_patches
                if item.get("finding_id")
            }
        )

        commit_body = [
            f"AIShield scan commit: {commit_sha}"
        ]

        if session_ids:
            commit_body.append(
                "AIShield remediation session: "
                + ", ".join(session_ids)
            )

        if finding_ids:
            commit_body.append(
                "AIShield finding IDs: "
                + ", ".join(finding_ids)
            )

        commit_message = (
            "fix(security): apply AIShield-approved fixes"
        )

        commit = run_git(
            [
                "commit",
                "-m",
                commit_message,
                "-m",
                "\n\n".join(commit_body),
            ],
            repo,
            env,
        )

        if commit.returncode:
            logger.error(
                "Remediation commit failed: %s",
                _git_error(commit),
            )

            raise HTTPException(
                status_code=500,
                detail="Could not create the remediation commit.",
            )

        # ---------------------------------------------------------
        # Push.
        # ---------------------------------------------------------

        push = run_git(
            [
                "push",
                "origin",
                f"HEAD:refs/heads/{branch_name}",
            ],
            repo,
            env,
            timeout=120,
        )

        if push.returncode:
            logger.error(
                "Git push failed: %s",
                _git_error(push),
            )

            raise HTTPException(
                status_code=502,
                detail=(
                    "Git host rejected the push. "
                    "Check token write permissions and branch protection."
                ),
            )

        # ---------------------------------------------------------
        # Return result.
        # ---------------------------------------------------------

        head = run_git(
            [
                "rev-parse",
                "HEAD",
            ],
            repo,
            env,
        )

        if head.returncode:
            raise HTTPException(
                status_code=500,
                detail="Could not retrieve remediation commit SHA.",
            )

        return {
            "branch_name": branch_name,
            "commit_sha": head.stdout.strip(),
            "changed_files": changed,
            "commit_message": commit_message,
            "session_ids": session_ids,
            "finding_ids": finding_ids,
        }

    except subprocess.TimeoutExpired as exc:
        logger.exception(
            "Git operation timed out during remediation."
        )

        raise HTTPException(
            status_code=504,
            detail="A Git operation timed out.",
        ) from exc

    finally:
        # Remove credentials from the environment mapping.
        env.pop("AISHIELD_GIT_TOKEN", None)
        env.pop("AISHIELD_GIT_USERNAME", None)

        # Remove temporary clone and askpass helper.
        shutil.rmtree(
            temp,
            ignore_errors=True,
        )

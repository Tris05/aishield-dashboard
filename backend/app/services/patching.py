from __future__ import annotations
import os, re, subprocess, tempfile, shutil
from pathlib import Path, PurePosixPath
from fastapi import HTTPException
from .source import safe_relative_path

def validate_diff(patch: str, expected_path: str) -> tuple[bool,str]:
    try: expected=safe_relative_path(expected_path)
    except HTTPException as exc: return False, str(exc.detail)
    if not patch.strip() or len(patch.encode("utf-8")) > 50_000 or "\x00" in patch:
        return False,"Patch is empty, too large, or contains NUL bytes."
    if not patch.lstrip().startswith("diff --git "): return False,"Expected a unified Git diff."
    headers=re.findall(r"^diff --git a/(.+?) b/(.+?)$",patch,re.M)
    if len(headers)!=1 or headers[0] != (expected,expected): return False,"Patch must modify exactly the finding's single file."
    file_headers=re.findall(r"^(---|\+\+\+) (.+)$", patch, re.M)
    expected_old=f"a/{expected}"
    expected_new=f"b/{expected}"
    if file_headers != [("---", expected_old), ("+++", expected_new)]:
        return False,"Patch file headers must match the exact target path."
    if re.search(r"^(?:new file mode|deleted file mode|rename from|rename to|copy from|copy to)",patch,re.M): return False,"File creation, deletion, rename and copy operations are not allowed."
    return True,"Patch scope and structure accepted; applicability is checked against a fresh clone before push."

def run_git(args: list[str], cwd: Path, env: dict | None=None, input_text: str | None=None, timeout: int=60) -> subprocess.CompletedProcess:
    return subprocess.run(["git", *args], cwd=cwd, env=env, input=input_text, text=True, capture_output=True, timeout=timeout, check=False)

def apply_and_push(repository_url: str, commit_sha: str, source_branch: str, branch_name: str, patches: list[dict], token: str) -> dict:
    if not branch_name.strip() or len(branch_name) > 200 or "\x00" in branch_name:
        raise HTTPException(400,"Invalid remediation branch name.")
    branch_check=subprocess.run(["git","check-ref-format","--branch",branch_name],capture_output=True,text=True,check=False)
    if branch_check.returncode:
        raise HTTPException(400,"Invalid remediation branch name.")
    if not re.fullmatch(r"[0-9a-fA-F]{7,64}", commit_sha):
        raise HTTPException(400,"A valid scanned commit SHA is required.")
    host="github.com" if "github.com" in repository_url else "gitlab.com"
    username="x-access-token" if host=="github.com" else "oauth2"
    temp=Path(tempfile.mkdtemp(prefix="aishield-remediate-"))
    askpass=temp/"askpass.sh"
    askpass.write_text('#!/bin/sh\ncase "$1" in *Username*) printf "%s\n" "$AISHIELD_GIT_USERNAME" ;; *) printf "%s\n" "$AISHIELD_GIT_TOKEN" ;; esac\n',encoding="utf-8")
    askpass.chmod(0o700)
    env=os.environ.copy(); env.update({"GIT_TERMINAL_PROMPT":"0","GIT_ASKPASS":str(askpass),"AISHIELD_GIT_USERNAME":username,"AISHIELD_GIT_TOKEN":token,"GIT_CONFIG_NOSYSTEM":"1","GIT_CONFIG_GLOBAL":os.devnull,"GIT_LFS_SKIP_SMUDGE":"1"})
    try:
        clone=run_git(["-c","http.followRedirects=false","-c","http.sslVerify=true","-c","protocol.file.allow=never","clone","--no-checkout","--filter=blob:none",repository_url,"repo"],temp,env,timeout=120)
        if clone.returncode: raise HTTPException(502,"Could not clone public repository for patch application.")
        repo=temp/"repo"
        # Fetching the source branch history makes the scanned commit available even when the
        # host refuses a direct fetch of an unadvertised SHA. Blobs remain lazy-filtered.
        if source_branch and source_branch != "default":
            fetch=run_git(["fetch","--filter=blob:none","origin",source_branch],repo,env,timeout=120)
        else:
            fetch=run_git(["fetch","--filter=blob:none","origin"],repo,env,timeout=120)
        if fetch.returncode:
            fetch=run_git(["fetch","--depth=1","origin",commit_sha],repo,env,timeout=120)
        if fetch.returncode: raise HTTPException(409,"The scanned commit is no longer fetchable; run a fresh scan before remediation.")
        verify=run_git(["cat-file","-e",f"{commit_sha}^{{commit}}"],repo,env)
        if verify.returncode:
            fetch_exact=run_git(["fetch","--depth=1","origin",commit_sha],repo,env,timeout=120)
            if fetch_exact.returncode: raise HTTPException(409,"The scanned commit is not available from the repository; run a fresh scan before remediation.")
        checkout=run_git(["checkout","-b",branch_name,commit_sha],repo,env)
        if checkout.returncode: raise HTTPException(409,"Could not create remediation branch; the branch may already exist locally or the scanned commit is unavailable.")
        accepted=[]
        # Apply patches in an isolated temporary clone. Any failure aborts before remote push.
        for proposal in patches:
            rel=safe_relative_path(proposal["path"])
            target=repo
            for part in PurePosixPath(rel).parts:
                target=target/part
                if target.is_symlink():
                    raise HTTPException(422,f"Target path {rel} traverses a symlink; no branch was pushed.")
            if not target.is_file():
                raise HTTPException(422,f"Target path {rel} is not an existing regular file; no branch was pushed.")
            ok,message=validate_diff(proposal["patch"],rel)
            if not ok: raise HTTPException(422,f"Patch rejected for {rel}: {message}")
            check=run_git(["apply","--check","--whitespace=error"],repo,env,input_text=proposal["patch"])
            if check.returncode: raise HTTPException(422,f"Patch does not apply cleanly for {rel}; no branch was pushed.")
            applied=run_git(["apply","--whitespace=error"],repo,env,input_text=proposal["patch"])
            if applied.returncode: raise HTTPException(422,f"Patch application failed for {rel}; no branch was pushed.")
            accepted.append(rel)
        if not accepted: raise HTTPException(400,"No accepted fixes were supplied.")
        diffcheck=run_git(["diff","--check"],repo,env)
        if diffcheck.returncode: raise HTTPException(422,"Combined patch set failed git diff --check; no branch was pushed.")
        status=run_git(["status","--porcelain"],repo,env)
        changed=sorted({line[3:] for line in status.stdout.splitlines() if len(line)>3})
        if set(changed) != set(accepted): raise HTTPException(422,"Combined changes include unexpected files; no branch was pushed.")
        run_git(["config","user.name","AIShield Bot"],repo,env); run_git(["config","user.email","aishield-bot@users.noreply.github.com"],repo,env)
        add=run_git(["add","--",*changed],repo,env)
        if add.returncode: raise HTTPException(500,"Could not stage the validated patch set.")
        session_ids=sorted({str(item.get("session_id")) for item in patches if item.get("session_id")})
        finding_ids=sorted({str(item.get("finding_id")) for item in patches if item.get("finding_id")})
        commit_body=[f"AIShield scan commit: {commit_sha}"]
        if session_ids:
            commit_body.append("AIShield remediation session: " + ", ".join(session_ids))
        if finding_ids:
            commit_body.append("AIShield finding IDs: " + ", ".join(finding_ids))
        commit_message="fix(security): apply AIShield-approved fixes"
        commit=run_git(["commit","-m",commit_message,"-m","\n\n".join(commit_body)],repo,env)
        if commit.returncode: raise HTTPException(500,"Could not create the remediation commit.")
        push=run_git(["push","origin",f"HEAD:refs/heads/{branch_name}"],repo,env,timeout=120)
        if push.returncode: raise HTTPException(502,"Git host rejected the push. Check token write permissions and branch protection.")
        head=run_git(["rev-parse","HEAD"],repo,env).stdout.strip()
        return {"branch_name":branch_name,"commit_sha":head,"changed_files":changed,"commit_message":commit_message,"session_ids":session_ids,"finding_ids":finding_ids}
    finally:
        # The temporary clone and askpass helper are removed; the PAT is never written to disk.
        env.pop("AISHIELD_GIT_TOKEN",None)
        shutil.rmtree(temp,ignore_errors=True)

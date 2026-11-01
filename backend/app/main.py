from __future__ import annotations
from datetime import datetime, timezone
import json, secrets
from fastapi import FastAPI, Depends, HTTPException, Header
from fastapi.middleware.cors import CORSMiddleware
from .config import settings
from .database import get_database, ensure_indexes, close_database
from .schemas import ScanUpload, ConsentRequest, DecisionsRequest, ApplyRequest
from .security import require_ingest_token, require_viewer_token, validate_public_repo_url, sha256, new_token
from .services.source import fetch_source
from .services.gemini import generate_patch
from .services.patching import apply_and_push
from .services.gitlab_trigger import trigger_verification

app=FastAPI(title="AIShield Dashboard API",version="0.1.0",description="Report ingestion and consent-based AI remediation for public repositories.")
app.add_middleware(CORSMiddleware,allow_origins=list(settings.cors_origins),allow_credentials=False,allow_methods=["GET","POST","PATCH","OPTIONS"],allow_headers=["Authorization","Content-Type","X-AIShield-Viewer-Token"])

@app.on_event("shutdown")
def shutdown() -> None: close_database()

@app.get("/api/v1/health")
def health() -> dict: return {"status":"ok","service":"aishield-dashboard-api"}

@app.get("/api/v1/ready")
def ready() -> dict:
    try: get_database().command("ping"); return {"status":"ready","database":"connected"}
    except Exception as exc: raise HTTPException(503,f"Database unavailable ({type(exc).__name__}).") from exc

@app.post("/api/v1/scans/upload",dependencies=[Depends(require_ingest_token)])
def upload_scan(payload: ScanUpload) -> dict:
    db=get_database()
    ensure_indexes(db)
    canonical,provider,repo_key=validate_public_repo_url(payload.repository_url)
    if not isinstance(payload.report.get("findings"), list):
        raise HTTPException(422, "report.findings must be a JSON array.")
    encoded=json.dumps(payload.report,ensure_ascii=False,separators=(",",":" )).encode("utf-8")
    if len(encoded)>settings.max_report_bytes: raise HTTPException(413,f"Report exceeds MAX_REPORT_BYTES ({settings.max_report_bytes}).")
    now=datetime.now(timezone.utc); project=db.projects.find_one({"repo_key":repo_key})
    if not project:
        project_id="proj_"+repo_key[:16]
        db.projects.insert_one({"project_id":project_id,"repo_key":repo_key,"repository_url":canonical,"provider":provider,"created_at":now,"latest_scan_id":None})
    else: project_id=project["project_id"]
    scan_id="scan_"+secrets.token_hex(12); viewer_token=new_token(); status=payload.scan_status.lower()
    if status not in {"completed","incomplete","failed","error"}: status="completed"
    scan={"scan_id":scan_id,"project_id":project_id,"repository_url":canonical,"provider":provider,"branch":payload.branch,"commit_sha":payload.commit_sha,"scan_status":status,"scanner_version":payload.scanner_version,"ci":payload.ci,"report":payload.report,"access_token_hash":sha256(viewer_token),"created_at":now,"updated_at":now}
    db.scans.insert_one(scan)
    # Keep the most recently uploaded scan as the current report; all previous scan documents remain stored.
    db.projects.update_one({"project_id":project_id},{"$set":{"latest_scan_id":scan_id,"updated_at":now}})
    return {"project_id":project_id,"scan_id":scan_id,"scan_status":status,"dashboard_url":f"{settings.public_base_url}/s/{viewer_token}","message":"Report stored. Share the dashboard URL only with intended viewers."}

def _get_scan_by_token(db, token: str) -> dict:
    scan=db.scans.find_one({"access_token_hash":sha256(token)})
    if not scan: raise HTTPException(404,"Dashboard report not found or access URL is invalid.")
    return scan

@app.get("/api/v1/public/scans/{access_token}")
def public_scan(access_token: str) -> dict:
    scan=_get_scan_by_token(get_database(),access_token)
    return {"project_id":scan["project_id"],"scan_id":scan["scan_id"],"repository_url":scan["repository_url"],"provider":scan["provider"],"branch":scan["branch"],"commit_sha":scan.get("commit_sha"),"scan_status":scan["scan_status"],"created_at":scan["created_at"].isoformat(),"report":scan["report"]}

@app.post("/api/v1/public/scans/{access_token}/remediation/sessions")
def create_remediation_session(access_token: str, body: ConsentRequest) -> dict:
    if not body.consent: raise HTTPException(403,"AI remediation requires explicit consent.")
    db=get_database(); scan=_get_scan_by_token(db,access_token)
    findings=scan.get("report",{}).get("findings",[])
    by_id={str(item.get("id")):item for item in findings if isinstance(item,dict)}
    ids=body.finding_ids or [fid for fid,item in by_id.items() if item.get("severity") in {"critical","high","medium"} and item.get("path") and item.get("line")]
    if not ids or any(fid not in by_id for fid in ids): raise HTTPException(400,"Select valid finding IDs from this scan.")
    session_id="rem_"+secrets.token_hex(12); now=datetime.now(timezone.utc)
    db.remediation_sessions.insert_one({"session_id":session_id,"scan_id":scan["scan_id"],"project_id":scan["project_id"],"access_token_hash":sha256(access_token),"status":"consented","consent":True,"finding_ids":ids,"decisions":{},"created_at":now,"updated_at":now})
    return {"session_id":session_id,"status":"consented","finding_count":len(ids),"message":"Consent recorded for this remediation session. Source context will be retrieved only for selected findings."}

def _session(db, session_id: str, viewer_token: str) -> tuple[dict,dict]:
    session=db.remediation_sessions.find_one({"session_id":session_id,"access_token_hash":sha256(viewer_token)})
    if not session: raise HTTPException(404,"Remediation session not found.")
    scan=db.scans.find_one({"scan_id":session["scan_id"]})
    if not scan: raise HTTPException(404,"Source scan no longer exists.")
    return session,scan

@app.post("/api/v1/remediation/sessions/{session_id}/generate")
def generate_fixes(session_id: str, viewer_token: str=Depends(require_viewer_token)) -> dict:
    db=get_database(); session,scan=_session(db,session_id,viewer_token)
    if not session.get("consent"): raise HTTPException(403,"Consent is required.")
    commit_sha=str(scan.get("commit_sha") or "")
    if not __import__("re").fullmatch(r"[0-9a-fA-F]{7,64}", commit_sha):
        raise HTTPException(409,"This scan does not contain a valid commit SHA. Run a fresh scan with commit metadata before remediation.")
    finding_map={str(x.get("id")):x for x in scan.get("report",{}).get("findings",[]) if isinstance(x,dict)}
    proposals=[]
    for finding_id in session["finding_ids"]:
        finding=finding_map[finding_id]
        if finding.get("category") not in {"sast","ai-code-security","llm-application-security","secure-coding"} or not finding.get("path") or not finding.get("line"):
            proposals.append({"finding_id":finding_id,"status":"ineligible","message":"This finding category or location is not supported by the initial remediation workflow."}); continue
        fix_id="fix_"+secrets.token_hex(10); now=datetime.now(timezone.utc)
        try:
            source=fetch_source(scan["repository_url"],commit_sha,str(finding.get("path")))
            patch,message=generate_patch(finding,source)
        except HTTPException as exc:
            patch=""
            message=str(exc.detail)
        proposal={"fix_id":fix_id,"session_id":session_id,"finding_id":finding_id,"path":finding["path"],"patch":patch,"status":"proposed" if patch else "rejected","decision":"pending","validation_message":message,"created_at":now}
        db.fix_proposals.insert_one(proposal)
        proposals.append({"fix_id":fix_id,"finding_id":finding_id,"path":finding["path"],"patch":patch,"status":proposal["status"],"decision":"pending","validation_message":message})
    db.remediation_sessions.update_one({"session_id":session_id},{"$set":{"status":"proposals_generated","updated_at":datetime.now(timezone.utc)}})
    return {"session_id":session_id,"proposals":proposals}

@app.patch("/api/v1/remediation/sessions/{session_id}/decisions")
def save_decisions(session_id: str, body: DecisionsRequest, viewer_token: str=Depends(require_viewer_token)) -> dict:
    db=get_database(); session,scan=_session(db,session_id,viewer_token)
    allowed={x["fix_id"] for x in db.fix_proposals.find({"session_id":session_id,"status":"proposed"})}
    if any(fid not in allowed or decision not in {"accepted","rejected"} for fid,decision in body.decisions.items()): raise HTTPException(400,"Decision contains an unknown fix or invalid value.")
    for fid,decision in body.decisions.items(): db.fix_proposals.update_one({"fix_id":fid,"session_id":session_id},{"$set":{"decision":decision}})
    db.remediation_sessions.update_one({"session_id":session_id},{"$set":{"decisions":body.decisions,"updated_at":datetime.now(timezone.utc)}})
    return {"status":"saved","decisions":body.decisions}

@app.post("/api/v1/remediation/sessions/{session_id}/apply")
def apply_fixes(session_id: str, body: ApplyRequest, viewer_token: str=Depends(require_viewer_token)) -> dict:
    db=get_database(); session,scan=_session(db,session_id,viewer_token)
    proposals=list(db.fix_proposals.find({"session_id":session_id,"status":"proposed","decision":"accepted"}))
    if not proposals: raise HTTPException(400,"No fixes have been accepted.")
    if not body.git_token.strip():
        raise HTTPException(400,"A repository write token is required.")
    if not scan.get("commit_sha"):
        raise HTTPException(409,"The scan has no commit SHA; run a fresh scan before applying fixes.")
    result=apply_and_push(scan["repository_url"],str(scan["commit_sha"]),str(scan.get("branch") or ""),body.branch_name,proposals,body.git_token)
    try:
        verification=trigger_verification(scan["repository_url"],body.branch_name)
    except Exception as exc:
        verification={"status":"trigger_failed","message":f"Branch was pushed, but verification trigger failed ({type(exc).__name__})."}
    db.remediation_sessions.update_one({"session_id":session_id},{"$set":{"status":"pushed","branch_name":body.branch_name,"commit_sha":result["commit_sha"],"verification":verification,"updated_at":datetime.now(timezone.utc)}})
    # Derive the public compare/new PR URL. Users create PR/MR manually in this POC.
    p=scan["repository_url"].rstrip("/")
    compare_url=(f"{p}/compare/{scan.get('branch','main')}...{body.branch_name}" if scan["provider"]=="github" else f"{p}/-/compare/{scan.get('branch','main')}...{body.branch_name}")
    return {"status":"pushed","branch_name":body.branch_name,"commit_sha":result["commit_sha"],"changed_files":result["changed_files"],"compare_url":compare_url,"verification":verification,"message":"Fixes pushed in one commit. Review the branch and create a Pull Request / Merge Request manually."}

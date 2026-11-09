"use client";

import { useEffect, useMemo, useState } from "react";
import Link from "next/link";
import {
    ShieldCheck, GitBranch, ExternalLink, Check, X, Sparkles,
    LockKeyhole, Search, Filter, AlertCircle, FileCode2
} from "lucide-react";

type Finding = {
    id: string;
    title: string;
    description?: string;
    severity: string;
    category?: string;
    path?: string;
    line?: number;
    recommendation?: string;
    scanner?: string;
    evidence?: string;
};

type Scan = {
    project_id: string;
    scan_id: string;
    repository_url: string;
    provider: string;
    branch: string;
    commit_sha?: string;
    scan_status: string;
    created_at: string;
    report: {
        finding_count?: number;
        counts?: Record<string, number>;
        findings: Finding[];
        execution_summary?: { status?: string };
        coverage?: Array<{ id: string; status: string }>;
    };
};

type Proposal = {
    fix_id: string;
    finding_id: string;
    path: string;
    patch: string;
    status: string;
    decision: string;
    validation_message: string;
};

type ApplyResult = {
    message: string;
    branch_name?: string;
    commit_sha?: string;
    compare_url?: string;
    verification?: { status?: string; message?: string };
};

const API = (process.env.NEXT_PUBLIC_API_BASE_URL || "http://localhost:8000").replace(/\/$/, "");
const severityOrder = ["critical", "high", "medium", "low", "info"];
const fixableCategories = new Set([
    "sast", "ai-code-security", "llm-application-security", "secure-coding",
]);

function normalized(value?: string) {
    return (value || "").trim().toLowerCase().replaceAll("_", "-").replaceAll(" ", "-");
}

function eligibilityReason(f: Finding) {
    const reasons: string[] = [];
    if (!fixableCategories.has(normalized(f.category))) reasons.push("This finding category is not currently supported for automated patching.");
    if (!f.path) reasons.push("No source file path was provided.");
    if (!f.line) reasons.push("No source line number was provided.");
    if (!["critical", "high", "medium"].includes(normalized(f.severity))) reasons.push("Automated remediation currently supports Critical, High and Medium severity only.");
    return reasons;
}

function severityCount(findings: Finding[], level: string) {
    return findings.filter((f) => normalized(f.severity) === level).length;
}

export default function ReportView({ token }: { token: string }) {
    const [scan, setScan] = useState<Scan | null>(null);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState("");
    const [consent, setConsent] = useState(false);
    const [sessionId, setSessionId] = useState("");
    const [proposals, setProposals] = useState<Proposal[]>([]);
    const [busy, setBusy] = useState(false);
    const [message, setMessage] = useState("");
    const [pat, setPat] = useState("");
    const [branch, setBranch] = useState("");
    const [result, setResult] = useState<ApplyResult | null>(null);
    const [severity, setSeverity] = useState("all");
    const [category, setCategory] = useState("all");
    const [scanner, setScanner] = useState("all");
    const [search, setSearch] = useState("");
    const [activeFinding, setActiveFinding] = useState<Finding | null>(null);
    const [selectedFindingIds, setSelectedFindingIds] = useState<string[]>([]);

    useEffect(() => {
        let active = true;
        (async () => {
            try {
                const r = await fetch(`${API}/api/v1/public/scans/${encodeURIComponent(token)}`, { cache: "no-store" });
                if (!r.ok) throw new Error(r.status === 404 ? "This dashboard link is invalid or expired." : "Could not load the scan report.");
                const data = await r.json();
                if (active) {
                    setScan(data);
                    setBranch(`aishield/fix-${data.scan_id.slice(-8)}`);
                }
            } catch (e) {
                if (active) setError(e instanceof Error ? e.message : "Unexpected error");
            } finally {
                if (active) setLoading(false);
            }
        })();
        return () => { active = false; };
    }, [token]);

    const findings = scan?.report.findings || [];
    const eligible = useMemo(() => findings.filter((f) => eligibilityReason(f).length === 0), [findings]);
    const categories = useMemo(() => [...new Set(findings.map((f) => f.category || "Uncategorised"))].sort(), [findings]);
    const scanners = useMemo(() => [...new Set(findings.map((f) => f.scanner || "Unknown scanner"))].sort(), [findings]);
    const filteredFindings = useMemo(() => findings.filter((f) => {
        const matchesSeverity = severity === "all" || normalized(f.severity) === severity;
        const matchesCategory = category === "all" || (f.category || "Uncategorised") === category;
        const matchesScanner = scanner === "all" || (f.scanner || "Unknown scanner") === scanner;
        const haystack = [f.title, f.description, f.category, f.scanner, f.path, f.evidence, f.recommendation].join(" ").toLowerCase();
        return matchesSeverity && matchesCategory && matchesScanner && haystack.includes(search.toLowerCase());
    }), [findings, severity, category, scanner, search]);

    async function startRemediation(findingIds: string[]) {
        if (!consent || !scan || !findingIds.length || sessionId) return;
        setBusy(true);
        setMessage("Recording consent…");
        setSelectedFindingIds(findingIds);
        try {
            const r = await fetch(`${API}/api/v1/public/scans/${encodeURIComponent(token)}/remediation/sessions`, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ consent: true, finding_ids: findingIds }),
            });
            const d = await r.json();
            if (!r.ok) throw new Error(d.detail || "Could not start remediation");
            setSessionId(d.session_id);
            setMessage("Retrieving source context and generating patch proposals with Gemini…");
            const g = await fetch(`${API}/api/v1/remediation/sessions/${d.session_id}/generate`, {
                method: "POST",
                headers: { "X-AIShield-Viewer-Token": token },
            });
            const gd = await g.json();
            if (!g.ok) throw new Error(gd.detail || "Patch generation failed");
            setProposals(gd.proposals || []);
            setMessage(`Generated ${gd.proposals?.length || 0} proposal(s). Review each diff before accepting.`);
            const firstProposal = (gd.proposals || []).find((p: Proposal) => findingIds.includes(p.finding_id));
            const target = findings.find((f) => f.id === firstProposal?.finding_id) || findings.find((f) => findingIds.includes(f.id));
            if (target) setActiveFinding(target);
        } catch (e) {
            setMessage(e instanceof Error ? e.message : "Remediation failed");
        } finally {
            setBusy(false);
        }
    }

    function decide(id: string, decision: string) {
        setProposals((current) => current.map((p) => p.fix_id === id ? { ...p, decision } : p));
    }

    async function saveDecisions() {
        if (!sessionId) return;
        setBusy(true);
        try {
            const decisions = Object.fromEntries(proposals.filter((p) => p.status === "proposed" && ["accepted", "rejected"].includes(p.decision)).map((p) => [p.fix_id, p.decision]));
            const r = await fetch(`${API}/api/v1/remediation/sessions/${sessionId}/decisions`, {
                method: "PATCH",
                headers: { "Content-Type": "application/json", "X-AIShield-Viewer-Token": token },
                body: JSON.stringify({ decisions }),
            });
            const d = await r.json();
            if (!r.ok) throw new Error(d.detail || "Could not save decisions");
            setMessage("Your fix decisions have been saved.");
        } catch (e) {
            setMessage(e instanceof Error ? e.message : "Could not save decisions");
        } finally {
            setBusy(false);
        }
    }

    async function applyFixes() {
        if (!pat || !branch || !sessionId) return;
        setBusy(true);
        setMessage("Saving decisions, validating the accepted patch set and pushing one branch…");
        try {
            const decisions = Object.fromEntries(proposals.filter((p) => p.status === "proposed" && ["accepted", "rejected"].includes(p.decision)).map((p) => [p.fix_id, p.decision]));
            const saved = await fetch(`${API}/api/v1/remediation/sessions/${sessionId}/decisions`, {
                method: "PATCH",
                headers: { "Content-Type": "application/json", "X-AIShield-Viewer-Token": token },
                body: JSON.stringify({ decisions }),
            });
            const sd = await saved.json();
            if (!saved.ok) throw new Error(sd.detail || "Could not save fix decisions");
            const r = await fetch(`${API}/api/v1/remediation/sessions/${sessionId}/apply`, {
                method: "POST",
                headers: { "Content-Type": "application/json", "X-AIShield-Viewer-Token": token },
                body: JSON.stringify({ git_token: pat, branch_name: branch }),
            });
            const d: ApplyResult = await r.json();
            if (!r.ok) throw new Error(d.message || "Could not apply fixes");
            setResult(d);
            setPat("");
            setMessage(d.message);
        } catch (e) {
            setMessage(e instanceof Error ? e.message : "Apply failed");
        } finally {
            setBusy(false);
        }
    }

    if (loading) return <main className="loading-shell"><div className="spinner" />Loading your AIShield report…</main>;
    if (error || !scan) return <main className="error-shell"><ShieldCheck size={34} /><h1>Report unavailable</h1><p>{error || "No report found."}</p><Link href="/">Back to AIShield</Link></main>;

    const activeProposal = activeFinding ? proposals.find((p) => p.finding_id === activeFinding.id) : undefined;
    const acceptedCount = proposals.filter((p) => p.status === "proposed" && p.decision === "accepted").length;

    return (
        <main className="report-shell">
            <header className="report-topbar">
                <Link className="brand" href="/"><span className="brand-mark"><ShieldCheck size={18} /></span>AIShield</Link>
                <span className="pill">SCAN REPORT</span>
            </header>

            <section className="report-heading">
                <div>
                    <div className="eyebrow"><span className="eyebrow-dot" /> REPOSITORY SECURITY REPORT</div>
                    <h1>{scan.repository_url.split("/").slice(-2).join(" / ")}</h1>
                    <p className="muted">Branch <strong>{scan.branch}</strong> · Commit <code>{(scan.commit_sha || "unknown").slice(0, 12)}</code> · {new Date(scan.created_at).toLocaleString()}</p>
                </div>
                <div className="status-pill"><span />{scan.scan_status.toUpperCase()}</div>
            </section>

            <section className="summary-grid">
                <div className="summary-main"><span className="metric-label">TOTAL FINDINGS</span><strong>{scan.report.finding_count ?? findings.length}</strong><span className="muted">Across all completed scanner stages</span></div>
                {severityOrder.map((s) => <div className={`severity-card sev-${s}`} key={s}><span>{s}</span><strong>{severityCount(findings, s)}</strong></div>)}
            </section>

            {/* Keep consent and remediation controls above the findings list. */}
            <section className="remediation-panel remediation-panel-top" id="ai-remediation">
                <div className="remediation-title">
                    <div className="icon-tile"><Sparkles /></div>
                    <div>
                        <span className="eyebrow">OPTIONAL · HUMAN REVIEW REQUIRED</span>
                        <h2>AI-assisted remediation</h2>
                        <p className="muted">Generate scoped patch proposals for supported code findings. Source snippets are sent to Gemini only after consent. Nothing is pushed until you review and accept fixes and provide a repository write token.</p>
                    </div>
                </div>
                <div className="remediation-controls">
                    <div className="consent-row">
                        <input id="consent" type="checkbox" checked={consent} onChange={(e) => setConsent(e.target.checked)} disabled={!!sessionId} />
                        <label htmlFor="consent">I consent to AIShield retrieving the relevant source files from this public repository and sending redacted snippets of selected findings to Gemini for patch generation. I understand proposals require human review.</label>
                    </div>
                    <div className="remediation-actions">
                        <button className="button button-primary" disabled={!consent || busy || !eligible.length || !!sessionId} onClick={() => startRemediation(eligible.map((f) => f.id))}>
                            <Sparkles size={16} />{busy ? "Working…" : sessionId ? "Remediation session active" : `Generate fixes for all eligible (${eligible.length})`}
                        </button>
                        <span className="muted small">{eligible.length} of {findings.length} findings currently eligible</span>
                    </div>
                </div>
                {!eligible.length && <p className="muted small">No findings currently meet the supported remediation rules. Each finding below explains why it is or is not eligible.</p>}
                {message && <p className="inline-message" role="status">{message}</p>}
                {proposals.length > 0 && (
                    <div className="proposal-management">
                        <div className="proposal-toolbar">
                            <button className="button button-secondary" disabled={busy || !proposals.some((p) => p.status === "proposed")} onClick={() => setProposals((current) => current.map((p) => p.status === "proposed" ? { ...p, decision: "accepted" } : p))}>Accept All</button>
                            <button className="button button-secondary" disabled={busy || !proposals.some((p) => p.status === "proposed")} onClick={() => setProposals((current) => current.map((p) => p.status === "proposed" ? { ...p, decision: "rejected" } : p))}>Reject All</button>
                            <button className="button button-secondary" onClick={saveDecisions} disabled={busy}>Save decisions</button>
                            <span className="muted small">{acceptedCount} accepted · {proposals.length} proposal(s)</span>
                        </div>
                        <div className="proposal-list">
                            {proposals.map((p) => (
                                <article className="proposal-card" key={p.fix_id || p.finding_id}>
                                    <div className="proposal-head">
                                        <div><strong>{p.path}</strong><div className="muted small">Finding {p.finding_id.slice(0, 12)} · {p.status}</div></div>
                                        {p.status === "proposed" && <div className="decision-actions">
                                            <button className={p.decision === "accepted" ? "decision selected" : "decision"} onClick={() => decide(p.fix_id, "accepted")}><Check size={14} />Accept</button>
                                            <button className={p.decision === "rejected" ? "decision rejected" : "decision"} onClick={() => decide(p.fix_id, "rejected")}><X size={14} />Reject</button>
                                        </div>}
                                    </div>
                                    {p.patch ? <pre className="diff-block">{p.patch}</pre> : <p className="muted">{p.validation_message || "No patch was returned for this finding."}</p>}
                                </article>
                            ))}
                        </div>
                        <div className="apply-box">
                            <h3><GitBranch size={17} />Apply accepted fixes</h3>
                            <p className="muted">AIShield validates the accepted patch set in an isolated clone, then creates one branch and one commit. A validation error prevents any push.</p>
                            <label>New branch name<input value={branch} onChange={(e) => setBranch(e.target.value)} placeholder="aishield/fix-…" /></label>
                            <label>GitHub / GitLab Personal Access Token<input type="password" value={pat} onChange={(e) => setPat(e.target.value)} placeholder="Provided only for this operation" autoComplete="off" /></label>
                            <button className="button button-primary" disabled={busy || !pat || !branch.trim() || !acceptedCount} onClick={applyFixes}>Apply All Accepted Fixes</button>
                            <p className="muted tiny"><LockKeyhole size={12} />Your token is sent over HTTPS for the push operation and is not stored in the database.</p>
                        </div>
                    </div>
                )}
                {result && <div className="success-panel"><h3><ShieldCheck />Fix branch pushed</h3><p>Branch: <code>{result.branch_name}</code> · Commit: <code>{result.commit_sha?.slice(0, 12)}</code></p>{result.compare_url && <a href={result.compare_url} target="_blank" rel="noreferrer">Review changes / create PR or MR <ExternalLink size={14} /></a>}<p className="muted">Verification: {result.verification?.status} — {result.verification?.message}</p></div>}
            </section>

            <section className="section-heading findings-heading">
                <div><span className="eyebrow">ASSESSMENT</span><h2>Security findings</h2></div>
                <span className="muted">Showing {filteredFindings.length} of {findings.length} finding(s)</span>
            </section>

            <section className="finding-filters" aria-label="Finding filters">
                <div className="severity-filters">
                    {["all", ...severityOrder].map((level) => (
                        <button key={level} className={`filter-pill ${severity === level ? "active" : ""} ${level !== "all" ? `sev-${level}` : ""}`} onClick={() => setSeverity(level)}>
                            {level === "all" ? "All" : level[0].toUpperCase() + level.slice(1)} <span>{level === "all" ? findings.length : severityCount(findings, level)}</span>
                        </button>
                    ))}
                </div>
                <div className="filter-row">
                    <label><Filter size={14} /><select value={category} onChange={(e) => setCategory(e.target.value)}><option value="all">All vulnerability types</option>{categories.map((c) => <option key={c} value={c}>{c}</option>)}</select></label>
                    <label><FileCode2 size={14} /><select value={scanner} onChange={(e) => setScanner(e.target.value)}><option value="all">All scanners</option>{scanners.map((s) => <option key={s} value={s}>{s}</option>)}</select></label>
                    <label className="finding-search"><Search size={15} /><input value={search} onChange={(e) => setSearch(e.target.value)} placeholder="Search title, file, evidence…" /><button type="button" onClick={() => setSearch("")} aria-label="Clear search" disabled={!search}><X size={14} /></button></label>
                </div>
            </section>

            <div className="finding-list">
                {filteredFindings.map((f, i) => {
                    const reasons = eligibilityReason(f);
                    const findingProposal = proposals.find((p) => p.finding_id === f.id);
                    return (
                        <article className="finding-card" key={f.id || i}>
                            <div className="finding-meta">
                                <span className={`severity-tag sev-${normalized(f.severity)}`}>{f.severity}</span>
                                <span className="finding-type">{f.category || "Uncategorised"}</span>
                                <span className="muted">Scanner: {f.scanner || "Unknown"}</span>
                                <span className="muted">{f.path ? `${f.path}${f.line ? `:${f.line}` : ""}` : "Repository-wide"}</span>
                            </div>
                            <h3>{f.title}</h3>
                            <p>{f.description || "No description was provided by the scanner."}</p>
                            {f.evidence && <div className="finding-detail"><strong>Evidence</strong><pre>{f.evidence}</pre></div>}
                            {f.recommendation && <div className="recommendation"><strong>Recommended action</strong><p>{f.recommendation}</p></div>}
                            <div className="finding-actions">
                                {reasons.length === 0 && !findingProposal ? (
                                    <button className="button button-primary finding-fix-button" disabled={!consent || busy || !!sessionId} onClick={() => startRemediation([f.id])}>
                                        <Sparkles size={14} />AI Fix
                                    </button>
                                ) : reasons.length === 0 && findingProposal ? (
                                    <button className="button button-secondary finding-fix-button" onClick={() => setActiveFinding(f)}>
                                        <Sparkles size={14} />Review AI proposal
                                    </button>
                                ) : (
                                    <div className="eligibility-note"><AlertCircle size={14} /><span><strong>Automated fix unavailable:</strong> {reasons.join(" ")}</span></div>
                                )}

                            </div>
                            {reasons.length === 0 && !consent && <p className="muted tiny">Give consent in the AI-assisted remediation section above to enable AI Fix.</p>}
                            {reasons.length === 0 && sessionId && !findingProposal && <p className="muted tiny">The current remediation session is scoped to its selected findings. Start a new scan/session to generate a separate proposal for this finding.</p>}
                        </article>
                    );
                })}
                {!filteredFindings.length && <div className="empty-state"><Search size={30} /><h3>No matching findings</h3><p>Try changing the severity, category, scanner or search filters.</p><button className="button button-secondary" onClick={() => { setSeverity("all"); setCategory("all"); setScanner("all"); setSearch(""); }}>Clear filters</button></div>}
                {!findings.length && <div className="empty-state"><ShieldCheck size={32} /><h3>No findings were emitted</h3><p>Review execution status and scan coverage before interpreting this as clean.</p></div>}
            </div>

            {activeFinding && activeProposal && (
                <div className="modal-backdrop" role="presentation" onMouseDown={(e) => { if (e.target === e.currentTarget) setActiveFinding(null); }}>
                    <section className="remediation-modal" role="dialog" aria-modal="true" aria-labelledby="proposal-modal-title">
                        <div className="modal-heading"><div><span className="eyebrow">AI REMEDIATION PROPOSAL</span><h2 id="proposal-modal-title">{activeFinding.title}</h2><p className="muted">{activeFinding.path}{activeFinding.line ? `:${activeFinding.line}` : ""} · {activeFinding.severity}</p></div><button className="modal-close" onClick={() => setActiveFinding(null)} aria-label="Close"><X /></button></div>
                        <p className="muted">Review the generated unified diff carefully. AI-generated changes may be incorrect or incomplete.</p>
                        {activeProposal.patch ? <pre className="diff-block modal-diff">{activeProposal.patch}</pre> : <p className="eligibility-note">{activeProposal.validation_message || "No patch was returned."}</p>}
                        {activeProposal.status === "proposed" && <div className="modal-actions">
                            <button className={activeProposal.decision === "accepted" ? "button button-primary" : "button button-secondary"} onClick={() => decide(activeProposal.fix_id, "accepted")}><Check size={15} />Accept</button>
                            <button className={activeProposal.decision === "rejected" ? "button button-primary reject-button" : "button button-secondary"} onClick={() => decide(activeProposal.fix_id, "rejected")}><X size={15} />Reject</button>
                        </div>}
                        <button id="proposal-review" className="button button-secondary modal-done" onClick={() => setActiveFinding(null)}>Done reviewing</button>
                    </section>
                </div>
            )}

            <footer className="landing-footer">AIShield POC · This report link is a bearer link. Share it only with people you trust.</footer>
        </main>
    );
}

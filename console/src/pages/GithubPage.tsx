import { useEffect, useState } from "react";
import { api } from "../api.ts";
import { entityIds } from "../draft.tsx";
import { DecisionBadge, PolicyChips } from "../components/Badges.tsx";
import type { GithubIssueResult, SimulateResult } from "../types.ts";

export function GithubPage() {
  const [agents, setAgents] = useState<string[]>([]);
  const [agentId, setAgentId] = useState("developer-agent");
  const [repositories, setRepositories] = useState<string[]>([]);
  const [repository, setRepository] = useState("");
  const [mode, setMode] = useState<"mock" | "real" | null>(null);
  const [title, setTitle] = useState("");
  const [body, setBody] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<GithubIssueResult | null>(null);
  const [simulation, setSimulation] = useState<SimulateResult | null>(null);

  useEffect(() => {
    Promise.all([api.githubRepositories(), api.active()]).then(([r, active]) => {
      const ids = entityIds(active.version?.entities ?? [], "Agent");
      setAgents(ids); setAgentId(ids.includes("developer-agent") ? "developer-agent" : ids[0] ?? "");
      setRepositories(r.repositories); setRepository(r.repositories[0] ?? ""); setMode(r.mode);
    }).catch((e: Error) => setError(e.message));
  }, []);

  async function evaluate() {
    setBusy(true); setError(null); setSimulation(null); setResult(null);
    try {
      setSimulation(await api.simulate([{ agentId, action: "github.issue.Create", resource: { type: "Repository", id: repository } }], undefined, undefined, true));
    } catch (e) { setError((e as Error).message); } finally { setBusy(false); }
  }

  async function create() {
    setBusy(true); setError(null); setResult(null); setSimulation(null);
    try { setResult(await api.createGithubIssue(agentId, repository, title, body)); }
    catch (e) { setError(`${(e as Error).message}. Check Activity and GitHub before trying again; an interrupted request may have created an issue.`); }
    finally { setBusy(false); }
  }

  const simulated = simulation?.results[0];
  return <div className="stack">
    <header><h1>GitHub issues</h1><p>Create one issue as a registered agent. The active policy decides whether it can proceed.</p></header>
    <div className={`banner ${mode === "real" ? "banner-error" : ""}`}>
      {mode === "real" ? "LIVE · Allowed requests create real GitHub issues." : mode === "mock" ? "MOCK · Exercises authorization and audit without contacting GitHub." : "Connecting to the GitHub service…"}
    </div>
    {error && <div className="banner banner-error" role="alert">{error}</div>}
    <section className="panel">
      <header className="panel-head"><h2>New issue</h2></header>
      <form className="panel-body stack" onSubmit={(e) => { e.preventDefault(); void create(); }}>
        <label className="field"><span>Agent</span><select aria-label="Agent" value={agentId} disabled={busy} onChange={(e) => { setAgentId(e.target.value); setSimulation(null); setResult(null); }}>
          {agents.map((id) => <option key={id} value={id}>{id}</option>)}
        </select></label>
        <label className="field"><span>Repository</span><select aria-label="Repository" value={repository} disabled={busy} onChange={(e) => { setRepository(e.target.value); setSimulation(null); setResult(null); }}>
          {repositories.map((repo) => <option key={repo} value={repo}>{repo}</option>)}
        </select></label>
        <label className="field"><span>Title</span><input value={title} maxLength={256} disabled={busy} onChange={(e) => setTitle(e.target.value)} required /></label>
        <label className="field"><span>Description</span><textarea value={body} maxLength={60000} rows={6} disabled={busy} onChange={(e) => setBody(e.target.value)} /></label>
        <div className="row">
          <button type="button" className="button" disabled={busy || !repository || !agentId} onClick={() => void evaluate()}>Check active policy</button>
          <button type="submit" className="button primary" disabled={busy || !mode || !repository || !agentId || !title.trim()}>{busy ? "Working…" : mode === "real" ? "Create GitHub issue" : "Run mock issue creation"}</button>
        </div>
        <p className="muted small">Checks use the active version, not unsaved policy edits. Each creation checks the policy again. Requests are never retried automatically.</p>
      </form>
    </section>
    {simulated && <section className="panel" aria-live="polite"><div className="panel-body stack">
      <h2>Policy check · {simulation?.source}</h2><div><DecisionBadge decision={simulated.decision} /> <PolicyChips ids={simulated.determiningPolicies} /></div>
      <p>No GitHub call was made.</p>
    </div></section>}
    {result && <section className="panel" aria-live="polite"><div className="panel-body stack">
      <h2>{result.status === "SUCCESS" ? result.mode === "mock" ? "Mock issue created" : `Issue #${result.issueNumber} created` : result.status === "DENIED" ? "Issue creation denied" : "Issue outcome needs checking"}</h2>
      <div><DecisionBadge decision={result.decision} /> <PolicyChips ids={result.determiningPolicies} /></div>
      <p>{result.status === "DENIED" ? "The request was blocked before contacting GitHub." : result.status === "ERROR" || result.status === "OUTCOME_AUDIT_UNAVAILABLE" ? "Check GitHub and Activity before trying again. The request may have succeeded." : result.mode === "mock" ? "Mock result only; no GitHub issue was created." : "The issue was created using the GitHub App."}</p>
      <div className="row">{result.issueUrl && <a className="button" href={result.issueUrl} target="_blank" rel="noreferrer">Open issue</a>}<a className="button" href={`#/activity/${encodeURIComponent(result.requestId)}`}>View audit decision</a></div>
      <span className="muted small">Policy v{result.policyVersion} · {result.mode.toUpperCase()}</span>
    </div></section>}
  </div>;
}

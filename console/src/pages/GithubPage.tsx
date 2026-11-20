import { useEffect, useState } from "react";
import { api } from "../api.ts";
import { useDraft } from "../draft.tsx";
import { EntityPicker } from "../components/EntityPicker.tsx";
import { useRepositories, useSourceAgents } from "./shared.ts";
import { ExplanationView } from "../components/Explanation.tsx";
import { DecisionBadge, PolicyChips } from "../components/Badges.tsx";
import type { GithubIssueResult, SimulateResult } from "../types.ts";

export function GithubPage() {
  const draft = useDraft();
  // Checks and creation use the active version, so its agents are the choices.
  const agents = useSourceAgents("active", draft);
  const repositories = useRepositories();
  const mode = repositories.mode;
  const [agentId, setAgentId] = useState("");
  const [repository, setRepository] = useState("");
  const [title, setTitle] = useState("");
  const [body, setBody] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<GithubIssueResult | null>(null);
  const [simulation, setSimulation] = useState<SimulateResult | null>(null);

  useEffect(() => {
    const ids = agents.data ?? [];
    setAgentId((cur) => cur || (ids.includes("developer-agent") ? "developer-agent" : (ids[0] ?? "")));
  }, [agents.data]);
  useEffect(() => setRepository((cur) => cur || (repositories.data?.[0] ?? "")), [repositories.data]);
  const changed = () => { setSimulation(null); setResult(null); };

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
      {mode === "real" ? "LIVE · Allowed requests create real GitHub issues." : mode === "mock" ? "MOCK · Exercises authorization and audit without contacting GitHub." : repositories.error ? "The GitHub service is unavailable." : "Connecting to the GitHub service…"}
    </div>
    {error && <div className="banner banner-error" role="alert">{error}</div>}
    <section className="panel">
      <header className="panel-head"><h2>New issue</h2></header>
      <form className="panel-body stack" onSubmit={(e) => { e.preventDefault(); void create(); }}>
        <EntityPicker label="Agent" value={agentId} disabled={busy} noun="an agent" options={agents.data ?? []} loading={agents.data === null && !agents.error} error={agents.error} placeholder="registered agent id" onChange={(v) => { setAgentId(v); changed(); }} />
        {repositories.error
          ? <p className="builder-warning">Configured repositories could not be loaded: {repositories.error}. Issue creation needs the GitHub service.</p>
          : <EntityPicker label="Repository" value={repository} disabled={busy} noun="a repository" options={repositories.data ?? []} loading={repositories.data === null} onChange={(v) => { setRepository(v); changed(); }} />}
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
      {simulated.explanation && <ExplanationView explanation={simulated.explanation} request={{ agentId: simulated.request.agentId, action: simulated.request.action, resource: simulated.request.resource.id, resourceType: "Repository" }} />}
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

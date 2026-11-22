import { useEffect, useRef, useState } from "react";
import { api } from "../api.ts";
import { useDraft } from "../draft.tsx";
import { EntityPicker } from "../components/EntityPicker.tsx";
import { useRepositories, useSourceAgents } from "./shared.ts";
import { ExplanationView } from "../components/Explanation.tsx";
import { DecisionBadge, PolicyChips } from "../components/Badges.tsx";
import type { GithubIssueResult, SimulateResult } from "../types.ts";
import { useAgentRun } from "../agent-run.tsx";
import { AgentRunView } from "../components/AgentRunView.tsx";

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
  const [task, setTask] = useState("");
  const [confirmGemini, setConfirmGemini] = useState(false);
  const [proposedTitle, setProposedTitle] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<GithubIssueResult | null>(null);
  const [simulation, setSimulation] = useState<SimulateResult | null>(null);
  const feedbackBanner = useRef<HTMLDivElement>(null);
  const [agentTask, setAgentTask] = useState("");
  const [confirmAgent, setConfirmAgent] = useState(false);
  const agentRun = useAgentRun();
  const agentRunning = !!agentRun.current && agentRun.current.status !== "done";

  useEffect(() => {
    const ids = agents.data ?? [];
    setAgentId((cur) => cur || (ids.includes("developer-agent") ? "developer-agent" : (ids[0] ?? "")));
  }, [agents.data]);
  useEffect(() => setRepository((cur) => cur || (repositories.data?.[0] ?? "")), [repositories.data]);
  useEffect(() => { if (result || error) feedbackBanner.current?.scrollIntoView({ behavior: "smooth", block: "start" }); }, [result, error]);
  const changed = () => { setSimulation(null); setResult(null); setProposedTitle(null); setConfirmGemini(false); };

  async function evaluate() {
    setBusy(true); setError(null); setSimulation(null); setResult(null);
    try {
      setSimulation(await api.simulate([{ agentId, action: "github.issue.Create", resource: { type: "Repository", id: repository } }], undefined, undefined, true));
    } catch (e) { setError((e as Error).message); } finally { setBusy(false); }
  }

  async function create() {
    setBusy(true); setError(null); setResult(null); setSimulation(null); setProposedTitle(null);
    try { setResult(await api.createGithubIssue(agentId, repository, title, body)); }
    catch (e) { setError(`${(e as Error).message}. Check Activity and GitHub before trying again; an interrupted request may have created an issue.`); }
    finally { setBusy(false); }
  }

  async function createWithGemini() {
    setBusy(true); setError(null); setResult(null); setSimulation(null); setProposedTitle(null);
    try {
      const outcome = await api.createGeminiGithubIssue(agentId, repository, task, confirmGemini);
      setResult(outcome.result);
      setProposedTitle(outcome.proposal.title);
      setConfirmGemini(false);
    } catch (e) {
      setError(`${(e as Error).message}. Check Activity and GitHub before trying again; an interrupted request may have created an issue.`);
    } finally { setBusy(false); }
  }

  async function runAgent() {
    setError(null);
    try {
      await agentRun.start(agentId, repository, agentTask);
      setConfirmAgent(false);
    } catch (e) {
      setError((e as Error).message);
    }
  }

  const simulated = simulation?.results[0];
  return <div className="stack">
    <header><h1>GitHub</h1><p>Act in the configured repository as a registered agent: create an issue yourself, or let Gemini work on a task. The active policy decides every request.</p></header>
    <div className={`banner ${mode === "real" ? "banner-error" : ""}`}>
      {mode === "real" ? "LIVE · Allowed requests create real GitHub issues." : mode === "mock" ? "MOCK · Exercises authorization and audit without contacting GitHub." : repositories.error ? "The GitHub service is unavailable." : "Connecting to the GitHub service…"}
    </div>
    {error && <div ref={feedbackBanner} className="banner banner-error github-outcome-banner" role="alert">{error}</div>}
    {result && <div ref={feedbackBanner} className={`banner inline-banner github-outcome-banner ${result.status === "SUCCESS" ? "banner-ok" : "banner-error"}`} role={result.status === "SUCCESS" ? "status" : "alert"}>
      <strong>{result.status === "SUCCESS" ? result.mode === "mock" ? "Mock issue creation succeeded" : result.issueNumber ? `Issue #${result.issueNumber} created` : "GitHub issue created" : result.status === "DENIED" ? "Issue creation denied" : "Issue outcome needs checking"}</strong>
      {" · "}{result.status === "DENIED" ? "The active policy blocked this request; no GitHub issue was created." : result.status === "SUCCESS" ? result.mode === "mock" ? "No GitHub issue was created." : `Created in ${repository}.` : "Check GitHub and Activity before retrying; the issue may have been created."}
      {" "}{result.issueUrl && <a href={result.issueUrl} target="_blank" rel="noreferrer">Open issue</a>}
      {" "}<a href={`#/activity/${encodeURIComponent(result.requestId)}`}>View audit decision</a>
    </div>}
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
    <section className="panel">
      <header className="panel-head"><h2>Ask Gemini to create an issue</h2></header>
      <form className="panel-body stack" onSubmit={(e) => { e.preventDefault(); void createWithGemini(); }}>
        <p>Gemini writes one title and description from your task. Orbitport creates the issue as the agent and checks the active policy.</p>
        <label className="field"><span>Task</span><textarea value={task} maxLength={4000} rows={5} disabled={busy} onChange={(e) => { setTask(e.target.value); changed(); }} placeholder="Describe the issue you want created" required /></label>
        <label className="row"><input type="checkbox" checked={confirmGemini} disabled={busy} onChange={(e) => setConfirmGemini(e.target.checked)} /><span>{mode === "real" ? "I understand this may create a real GitHub issue in the selected repository." : "I understand this will attempt one mock issue creation."}</span></label>
        <button type="submit" className="button primary" disabled={busy || !mode || !repository || !agentId || !task.trim() || !confirmGemini}>{busy ? "Working…" : mode === "real" ? "Create issue with Gemini" : "Run Gemini mock issue"}</button>
        <p className="muted small">Uses the agent and repository selected above. Gemini can write the issue text; it cannot choose the agent or repository.</p>
      </form>
    </section>
    <section className="panel">
      <header className="panel-head"><h2>Gemini agent</h2></header>
      <form className="panel-body stack" onSubmit={(e) => { e.preventDefault(); void runAgent(); }}>
        <p>Gemini works on a task in the selected repository as the selected agent, using GitHub tools. <strong>Every tool call is checked by the active policy</strong>; denied calls are reported back to Gemini and recorded in Activity.</p>
        <label className="field"><span>Task</span><textarea value={agentTask} maxLength={4000} rows={5} disabled={busy} onChange={(e) => { setAgentTask(e.target.value); setConfirmAgent(false); }} placeholder="e.g. Read README.md, fix the typo in the first paragraph on a new branch, and open a pull request" required /></label>
        <label className="row"><input type="checkbox" checked={confirmAgent} disabled={busy} onChange={(e) => setConfirmAgent(e.target.checked)} /><span>{mode === "real" ? "I understand Gemini may make real changes in this repository (issues, branches, commits, pull requests) wherever the policy allows." : "I understand Gemini will run against the mock repository."}</span></label>
        <div className="row">
          <button type="submit" className="button primary" disabled={busy || agentRunning || !mode || !repository || !agentId || !agentTask.trim() || !confirmAgent}>{agentRunning ? "Gemini is working…" : "Run Gemini agent"}</button>
          {agentRunning && <button type="button" className="button danger" disabled={agentRun.current?.status === "stopping"} onClick={() => void agentRun.stop()}>{agentRun.current?.status === "stopping" ? "Stopping…" : "Stop"}</button>}
        </div>
        <p className="muted small">At most 12 tool calls and 2 minutes per run. The run continues if you switch pages (a corner toast shows its progress). Stop ends it at the next safe point: a pending Gemini call is cancelled, a GitHub call already sent finishes first. Gemini can't choose the agent or the repository. Nothing is retried automatically.</p>
        {agentRun.error && <p className="field-hint">{agentRun.error}</p>}
      </form>
    </section>
    {agentRun.current && <AgentRunView state={agentRun.current} onStop={() => void agentRun.stop()} />}
    {simulated && <section className="panel" aria-live="polite"><div className="panel-body stack">
      <h2>Policy check · {simulation?.source}</h2><div><DecisionBadge decision={simulated.decision} /> <PolicyChips ids={simulated.determiningPolicies} /></div>
      {simulated.explanation && <ExplanationView explanation={simulated.explanation} request={{ agentId: simulated.request.agentId, action: simulated.request.action, resource: simulated.request.resource.id, resourceType: "Repository" }} />}
      <p>No GitHub call was made.</p>
    </div></section>}
    {result && <section className="panel" aria-live="polite"><div className="panel-body stack">
      <h2>{result.status === "SUCCESS" ? result.mode === "mock" ? "Mock issue created" : `Issue #${result.issueNumber} created` : result.status === "DENIED" ? "Issue creation denied" : "Issue outcome needs checking"}</h2>
      {proposedTitle && <p>Gemini proposed: <strong>{proposedTitle}</strong></p>}
      <div><DecisionBadge decision={result.decision} /> <PolicyChips ids={result.determiningPolicies} /></div>
      <p>{result.status === "DENIED" ? "The request was blocked before contacting GitHub." : result.status === "ERROR" || result.status === "OUTCOME_AUDIT_UNAVAILABLE" ? "Check GitHub and Activity before trying again. The request may have succeeded." : result.mode === "mock" ? "Mock result only; no GitHub issue was created." : "The issue was created using the GitHub App."}</p>
      <div className="row">{result.issueUrl && <a className="button" href={result.issueUrl} target="_blank" rel="noreferrer">Open issue</a>}<a className="button" href={`#/activity/${encodeURIComponent(result.requestId)}`}>View audit decision</a></div>
      <span className="muted small">Policy v{result.policyVersion} · {result.mode.toUpperCase()}</span>
    </div></section>}
  </div>;
}

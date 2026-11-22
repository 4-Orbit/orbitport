import { useState } from "react";
import type { AgentRun, AgentRunState, AgentStep } from "../types.ts";
import { DecisionBadge, PolicyChips } from "./Badges.tsx";
import { InfoDialog } from "./Confirm.tsx";
import { needsHelp, stepHelp } from "../agent-step-help.ts";

const stoppedText: Record<AgentRun["stopped"], string> = {
  done: "Gemini finished.",
  step_limit: "Stopped at the tool-call limit.",
  time_limit: "Stopped at the time limit.",
  gemini_error: "Stopped: Gemini failed.",
  nothing_allowed: "Not started: the active policy and the GitHub App installation allow none of the GitHub tools for this agent and repository. Gemini wasn't called.",
  denied: "Stopped after repeated denials, without another Gemini call.",
  stopped: "Stopped by you. Steps already done stay done.",
};

/** The log of one Gemini agent run: every tool call and what the policy decided. */
/** A run in progress or finished: steps appear as they happen. */
export function AgentRunView({ state, onStop }: { state: AgentRunState; onStop: () => void }) {
  const live = state.status !== "done";
  const run: AgentRun = state.run ?? { steps: state.steps, final: null, stopped: "done", tools: [], ...(state.error && { stopped: "gemini_error", error: state.error }) };
  const { mode, agentId, repository } = state;
  const denied = run.steps.filter((s) => s.decision === "DENY").length;
  const failed = run.steps.filter(needsHelp).length;
  const [open, setOpen] = useState<{ step: AgentStep; n: number } | null>(null);
  return (
    <section className="panel" aria-live="polite" aria-label="Gemini agent run">
      <header className="panel-head">
        <h2>Agent run</h2>
        <span className="muted small">
          {run.steps.length} tool call{run.steps.length === 1 ? "" : "s"} · {denied} denied · {failed - denied} other problem{failed - denied === 1 ? "" : "s"} · {mode ? mode.toUpperCase() : "mode unknown"}
        </span>
      </header>
      <div className="panel-body stack">
        {live ? (
          <div className="row">
            <span className="muted small">{state.status === "stopping" ? "Stopping at the next safe point…" : `Gemini is working… ${state.steps.length} tool call${state.steps.length === 1 ? "" : "s"} so far.`}</span>
            <button type="button" className="button small danger" disabled={state.status === "stopping"} onClick={onStop}>
              {state.status === "stopping" ? "Stopping…" : "Stop"}
            </button>
          </div>
        ) : (
          <p className={run.stopped === "done" ? "muted small" : "builder-warning"}>
            {stoppedText[run.stopped]}
            {run.error ? ` ${run.error}` : ""}
          </p>
        )}
        {!live && run.stopped !== "nothing_allowed" && (
          <p className="muted small">
            Tools offered to Gemini (the ones the active policy and the App installation could allow): <span className="mono">{run.tools.join(", ") || "none"}</span>
          </p>
        )}
        {run.skipped?.some((s) => s.why === "app") && (
          <p className="builder-warning">
            Left out because the GitHub App installation lacks permissions:{" "}
            {run.skipped
              .filter((s) => s.why === "app")
              .map((s) => `${s.method} (needs ${s.missing?.join(", ")})`)
              .join("; ")}
            . Give the App those permissions and accept them on the installation (the org's Settings → Third-party Access → GitHub Apps → Configure).
          </p>
        )}
        {run.steps.length > 0 && (
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>#</th>
                  <th>Tool</th>
                  <th>Request</th>
                  <th>Cedar</th>
                  <th>Outcome</th>
                  <th>Determined by</th>
                  <th />
                </tr>
              </thead>
              <tbody>
                {run.steps.map((s, i) => (
                  <tr key={i} className={s.decision === "DENY" || s.error ? "row-fail" : undefined}>
                    <td className="mono">{i + 1}</td>
                    <td className="mono">{s.tool}</td>
                    <td>{s.summary}</td>
                    <td>{s.decision ? <DecisionBadge decision={s.decision} /> : <span className="muted">—</span>}</td>
                    <td className="small agent-outcome">
                      {s.error ? (
                        <>
                          <span className="field-hint">{s.error}</span>
                          <div>
                            <button type="button" className="link-button" onClick={() => setOpen({ step: s, n: i + 1 })}>
                              Details
                            </button>
                          </div>
                        </>
                      ) : (
                        <>
                          {s.status}
                          {s.number ? ` #${s.number}` : ""}
                          {s.ref ? ` ${s.ref}` : ""}
                          {s.sha ? <span className="mono"> {s.sha.slice(0, 7)}</span> : ""}
                          {s.url && (
                            <>
                              {" "}
                              <a href={s.url} target="_blank" rel="noreferrer">
                                open
                              </a>
                            </>
                          )}
                          {s.reason && <div className="field-hint">{s.reason}</div>}
                          {needsHelp(s) && (
                            <div>
                              <button type="button" className="link-button" onClick={() => setOpen({ step: s, n: i + 1 })}>
                                Details
                              </button>
                            </div>
                          )}
                        </>
                      )}
                    </td>
                    <td>{s.determiningPolicies && <PolicyChips ids={s.determiningPolicies} />}</td>
                    <td>{s.requestId && <a href={`#/activity/${encodeURIComponent(s.requestId)}`}>audit</a>}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
        {open && <StepDetails step={open.step} n={open.n} agentId={agentId} repository={repository} onClose={() => setOpen(null)} />}
        {run.final && (
          <div>
            <strong>{run.stopped === "done" || run.stopped === "step_limit" ? "Gemini’s summary" : "Summary"}</strong>
            <p className="agent-final">{run.final}</p>
          </div>
        )}
      </div>
    </section>
  );
}

function StepDetails({ step, n, agentId, repository, onClose }: { step: AgentStep; n: number; agentId: string; repository: string; onClose: () => void }) {
  const help = stepHelp(step, { agentId, repository });
  return (
    <InfoDialog title={`Step ${n}: ${help.title}`} onClose={onClose}>
      <dl className="kv">
        <dt>Tool</dt>
        <dd className="mono">
          {step.tool}
          {step.method ? ` (${step.method})` : ""}
        </dd>
        <dt>Request</dt>
        <dd>{step.summary}</dd>
        <dt>Cedar</dt>
        <dd>
          {step.decision ? <DecisionBadge decision={step.decision} /> : "not evaluated"} {step.determiningPolicies && <PolicyChips ids={step.determiningPolicies} />}
        </dd>
        {step.status && (
          <>
            <dt>Outcome</dt>
            <dd className="mono">{step.status}</dd>
          </>
        )}
        {(step.reason || step.error) && (
          <>
            <dt>Reason</dt>
            <dd>{step.reason ?? step.error}</dd>
          </>
        )}
      </dl>
      <p>{help.meaning}</p>
      <strong>What you can do</strong>
      <ul>
        {help.fixes.map((f) => (
          <li key={f}>{f}</li>
        ))}
      </ul>
      {step.requestId && (
        <p className="small">
          <a href={`#/activity/${encodeURIComponent(step.requestId)}`} onClick={onClose}>
            Open the audit entry
          </a>
        </p>
      )}
    </InfoDialog>
  );
}

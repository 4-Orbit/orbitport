import type { AgentRun } from "../types.ts";
import { DecisionBadge, PolicyChips } from "./Badges.tsx";

const stoppedText: Record<AgentRun["stopped"], string> = {
  done: "Gemini finished.",
  step_limit: "Stopped at the tool-call limit.",
  time_limit: "Stopped at the time limit.",
  gemini_error: "Stopped: Gemini failed.",
  nothing_allowed: "Not started: the active policy allows none of the GitHub tools for this agent and repository. Gemini wasn't called.",
  denied: "Stopped after repeated denials, without another Gemini call.",
};

/** The log of one Gemini agent run: every tool call and what the policy decided. */
export function AgentRunView({ run, mode }: { run: AgentRun; mode: "mock" | "real" | null }) {
  const denied = run.steps.filter((s) => s.decision === "DENY").length;
  return (
    <section className="panel" aria-live="polite" aria-label="Gemini agent run">
      <header className="panel-head">
        <h2>Agent run</h2>
        <span className="muted small">
          {run.steps.length} tool call{run.steps.length === 1 ? "" : "s"} · {denied} denied · {mode ? mode.toUpperCase() : "mode unknown"}
        </span>
      </header>
      <div className="panel-body stack">
        <p className={run.stopped === "done" ? "muted small" : "builder-warning"}>
          {stoppedText[run.stopped]}
          {run.error ? ` ${run.error}` : ""}
        </p>
        {run.stopped !== "nothing_allowed" && (
          <p className="muted small">
            Tools offered to Gemini (the ones the active policy could allow): <span className="mono">{run.tools.join(", ") || "none"}</span>
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
                    <td className="small">
                      {s.error ? (
                        <span className="field-hint">{s.error}</span>
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

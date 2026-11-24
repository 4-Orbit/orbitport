import { useAgentRun } from "../agent-run.tsx";
import { DecisionBadge } from "./Badges.tsx";

/** Progress of a Gemini agent run, in the corner of every page but GitHub. */
export function AgentRunToast() {
  const { current, toastVisible, stop } = useAgentRun();
  if (!current || !toastVisible) return null;
  const last = current.steps.at(-1);
  const done = current.status === "done";
  const denied = current.steps.filter((s) => s.decision === "DENY").length;
  return (
    <div className="agent-toast" role="status" aria-label="Gemini agent run">
      <div className="agent-toast-head">
        <strong>{done ? (current.run?.stopped === "stopped" ? "Gemini agent stopped" : "Gemini agent finished") : current.status === "stopping" ? "Stopping Gemini agent…" : "Gemini agent working…"}</strong>
        <span className="muted small">
          {current.agentId} · {current.steps.length} tool call{current.steps.length === 1 ? "" : "s"}
          {denied ? ` · ${denied} denied` : ""}
        </span>
      </div>
      {last && (
        <div className="small agent-toast-last">
          {last.decision && <DecisionBadge decision={last.decision} />} <span className="mono">{last.tool}</span> {last.summary}
        </div>
      )}
      {current.error && <div className="field-hint">{current.error}</div>}
      <div className="row">
        {!done && (
          <button type="button" className="button small danger" disabled={current.status === "stopping"} onClick={() => void stop()}>
            {current.status === "stopping" ? "Stopping…" : "Stop"}
          </button>
        )}
        <a className="button small" href="#/github">
          View run
        </a>
      </div>
    </div>
  );
}

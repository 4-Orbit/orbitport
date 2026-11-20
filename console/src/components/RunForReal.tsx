import { useCallback, useState } from "react";
import { api } from "../api.ts";
import { cannotRun } from "../run-actions.ts";
import { compareRun, type Simulated } from "../run-compare.ts";
import type { RunResult, SimRequest } from "../types.ts";
import { DecisionBadge, KmsCalledBadge, PolicyChips } from "./Badges.tsx";
import { LiveExplanation } from "./Explanation.tsx";

/**
 * "Run it for real": send the simulated request to the KMS as the agent and
 * show the real decision beside the simulated one. The console server
 * mints a short-lived token for the agent; the browser never sees it.
 */
export function RunForReal({ request, simulated }: { request: SimRequest; simulated: Simulated }) {
  const [busy, setBusy] = useState(false);
  const [real, setReal] = useState<RunResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const blocked = cannotRun(request);

  const run = async () => {
    setBusy(true);
    setError(null);
    setReal(null);
    try {
      setReal(await api.runForReal(request.agentId!, request.action, request.resource.id));
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  };

  // A real DENY is explained against the version the KMS enforced, now.
  const version = real?.policyVersion ?? 0;
  const loadExplanation = useCallback(
    () => api.explain(request, version ? { version } : undefined).then((r) => r.explanation),
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [request.agentId, request.action, request.resource.id, version],
  );

  if (request.resource.type === "Repository")
    return (
      <p className="muted small">
        Run it for real only sends KMS requests. To try this for real, <a href="#/github">create an issue on the GitHub page</a>; the active version decides it the same way.
      </p>
    );
  if (blocked) return <p className="muted small">{blocked}</p>;
  const cmp = real ? compareRun(simulated, real) : null;

  return (
    <div className="run-real">
      <div className="row">
        <button type="button" className="button" disabled={busy} onClick={() => void run()}>
          {busy ? "Running…" : real ? "Run it for real again" : "Run it for real"}
        </button>
        <span className="muted small">
          Sends this request to the KMS as <strong>{request.agentId}</strong>, with sample data. Nothing about the key changes.
        </span>
      </div>
      {error && <div className="banner banner-error inline-banner">{error}</div>}
      {real && cmp && (
        <div className={`run-compare run-${cmp.tone}`} role="status">
          <div className="run-sides">
            <div>
              <span className="muted small">Simulated ({simulated.source})</span>
              <DecisionBadge decision={simulated.decision} />
            </div>
            <div>
              <span className="muted small">Real ({real.policyVersion ? `v${real.policyVersion}` : "KMS"})</span>
              {real.decision ? <DecisionBadge decision={real.decision} /> : <span className="badge result result-none">unknown</span>}
            </div>
            {real.kmsCalled !== null && (
              <div>
                <span className="muted small">KMS called</span>
                <KmsCalledBadge called={real.kmsCalled} />
              </div>
            )}
          </div>
          <p className={cmp.tone === "disagree" ? "run-alarm" : undefined}>{cmp.message}</p>
          <p className="small">
            <span className="muted">Result: </span>
            {real.outcome}
            {real.decision === "ALLOW" && real.failed && <span className="muted"> (allowed by policy; the KMS refused the sample request)</span>}
          </p>
          {real.decision && (
            <p className="small">
              <span className="muted">Decided by </span>
              <PolicyChips ids={real.determiningPolicies} />
              {real.requestId && (
                <>
                  {" · "}
                  <a href={`#/activity/${encodeURIComponent(real.requestId)}`}>open in Activity</a>
                </>
              )}
            </p>
          )}
          {/* The simulation already explains its own DENY; explain the real one only when it adds something. */}
          {real.decision === "DENY" && simulated.decision !== "DENY" && (
            <LiveExplanation load={loadExplanation} request={{ agentId: request.agentId, action: request.action, resource: request.resource.id }} />
          )}
        </div>
      )}
    </div>
  );
}

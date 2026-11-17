import { useState } from "react";
import { api } from "../api.ts";
import { usePolling } from "../usePolling.ts";
import { go } from "../route.ts";
import { useDraft } from "../draft.tsx";
import type { AuditEvent, AuditFilter, Decision } from "../types.ts";
import { DecisionBadge, KmsCalledBadge, KmsResultBadge, ModeBadge, PolicyChips } from "../components/Badges.tsx";
import { SummaryStrip } from "../components/SummaryStrip.tsx";
import { formatTime } from "../format.ts";

/** `Agent::"developer-agent"` -> developer-agent */
export const uidId = (uid: string) => /::"(.*)"$/.exec(uid)?.[1] ?? uid;
export const uidType = (uid: string) => uid.split("::")[0];

export function ActivityPage({ selectedId }: { selectedId: string | null }) {
  const [filter, setFilter] = useState<AuditFilter>({ limit: 200 });
  const audit = usePolling(() => api.audit(filter), 3000);
  const events = audit.data?.events ?? [];
  const selected = events.find((e) => e.requestId === selectedId) ?? null;
  const principals = new Set(events.map((e) => e.principal)).size;

  return (
    <>
      {audit.error && <div className="banner banner-error inline-banner">Could not load audit: {audit.error}</div>}
      {audit.data && <SummaryStrip summary={audit.data.summary} agents={principals} />}
      <Filters filter={filter} onChange={setFilter} />
      {audit.data && events.length === 0 && (
        <section className="panel empty-state">
          <h2>No decisions match</h2>
          <p>
            Every KMS call and policy-admin attempt is recorded here. Generate some with <code>make 4orbit-e2e</code> or, for example:
          </p>
          <pre>scripts/4orbit/rpc.sh developer-agent kms.Encrypt '{"{"}"KeyId":"kms:dev-key","Plaintext":"aGVsbG8="{"}"}'</pre>
        </section>
      )}
      {events.length > 0 && (
        <div className={selected ? "split" : undefined}>
          <section className="panel activity">
            <div className="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>Time</th>
                    <th>Principal</th>
                    <th>Action</th>
                    <th>Resource</th>
                    <th>Cedar</th>
                    <th>Determining policies</th>
                    <th>KMS called</th>
                    <th>Result</th>
                    <th>Mode</th>
                    <th>Policy</th>
                  </tr>
                </thead>
                <tbody>
                  {events.map((ev) => (
                    <tr
                      key={ev.requestId}
                      className={ev.requestId === selectedId ? "selected" : undefined}
                      tabIndex={0}
                      onClick={() => go("activity", ev.requestId)}
                      onKeyDown={(e) => (e.key === "Enter" || e.key === " ") && (e.preventDefault(), go("activity", ev.requestId))}
                      aria-selected={ev.requestId === selectedId}
                    >
                      <td className="mono muted" title={ev.ts}>
                        {formatTime(ev.ts)}
                      </td>
                      <td className="mono">{uidType(ev.principal) === "Account" ? "(account)" : uidId(ev.principal)}</td>
                      <td className="mono">{uidId(ev.action)}</td>
                      <td className="mono">{uidId(ev.resource)}</td>
                      <td>
                        <DecisionBadge decision={ev.decision} />
                      </td>
                      <td>
                        <PolicyChips ids={ev.determiningPolicies} />
                        {ev.authzErrors && <span className="badge result result-error">ERROR</span>}
                      </td>
                      <td>
                        <KmsCalledBadge called={ev.kmsCalled} />
                      </td>
                      <td>
                        <KmsResultBadge ev={ev} />
                      </td>
                      <td>
                        <ModeBadge mode={ev.mode} />
                      </td>
                      <td className="mono muted">{ev.policyVersion ? `v${ev.policyVersion}` : "—"}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </section>
          {selected && <Detail ev={selected} />}
        </div>
      )}
    </>
  );
}

function Filters({ filter, onChange }: { filter: AuditFilter; onChange: (f: AuditFilter) => void }) {
  return (
    <section className="panel filters">
      <div className="segmented" role="group" aria-label="Filter by decision">
        {(["", "ALLOW", "DENY"] as const).map((d) => (
          <button key={d || "all"} type="button" aria-pressed={(filter.decision ?? "") === d} onClick={() => onChange({ ...filter, decision: d as Decision | "" })}>
            {d || "All"}
          </button>
        ))}
      </div>
      <label className="field inline">
        <span>Agent</span>
        <input value={filter.agentId ?? ""} placeholder="any" onChange={(e) => onChange({ ...filter, agentId: e.target.value.trim() })} />
      </label>
      <label className="field inline">
        <span>Action</span>
        <input value={filter.action ?? ""} placeholder="e.g. kms.Encrypt" onChange={(e) => onChange({ ...filter, action: e.target.value.trim() })} />
      </label>
      <label className="field inline">
        <span>Resource</span>
        <input value={filter.resource ?? ""} placeholder="e.g. dev-key" onChange={(e) => onChange({ ...filter, resource: e.target.value.trim() })} />
      </label>
    </section>
  );
}

function Detail({ ev }: { ev: AuditEvent }) {
  const draft = useDraft();
  const replayable = uidType(ev.resource) === "Key" && ev.action.startsWith('Action::"kms.');
  const replay = () => {
    draft.setPendingSim({
      agentId: uidType(ev.principal) === "Agent" ? uidId(ev.principal) : undefined,
      action: uidId(ev.action),
      resource: { type: uidType(ev.resource), id: uidId(ev.resource) },
    });
    go("simulate");
  };
  return (
    <aside className="panel detail" aria-label="Decision detail">
      <header className="panel-head">
        <h2>Decision</h2>
        <button type="button" className="icon-button" aria-label="Close" onClick={() => go("activity")}>
          ×
        </button>
      </header>
      <div className="detail-id mono">{ev.requestId}</div>
      <dl className="kv">
        <dt>Time</dt>
        <dd className="mono">{ev.ts}</dd>
        <dt>Principal</dt>
        <dd className="mono">{ev.principal}</dd>
        <dt>Action</dt>
        <dd className="mono">{ev.action}</dd>
        <dt>Resource</dt>
        <dd className="mono">{ev.resource}</dd>
        <dt>Cedar</dt>
        <dd>
          <DecisionBadge decision={ev.decision} />
        </dd>
        <dt>Determined by</dt>
        <dd>
          <PolicyChips ids={ev.determiningPolicies} />
        </dd>
        {ev.authzErrors && (
          <>
            <dt>Authz errors</dt>
            <dd>{ev.authzErrors.join(", ")} (failed closed; diagnostics stay in the KMS plugin log)</dd>
          </>
        )}
        <dt>KMS called</dt>
        <dd>
          <KmsCalledBadge called={ev.kmsCalled} /> {ev.kmsOperation && <span className="mono muted">{ev.kmsOperation}</span>}
        </dd>
        <dt>KMS result</dt>
        <dd>
          <KmsResultBadge ev={ev} />
        </dd>
        <dt>Mode</dt>
        <dd>
          <ModeBadge mode={ev.mode} />
        </dd>
        <dt>Policy version</dt>
        <dd className="mono">{ev.policyVersion ? `v${ev.policyVersion}` : "none (platform only)"}</dd>
        <dt>Token</dt>
        <dd className="mono muted">{ev.jtiHash ? `jti hash ${ev.jtiHash}` : "—"}</dd>
      </dl>
      {replayable && (
        <div className="detail-section">
          <p className="muted small">Would your draft have decided this differently?</p>
          <button type="button" className="button" onClick={replay}>
            Replay in simulator
          </button>
        </div>
      )}
    </aside>
  );
}

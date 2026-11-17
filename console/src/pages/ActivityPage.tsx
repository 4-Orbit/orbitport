import { Intro, Term } from "../components/Help.tsx";
import { useCallback, useEffect, useRef, useState } from "react";
import { appendPage } from "../paging.ts";
import { api } from "../api.ts";
import { usePolling } from "../usePolling.ts";
import { go } from "../route.ts";
import { useDraft } from "../draft.tsx";
import type { AuditEvent, AuditFilter, Decision, KeyInfo } from "../types.ts";
import { DecisionBadge, KmsCalledBadge, KmsResultBadge, ModeBadge, PolicyChips } from "../components/Badges.tsx";
import { SummaryStrip } from "../components/SummaryStrip.tsx";
import { formatTime } from "../format.ts";
import { ExplanationView, LiveExplanation } from "../components/Explanation.tsx";
import { useKeys } from "./shared.ts";

/** `Agent::"developer-agent"` -> developer-agent */
export const uidId = (uid: string) => /::"(.*)"$/.exec(uid)?.[1] ?? uid;
export const uidType = (uid: string) => uid.split("::")[0];

/** Events per page. The newest page keeps polling; older pages are appended. */
const PAGE = 50;

interface Older {
  /** The filter these pages belong to (as JSON), so a filter change discards them. */
  filterKey: string;
  items: AuditEvent[];
  cursor: string;
}

export function ActivityPage({ selectedId }: { selectedId: string | null }) {
  const [filter, setFilter] = useState<AuditFilter>({});
  const filterKey = JSON.stringify(filter);
  const audit = usePolling(() => api.audit({ ...filter, limit: PAGE }), 3000);
  const [older, setOlder] = useState<Older>({ filterKey, items: [], cursor: "" });
  const [loadingOlder, setLoadingOlder] = useState(false);
  const shownIds = useRef<Set<string>>(new Set());

  // A new filter re-queries now and drops pages loaded for the old one.
  useEffect(() => {
    setOlder({ filterKey, items: [], cursor: "" });
    void audit.refresh();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [filterKey]);

  const newest = audit.data?.events ?? [];
  const olderItems = older.filterKey === filterKey ? older.items : [];
  // If so many events arrived that the newest page no longer touches what is
  // shown, older pages would leave a hidden gap: start again from the newest.
  useEffect(() => {
    if (olderItems.length === 0 || newest.length === 0) return;
    if (!newest.some((e) => shownIds.current.has(e.requestId))) setOlder({ filterKey, items: [], cursor: "" });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [audit.data]);

  const events = appendPage(newest, olderItems, (e) => e.requestId);
  shownIds.current = new Set(events.map((e) => e.requestId));
  const olderCursor = olderItems.length > 0 ? older.cursor : (audit.data?.nextCursor ?? "");

  async function loadOlder() {
    setLoadingOlder(true);
    try {
      const r = await api.audit({ ...filter, limit: PAGE, cursor: olderCursor });
      setOlder({ filterKey, items: appendPage(olderItems, r.events, (e) => e.requestId), cursor: r.nextCursor });
    } finally {
      setLoadingOlder(false);
    }
  }
  const selected = events.find((e) => e.requestId === selectedId) ?? null;
  const keys = useKeys();
  const principals = new Set(events.map((e) => e.principal)).size;

  return (
    <>
      <Intro page="activity" title="Activity: what actually happened">
        Every request agents made to the KMS, newest first: who asked, what, on which key, whether the <Term k="active">active version</Term>'s rules allowed it, and which rule decided. A DENY never reaches the key. Click a row for details, or replay it in the simulator.
      </Intro>
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
            <div className="list-footer">
              <span className="muted small">
                Showing {events.length} {filterKey === "{}" ? "" : "matching "}event{events.length === 1 ? "" : "s"}, newest first
                {olderCursor ? "; older events exist" : "; that's everything still kept (the newest 2,000 per tenant)"}
              </span>
              {olderCursor && (
                <button type="button" className="button small" disabled={loadingOlder} onClick={() => void loadOlder()}>
                  {loadingOlder ? "Loading…" : "Load older events"}
                </button>
              )}
            </div>
          </section>
          {selected && <Detail ev={selected} keys={keys.data} />}
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

function Detail({ ev, keys }: { ev: AuditEvent; keys: KeyInfo[] | null }) {
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
      {ev.decision === "DENY" && <DenyExplanation ev={ev} keys={keys} />}
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

/**
 * Why an Activity DENY happened: explained against the version that was
 * enforced, at the time of the request. Audit events don't record key tags,
 * so tag rules are judged with the key's current tags.
 *
 * Policy administration (policy.*) is decided by the platform rules alone
 * and recorded with version 0, so it is explained against an empty bundle,
 * which leaves exactly the platform rules. A KMS event with version 0 means
 * no version was active.
 */
function DenyExplanation({ ev, keys }: { ev: AuditEvent; keys: KeyInfo[] | null }) {
  const agentId = uidType(ev.principal) === "Agent" ? uidId(ev.principal) : undefined;
  const action = uidId(ev.action);
  const type = uidType(ev.resource);
  const id = uidId(ev.resource);
  const at = Math.floor(Date.parse(ev.ts) / 1000);
  const key = type === "Key" ? keys?.find((k) => k.alias === id) : undefined;
  const tags = key ? Object.fromEntries(key.tags.map((t) => [t.key, t.value])) : undefined;
  const tagsKey = JSON.stringify(tags ?? null);
  const platformOnly = action.startsWith("policy.");
  const source = platformOnly ? { draft: { policies: "", entities: [] } } : { version: ev.policyVersion };
  const load = useCallback(
    () =>
      api
        .explain(
          { agentId, action, resource: { type, id, ...(tags && { tags }), ...(key && { attrs: { scheme: key.scheme, keySpec: key.keySpec, keyUsage: key.keyUsage } }) } },
          source,
          Number.isFinite(at) ? at : undefined,
        )
        .then((r) => r.explanation),
    // tags/key are captured through tagsKey.
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [agentId, action, type, id, ev.policyVersion, platformOnly, at, tagsKey],
  );
  const request = { agentId, action, resource: id };
  return (
    <div className="detail-section">
      {platformOnly ? (
        <LiveExplanation load={load} request={request} note="Policy administration is decided by the platform rules alone." />
      ) : ev.policyVersion ? (
        <LiveExplanation load={load} request={request} note={`Explained against v${ev.policyVersion} at the time of the request${type === "Key" ? ", using the key's current tags" : ""}.`} />
      ) : (
        <ExplanationView explanation={{ decision: "DENY", kind: "noPolicy", determiningPolicies: [] }} request={request} />
      )}
    </div>
  );
}

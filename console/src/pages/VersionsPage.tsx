import { useEffect, useState } from "react";
import { api } from "../api.ts";
import { useDraft } from "../draft.tsx";
import { go } from "../route.ts";
import type { ActivateResult, CellChange, Version, VersionInfo } from "../types.ts";
import { DecisionBadge, PolicyChips } from "../components/Badges.tsx";
import { LineDiff } from "../components/LineDiff.tsx";
import { formatTime } from "../format.ts";

/** Saved versions: inspect, compare, activate (gated by tests), roll back. */
export function VersionsPage({ onActivated }: { onActivated: () => void }) {
  const draft = useDraft();
  const [versions, setVersions] = useState<VersionInfo[] | null>(null);
  const [selected, setSelected] = useState<Version | null>(null);
  const [active, setActive] = useState<Version | null>(null);
  const [changes, setChanges] = useState<CellChange[] | null>(null);
  const [activation, setActivation] = useState<{ version: number; result: ActivateResult } | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [refresh, setRefresh] = useState(0);

  useEffect(() => {
    api.versions().then((r) => setVersions(r.versions)).catch((e: Error) => setError(e.message));
    api.active().then((a) => setActive(a.version ?? null)).catch(() => setActive(null));
  }, [refresh]);

  async function open(v: number) {
    try {
      const r = await api.version(v);
      setSelected(r.version);
      setActivation(null);
      setChanges((await api.diff(undefined, { version: v })).changes);
    } catch (e) {
      setError((e as Error).message);
    }
  }

  async function activate(v: number, force = false) {
    try {
      const result = await api.activate(v, force);
      setActivation({ version: v, result });
      if (result.activated) {
        setRefresh((x) => x + 1);
        onActivated();
      }
    } catch (e) {
      setError((e as Error).message);
    }
  }

  return (
    <div className={selected ? "split wide-detail" : undefined}>
      <section className="panel">
        <header className="panel-head">
          <h2>Policy versions</h2>
          <span className="muted small">versions are immutable; activation moves the pointer, rollback re-activates an older one</span>
        </header>
        {error && <div className="banner banner-error inline-banner">{error}</div>}
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Version</th>
                <th>Created</th>
                <th>Author</th>
                <th>Message</th>
                <th>Status</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {(versions ?? []).map((v) => (
                <tr key={v.version} className={selected?.version === v.version ? "selected" : undefined} onClick={() => void open(v.version)} tabIndex={0} onKeyDown={(e) => e.key === "Enter" && void open(v.version)}>
                  <td className="mono">v{v.version}</td>
                  <td className="mono muted" title={v.createdAt}>
                    {formatTime(v.createdAt)}
                  </td>
                  <td className="muted">{v.author}</td>
                  <td>{v.message || <span className="muted">—</span>}</td>
                  <td>{v.active ? <span className="badge decision decision-allow">ACTIVE</span> : <span className="muted">saved</span>}</td>
                  <td>
                    {!v.active && (
                      <button
                        type="button"
                        className="button small"
                        onClick={(e) => {
                          e.stopPropagation();
                          void activate(v.version);
                        }}
                      >
                        {active && v.version < active.version ? "Roll back to this" : "Activate"}
                      </button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          {versions && versions.length === 0 && <p className="empty">No versions yet. Save one from the Policies page or run make 4orbit-seed.</p>}
        </div>
        {activation && <ActivationReport activation={activation} onForce={() => void activate(activation.version, true)} />}
      </section>

      {selected && (
        <aside className="panel detail">
          <header className="panel-head">
            <h2>Version {selected.version}</h2>
            <button type="button" className="icon-button" aria-label="Close" onClick={() => setSelected(null)}>
              ×
            </button>
          </header>
          <div className="panel-body stack">
            <p className="muted small">
              {selected.message || "no message"} · {selected.author} · {selected.createdAt}
            </p>
            <div className="row">
              <button
                type="button"
                className="button"
                onClick={() => {
                  draft.load({ policies: selected.policies, entities: selected.entities }, selected.version);
                  go("policies");
                }}
              >
                Open in editor
              </button>
            </div>
            <h3>Decision changes vs active{active ? ` (v${active.version})` : ""}</h3>
            {changes && changes.length === 0 && <p className="muted small">None for registered agents, keys and KMS actions.</p>}
            {changes && changes.length > 0 && (
              <ul className="changes">
                {changes.map((c, i) => (
                  <li key={i}>
                    <span className="mono">{c.principal}</span> · <span className="mono">{c.action}</span> · <span className="mono">{c.resource}</span>: <DecisionBadge decision={c.before} /> → <DecisionBadge decision={c.after} />
                  </li>
                ))}
              </ul>
            )}
            <h3>Policy text vs active</h3>
            <LineDiff before={active?.policies ?? ""} after={selected.policies} />
          </div>
        </aside>
      )}
    </div>
  );
}

function ActivationReport({ activation, onForce }: { activation: { version: number; result: ActivateResult }; onForce: () => void }) {
  const { result } = activation;
  const [confirming, setConfirming] = useState(false);
  if (result.activated) {
    return (
      <div className="banner banner-ok inline-banner" role="status">
        Version {activation.version} is active{result.forced ? " (forced past failing tests)" : ""}: {result.tests.passed}/{result.tests.total} tests passed. The KMS plugin picks it up within its cache TTL (5 s by default).
      </div>
    );
  }
  const failures = result.tests.results.filter((r) => !r.pass);
  return (
    <div className="activation-failed" role="alert">
      <p>
        <strong>Not activated:</strong> {failures.length} of {result.tests.total} test cases fail against version {activation.version}. The previous version stays active.
      </p>
      <ul className="changes">
        {failures.slice(0, 20).map((f) => (
          <li key={f.name}>
            {f.name}: expected <DecisionBadge decision={f.expect} /> got <DecisionBadge decision={f.actual} /> <PolicyChips ids={f.determiningPolicies} />
          </li>
        ))}
      </ul>
      {!confirming ? (
        <button type="button" className="button danger" onClick={() => setConfirming(true)}>
          Activate anyway…
        </button>
      ) : (
        <div className="row">
          <span>Enforce a version that breaks your own expectations?</span>
          <button type="button" className="button danger" onClick={onForce}>
            Yes, force activate
          </button>
          <button type="button" className="button" onClick={() => setConfirming(false)}>
            Cancel
          </button>
        </div>
      )}
    </div>
  );
}

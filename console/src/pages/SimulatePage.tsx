import { useEffect, useMemo, useState } from "react";
import { api } from "../api.ts";
import { entityIds, useDraft } from "../draft.tsx";
import type { SimResult, SimulateResult, TestCase } from "../types.ts";
import { DecisionBadge, PolicyChips, SimTimeBadge } from "../components/Badges.tsx";
import { SourcePicker, TimeTravel, toEpoch, toSource, type SourceChoice } from "../components/SourcePicker.tsx";
import { useKeys, useSchema, useVersions } from "./shared.ts";

interface HistoryItem {
  result: SimResult;
  source: string;
  at: number;
  simulatedTime: boolean;
}

export function SimulatePage() {
  const draft = useDraft();
  const schema = useSchema();
  const keys = useKeys();
  const versions = useVersions();
  const [choice, setChoice] = useState<SourceChoice>("draft");
  const [when, setWhen] = useState("");
  const [agentId, setAgentId] = useState("developer-agent");
  const [action, setAction] = useState("kms.Encrypt");
  const [resourceId, setResourceId] = useState("dev-key");
  const [tags, setTags] = useState("");
  const [last, setLast] = useState<SimulateResult | null>(null);
  const [history, setHistory] = useState<HistoryItem[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [saved, setSaved] = useState<string | null>(null);

  // Replay from Activity or a matrix cell.
  useEffect(() => {
    const p = draft.pendingSim;
    if (!p) return;
    setAgentId(p.agentId ?? "");
    setAction(p.action);
    setResourceId(p.resource.id);
    setTags("");
    draft.setPendingSim(null);
  }, [draft.pendingSim]);

  const resourceType = schema?.actions.find((a) => a.name === action)?.resourceType ?? "Key";
  const agents = entityIds(draft.entities, "Agent");
  const groups = useMemo(() => {
    const g = new Map<string, string[]>();
    for (const a of schema?.actions ?? []) g.set(a.group, [...(g.get(a.group) ?? []), a.name]);
    return [...g.entries()];
  }, [schema]);

  // Tags default to the KMS key's tags; an explicit "k=v, k2=v2" overrides.
  const effectiveTags = (): Record<string, string> | undefined => {
    if (resourceType !== "Key") return undefined;
    if (tags.trim()) return Object.fromEntries(tags.split(",").map((kv) => kv.split("=").map((s) => s.trim())).filter(([k]) => k) as [string, string][]);
    const k = keys.data?.find((x) => x.alias === resourceId);
    return k ? Object.fromEntries(k.tags.map((t) => [t.key, t.value])) : undefined;
  };

  async function run() {
    setError(null);
    setSaved(null);
    try {
      const key = keys.data?.find((x) => x.alias === resourceId);
      const r = await api.simulate(
        [
          {
            agentId: agentId || undefined,
            action,
            resource: { type: resourceType, id: resourceId, tags: effectiveTags(), ...(key && resourceType === "Key" && { attrs: { scheme: key.scheme, keySpec: key.keySpec, keyUsage: key.keyUsage } }) },
          },
        ],
        toSource(choice, draft),
        toEpoch(when),
      );
      setLast(r);
      setHistory((h) => [{ result: r.results[0], source: r.source, at: r.at, simulatedTime: r.simulatedTime }, ...h].slice(0, 15));
    } catch (e) {
      setError((e as Error).message);
    }
  }

  async function saveAsTest() {
    if (!last) return;
    const res = last.results[0];
    try {
      const { tests } = await api.tests();
      const tc: TestCase = {
        name: `${res.request.agentId || "(account)"} ${res.request.action} ${res.request.resource.id}${last.simulatedTime ? ` @${last.at}` : ""}`,
        agentId: res.request.agentId,
        action: res.request.action,
        resource: { type: res.request.resource.type, id: res.request.resource.id, ...(res.request.resource.tags && { tags: res.request.resource.tags }) },
        ...(last.simulatedTime && { at: last.at }),
        expect: res.decision,
      };
      await api.putTests([...tests, tc]);
      setSaved(`Saved "${tc.name}" expecting ${tc.expect}. Activation now requires it to keep passing.`);
    } catch (e) {
      setError((e as Error).message);
    }
  }

  const result = last?.results[0];

  return (
    <div className="simulate-page">
      <section className="panel">
        <header className="panel-head">
          <h2>Ask Cedar</h2>
          <span className="muted small">Nothing here calls the KMS.</span>
        </header>
        <form
          className="panel-body sim-form"
          onSubmit={(e) => {
            e.preventDefault();
            void run();
          }}
        >
          <label className="field">
            <span>Principal (agent id; empty = account)</span>
            <input list="sim-agents" value={agentId} onChange={(e) => setAgentId(e.target.value.trim())} placeholder="(account)" />
            <datalist id="sim-agents">
              {agents.map((a) => (
                <option key={a} value={a} />
              ))}
            </datalist>
          </label>
          <label className="field">
            <span>Action</span>
            <select value={action} onChange={(e) => setAction(e.target.value)}>
              {groups.map(([group, names]) => (
                <optgroup key={group} label={group}>
                  {names.map((n) => (
                    <option key={n} value={n}>
                      {n}
                    </option>
                  ))}
                </optgroup>
              ))}
            </select>
          </label>
          <label className="field">
            <span>Resource ({resourceType})</span>
            <input list="sim-keys" value={resourceId} onChange={(e) => setResourceId(e.target.value.trim())} />
            <datalist id="sim-keys">
              {(keys.data ?? []).map((k) => (
                <option key={k.alias} value={k.alias} />
              ))}
            </datalist>
          </label>
          {resourceType === "Key" && (
            <label className="field">
              <span>Key tags override (k=v, …)</span>
              <input value={tags} onChange={(e) => setTags(e.target.value)} placeholder={tagHint(keys.data?.find((k) => k.alias === resourceId)?.tags)} />
            </label>
          )}
          <SourcePicker value={choice} onChange={setChoice} versions={versions} />
          <TimeTravel value={when} onChange={setWhen} />
          <div className="row">
            <button type="submit" className="button primary" disabled={!action || !resourceId}>
              Evaluate
            </button>
          </div>
        </form>
      </section>

      {error && <div className="banner banner-error inline-banner">{error}</div>}

      {result && last && (
        <section className="panel sim-result" aria-live="polite">
          <header className="panel-head">
            <h2>Result</h2>
            <span className="muted small">source: {last.source}</span>
          </header>
          <div className="panel-body stack">
            <div className="row">
              <span className="big-decision">
                <DecisionBadge decision={result.decision} />
              </span>
              {last.simulatedTime && <SimTimeBadge at={last.at} />}
              {result.errored && <span className="badge result result-error">EVALUATION ERROR → DENY</span>}
            </div>
            <div>
              <span className="muted small">Determined by </span>
              <PolicyChips ids={result.determiningPolicies} />
            </div>
            {result.diagnostics && (
              <ul className="problems">
                {result.diagnostics.map((d, i) => (
                  <li key={i} className="problem problem-error">
                    {d}
                  </li>
                ))}
              </ul>
            )}
            <div className="row">
              <button type="button" className="button" onClick={() => void saveAsTest()}>
                Save as test case
              </button>
              {saved && <span className="muted small">{saved}</span>}
            </div>
          </div>
        </section>
      )}

      {history.length > 1 && (
        <section className="panel">
          <header className="panel-head">
            <h2>Recent</h2>
          </header>
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Principal</th>
                  <th>Action</th>
                  <th>Resource</th>
                  <th>Source</th>
                  <th>Time</th>
                  <th>Decision</th>
                  <th>Policies</th>
                </tr>
              </thead>
              <tbody>
                {history.map((h, i) => (
                  <tr key={i}>
                    <td className="mono">{h.result.request.agentId || "(account)"}</td>
                    <td className="mono">{h.result.request.action}</td>
                    <td className="mono">{h.result.request.resource.id}</td>
                    <td className="muted">{h.source}</td>
                    <td className="mono muted">{h.simulatedTime ? new Date(h.at * 1000).toISOString() : "now"}</td>
                    <td>
                      <DecisionBadge decision={h.result.decision} />
                    </td>
                    <td>
                      <PolicyChips ids={h.result.determiningPolicies} />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>
      )}
    </div>
  );
}

function tagHint(tags?: { key: string; value: string }[]): string {
  if (!tags || tags.length === 0) return "none (key has no tags)";
  return `from KMS: ${tags.map((t) => `${t.key}=${t.value}`).join(", ")}`;
}

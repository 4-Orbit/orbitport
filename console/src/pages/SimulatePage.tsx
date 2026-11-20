import { Intro, Term } from "../components/Help.tsx";
import { useEffect, useMemo, useState } from "react";
import { api } from "../api.ts";
import { useDraft } from "../draft.tsx";
import type { SimResult, SimulateResult, TestCase } from "../types.ts";
import { DecisionBadge, PolicyChips, SimTimeBadge } from "../components/Badges.tsx";
import { ExplanationView } from "../components/Explanation.tsx";
import { RunForReal } from "../components/RunForReal.tsx";
import { SourcePicker, TimeTravel, toEpoch, toSource, type SourceChoice } from "../components/SourcePicker.tsx";
import { EntityPicker } from "../components/EntityPicker.tsx";
import { actionGroups, defaultResource, resourceField, resourceForAction, resourceProblem, resourceTypeOf } from "../resource-fields.ts";
import { useKeys, useRepositories, useSchema, useSourceAgents, useVersions } from "./shared.ts";

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
  const repositories = useRepositories();
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

  const resourceType = resourceTypeOf(action, schema?.actions);
  const field = resourceField(resourceType);
  const agents = useSourceAgents(choice, draft);
  const keyAliases = useMemo(() => (keys.data ?? []).map((k) => k.alias), [keys.data]);
  const groups = useMemo(() => actionGroups(schema?.actions ?? []), [schema]);
  const problem = resourceProblem(resourceType, resourceId);

  // An empty resource is filled once its list arrives (the first visit, or a
  // switch to GitHub before the repositories loaded).
  useEffect(() => {
    if (!resourceId) setResourceId(defaultResource(resourceType, { keys: keyAliases, repositories: repositories.data ?? [] }));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [keyAliases, repositories.data]);

  // A new resource type starts on a resource of that type, so a key alias is
  // never sent as a repository (or the reverse).
  const changeAction = (next: string) => {
    setResourceId(resourceForAction(resourceType, resourceTypeOf(next, schema?.actions), resourceId, { keys: keyAliases, repositories: repositories.data ?? [] }));
    setTags("");
    setAction(next);
  };

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
        true,
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
      <Intro page="simulate" title="Simulate: ask “would this be allowed?”">
        Try any agent, action and key against your <Term k="draft" />, the active version or any saved version, optionally at a <Term k="simulatedTime">simulated time</Term>. Evaluating never touches the KMS; <strong>Run it for real</strong> then sends the same request to the KMS as that agent, to compare. Save useful answers as <Term k="test">tests</Term>.
      </Intro>
      <section className="panel">
        <header className="panel-head">
          <h2>Ask Cedar</h2>
          <span className="muted small">Evaluate never calls the KMS.</span>
        </header>
        <form
          className="panel-body sim-form"
          onSubmit={(e) => {
            e.preventDefault();
            void run();
          }}
        >
          <EntityPicker
            label="Principal"
            value={agentId}
            onChange={setAgentId}
            options={agents.data ?? []}
            loading={agents.data === null && !agents.error}
            error={agents.error}
            emptyLabel="(account)"
            allowOther
            noun="an agent"
            placeholder="agent id (not registered yet)"
            note={agentId && agents.data && !agents.data.includes(agentId) ? `Not registered in ${choice === "draft" ? "the draft" : choice === "active" ? "the active version" : `version ${choice.slice(1)}`}.` : undefined}
          />
          <label className="field">
            <span>Action</span>
            <select value={action} onChange={(e) => changeAction(e.target.value)}>
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
          {resourceType === "Repository" ? (
            <EntityPicker
              key="repository"
              label={field.label}
              value={resourceId}
              onChange={setResourceId}
              options={repositories.data ?? []}
              loading={repositories.data === null && !repositories.error}
              error={repositories.error}
              allowOther
              noun="a repository"
              placeholder={field.placeholder}
              problem={problem}
              note={resourceId && repositories.data && !repositories.data.includes(resourceId) ? "Not configured for issue creation; a rule can still name it." : undefined}
            />
          ) : (
            <EntityPicker
              key="key"
              label={field.label}
              value={resourceId}
              onChange={setResourceId}
              options={keyAliases}
              loading={keys.data === null}
              error={keys.error}
              allowOther
              noun="a key"
              placeholder={field.placeholder}
              problem={problem}
              note={keys.more ? `Showing the first ${keyAliases.length} keys; use Other… for any other alias.` : undefined}
            />
          )}
          {resourceType === "Key" && (
            <label className="field">
              <span>Key tags override (k=v, …)</span>
              <input value={tags} onChange={(e) => setTags(e.target.value)} placeholder={tagHint(keys.data?.find((k) => k.alias === resourceId)?.tags)} />
            </label>
          )}
          <SourcePicker value={choice} onChange={setChoice} versions={versions} />
          <TimeTravel value={when} onChange={setWhen} />
          <div className="row">
            <button type="submit" className="button primary" disabled={!action || problem !== null}>
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
            {result.explanation && (
              <ExplanationView explanation={result.explanation} request={{ agentId: result.request.agentId, action: result.request.action, resource: result.request.resource.id, resourceType: result.request.resource.type }} />
            )}
            {result.diagnostics && (
              <ul className="problems">
                {result.diagnostics.map((d, i) => (
                  <li key={i} className="problem problem-error">
                    {d}
                  </li>
                ))}
              </ul>
            )}
            <RunForReal
              key={`${last.at}|${JSON.stringify(result.request)}|${last.source}|${history.length}`}
              request={result.request}
              simulated={{ decision: result.decision, source: last.source, simulatedTime: last.simulatedTime }}
            />
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

import { useEffect, useState } from "react";
import { api } from "../api.ts";
import { entityIds, rolesOf, useDraft } from "../draft.tsx";
import type { CellChange, EntityJson, ValidateResult } from "../types.ts";
import { appendSnippet, CedarEditor } from "../components/CedarEditor.tsx";
import { DecisionBadge, PolicyChips } from "../components/Badges.tsx";
import { useSchema } from "./shared.ts";

const ID_RE = /^[a-z0-9][a-z0-9_-]{0,63}$/;

const SNIPPETS: { label: string; text: string }[] = [
  {
    label: "Role may encrypt with a key",
    text: `@id("role-encrypt-key")
permit (
  principal in Role::"developer",
  action == Action::"kms.Encrypt",
  resource == Key::"dev-key"
);`,
  },
  {
    label: "Role may use (encrypt/decrypt/sign) any key",
    text: `@id("role-use-any-key")
permit (principal in Role::"developer", action in Action::"use", resource);`,
  },
  {
    label: "Time-limited grant (expires at a Unix time)",
    text: `@id("temporary-grant")
permit (principal in Role::"developer", action == Action::"kms.Encrypt", resource == Key::"demo-key")
when { context.currentTime < 1800000000 };`,
  },
  {
    label: "Tag-based grant (keys tagged env=dev)",
    text: `@id("use-dev-tagged-keys")
permit (principal in Role::"developer", action in Action::"use", resource)
when { resource.hasTag("env") && resource.getTag("env") == "dev" };`,
  },
  {
    label: "Forbid prod for a role (overrides any permit)",
    text: `@id("no-prod-for-developers")
forbid (principal in Role::"developer", action, resource)
when { resource.hasTag("env") && resource.getTag("env") == "prod" };`,
  },
  {
    label: "Single agent may rotate a key",
    text: `@id("agent-rotate-key")
permit (principal == Agent::"security-agent", action == Action::"kms.RotateKey", resource == Key::"prod-key");`,
  },
];

export function PoliciesPage() {
  const draft = useDraft();
  const schema = useSchema();
  const [validation, setValidation] = useState<ValidateResult | null>(null);
  const [status, setStatus] = useState<{ tone: "ok" | "error"; text: string } | null>(null);
  const [message, setMessage] = useState("");
  const [changes, setChanges] = useState<CellChange[] | null>(null);
  const [showPlatform, setShowPlatform] = useState(false);
  const [entitiesJson, setEntitiesJson] = useState(false);

  // First visit with an empty draft: start from the active version.
  useEffect(() => {
    if (draft.policies === "" && draft.entities.length === 0 && draft.base === null) void loadActive();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // Debounced live validation with the enforcement engine.
  useEffect(() => {
    const t = setTimeout(() => {
      api
        .validate(draft.bundle)
        .then(setValidation)
        .catch((e: Error) => setValidation({ ok: false, problems: [{ severity: "error", message: e.message }] }));
    }, 350);
    return () => clearTimeout(t);
  }, [draft.bundle]);

  async function loadActive() {
    try {
      const a = await api.active();
      if (a.exists && a.version) {
        draft.load({ policies: a.version.policies, entities: a.version.entities }, a.version.version);
        setStatus({ tone: "ok", text: `Loaded active version ${a.version.version}.` });
      } else {
        draft.load({ policies: "", entities: [] }, null);
        setStatus({ tone: "ok", text: "No active version yet: start writing, or load the 4Orbit template." });
      }
      setChanges(null);
    } catch (e) {
      setStatus({ tone: "error", text: (e as Error).message });
    }
  }

  async function loadTemplate() {
    try {
      const r = await api.loadTemplate();
      const v = await api.version(r.version);
      draft.load({ policies: v.version.policies, entities: v.version.entities }, r.version);
      setStatus({ tone: "ok", text: `Saved the 4Orbit template as version ${r.version} with its ${r.tests}-case test suite. Activate it on the Versions page.` });
    } catch (e) {
      setStatus({ tone: "error", text: (e as Error).message });
    }
  }

  async function save() {
    try {
      const r = await api.saveDraft(draft.bundle, message.trim());
      draft.load(draft.bundle, r.version);
      setMessage("");
      setStatus({ tone: "ok", text: `Saved as version ${r.version}. It is not enforced until you activate it on the Versions page.` });
    } catch (e) {
      setStatus({ tone: "error", text: (e as Error).message });
    }
  }

  async function diffAgainstActive() {
    try {
      const r = await api.diff(undefined, { draft: draft.bundle });
      setChanges(r.changes);
    } catch (e) {
      setStatus({ tone: "error", text: (e as Error).message });
    }
  }

  const problems = validation?.problems ?? [];
  const errors = problems.filter((p) => p.severity === "error");

  return (
    <div className="policies-page">
      <section className="panel toolbar">
        <button type="button" className="button" onClick={() => void loadActive()}>
          Load active
        </button>
        <button type="button" className="button" onClick={() => void loadTemplate()}>
          Load 4Orbit template
        </button>
        <label className="field inline">
          <span>Insert snippet</span>
          <select
            value=""
            onChange={(e) => {
              const s = SNIPPETS[Number(e.target.value)];
              if (s) draft.setPolicies(appendSnippet(draft.policies, s.text));
            }}
          >
            <option value="">choose…</option>
            {SNIPPETS.map((s, i) => (
              <option key={s.label} value={i}>
                {s.label}
              </option>
            ))}
          </select>
        </label>
        <span className="muted small">
          {draft.base ? `based on v${draft.base}` : "new draft"}
          {draft.dirty ? " · edited" : ""}
        </span>
      </section>

      {status && <div className={`banner inline-banner ${status.tone === "error" ? "banner-error" : "banner-ok"}`}>{status.text}</div>}

      <div className="editor-grid">
        <section className="panel">
          <header className="panel-head">
            <h2>Tenant policies</h2>
            <ValidityBadge validation={validation} />
          </header>
          <div className="panel-body">
            <CedarEditor label="Tenant Cedar policies" value={draft.policies} onChange={draft.setPolicies} problems={problems} minHeight="420px" />
            <Problems validation={validation} />
          </div>
        </section>

        <div className="side-stack">
          <section className="panel">
            <header className="panel-head">
              <h2>Agents & roles</h2>
              <button type="button" className="link-button" onClick={() => setEntitiesJson((v) => !v)}>
                {entitiesJson ? "table" : "JSON"}
              </button>
            </header>
            <div className="panel-body">
              {entitiesJson ? <EntitiesJson entities={draft.entities} onChange={draft.setEntities} /> : <EntitiesTable entities={draft.entities} onChange={draft.setEntities} />}
            </div>
          </section>

          <section className="panel">
            <header className="panel-head">
              <h2>Save & compare</h2>
            </header>
            <div className="panel-body stack">
              <label className="field">
                <span>Version message</span>
                <input value={message} maxLength={500} placeholder="what changed and why" onChange={(e) => setMessage(e.target.value)} />
              </label>
              <div className="row">
                <button type="button" className="button primary" disabled={errors.length > 0 || !validation?.ok} onClick={() => void save()}>
                  Save as new version
                </button>
                <button type="button" className="button" disabled={!validation?.ok} onClick={() => void diffAgainstActive()}>
                  What changes vs active?
                </button>
              </div>
              {changes && <ChangeList changes={changes} />}
            </div>
          </section>

          <section className="panel">
            <header className="panel-head">
              <h2>Platform policy</h2>
              <button type="button" className="link-button" onClick={() => setShowPlatform((v) => !v)}>
                {showPlatform ? "hide" : "show"}
              </button>
            </header>
            <div className="panel-body">
              <p className="muted small">Always evaluated with your policies and not editable: owner access for account credentials, a tenant fence, and no policy administration by agents.</p>
              {showPlatform && schema && <CedarEditor label="Platform policy (read-only)" value={schema.platformPolicies} readOnly minHeight="120px" />}
            </div>
          </section>
        </div>
      </div>
    </div>
  );
}

function ValidityBadge({ validation }: { validation: ValidateResult | null }) {
  if (!validation) return <span className="muted small">validating…</span>;
  const errors = validation.problems.filter((p) => p.severity === "error").length;
  return validation.ok ? <span className="badge decision decision-allow">VALID</span> : <span className="badge decision decision-deny">{errors} ERROR{errors === 1 ? "" : "S"}</span>;
}

function Problems({ validation }: { validation: ValidateResult | null }) {
  if (!validation) return null;
  if (validation.problems.length === 0) {
    const s = validation.summary;
    return (
      <p className="muted small problems-ok">
        Valid against the schema · {s?.policyIds?.length ?? 0} policies · {s?.agents?.length ?? 0} agents · {s?.roles?.length ?? 0} roles
        {s && (s.referencedKeys?.length ?? 0) > 0 && <> · keys named: {s.referencedKeys.join(", ")}</>}
      </p>
    );
  }
  return (
    <ul className="problems">
      {validation.problems.map((p, i) => (
        <li key={i} className={`problem problem-${p.severity}`}>
          <span className="mono">{p.line ? `L${p.line}${p.column ? `:${p.column}` : ""}` : "—"}</span>
          {p.policyId && <code>{p.policyId}</code>}
          <span>{p.message}</span>
        </li>
      ))}
    </ul>
  );
}

function ChangeList({ changes }: { changes: CellChange[] }) {
  if (changes.length === 0) return <p className="muted small">No decision changes for any registered agent, key and KMS action.</p>;
  return (
    <ul className="changes">
      {changes.map((c, i) => (
        <li key={i}>
          <span className="mono">{c.principal}</span> · <span className="mono">{c.action}</span> · <span className="mono">{c.resource}</span>: <DecisionBadge decision={c.before} /> → <DecisionBadge decision={c.after} />{" "}
          {c.after === "ALLOW" && <PolicyChips ids={c.afterPolicies} />}
        </li>
      ))}
    </ul>
  );
}

function EntitiesTable({ entities, onChange }: { entities: EntityJson[]; onChange: (e: EntityJson[]) => void }) {
  const roles = entityIds(entities, "Role");
  const agents = entityIds(entities, "Agent");
  const [newAgent, setNewAgent] = useState("");
  const [newRole, setNewRole] = useState("");

  const toggle = (agent: string, role: string) => {
    onChange(
      entities.map((e) => {
        if (e.uid.type !== "Agent" || e.uid.id !== agent) return e;
        const has = e.parents.some((p) => p.type === "Role" && p.id === role);
        return { ...e, parents: has ? e.parents.filter((p) => !(p.type === "Role" && p.id === role)) : [...e.parents, { type: "Role", id: role }] };
      }),
    );
  };
  const add = (type: "Agent" | "Role", id: string) => {
    if (!ID_RE.test(id) || entities.some((e) => e.uid.type === type && e.uid.id === id)) return;
    onChange([...entities, { uid: { type, id }, attrs: {}, parents: [] }]);
  };
  const remove = (type: "Agent" | "Role", id: string) => {
    onChange(
      entities
        .filter((e) => !(e.uid.type === type && e.uid.id === id))
        .map((e) => (type === "Role" ? { ...e, parents: e.parents.filter((p) => !(p.type === "Role" && p.id === id)) } : e)),
    );
  };

  return (
    <div className="entities">
      <div className="table-wrap">
      <table className="compact">
        <thead>
          <tr>
            <th>Agent</th>
            {roles.map((r) => (
              <th key={r}>
                {r}{" "}
                <button type="button" className="link-button" aria-label={`Remove role ${r}`} onClick={() => remove("Role", r)}>
                  ×
                </button>
              </th>
            ))}
            <th />
          </tr>
        </thead>
        <tbody>
          {agents.map((a) => {
            const mine = rolesOf(entities, a);
            return (
              <tr key={a}>
                <td className="mono">{a}</td>
                {roles.map((r) => (
                  <td key={r}>
                    <input type="checkbox" aria-label={`${a} in ${r}`} checked={mine.includes(r)} onChange={() => toggle(a, r)} />
                  </td>
                ))}
                <td>
                  <button type="button" className="link-button" aria-label={`Remove agent ${a}`} onClick={() => remove("Agent", a)}>
                    remove
                  </button>
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
      </div>
      {agents.length === 0 && <p className="muted small">No agents yet. Agents are denied everything until a policy grants them access.</p>}
      <div className="row">
        <input aria-label="New agent id" value={newAgent} placeholder="new-agent-id" onChange={(e) => setNewAgent(e.target.value.toLowerCase())} />
        <button type="button" className="button" disabled={!ID_RE.test(newAgent)} onClick={() => (add("Agent", newAgent), setNewAgent(""))}>
          Add agent
        </button>
        <input aria-label="New role id" value={newRole} placeholder="new-role" onChange={(e) => setNewRole(e.target.value.toLowerCase())} />
        <button type="button" className="button" disabled={!ID_RE.test(newRole)} onClick={() => (add("Role", newRole), setNewRole(""))}>
          Add role
        </button>
      </div>
      <p className="muted small">Ids: 1–64 of a-z, 0-9, - and _. Keys are not declared here; they come from the KMS.</p>
    </div>
  );
}

function EntitiesJson({ entities, onChange }: { entities: EntityJson[]; onChange: (e: EntityJson[]) => void }) {
  const [text, setText] = useState(() => JSON.stringify(entities, null, 2));
  const [error, setError] = useState<string | null>(null);
  useEffect(() => setText(JSON.stringify(entities, null, 2)), [entities]);
  return (
    <div className="stack">
      <textarea
        className="json-area mono"
        aria-label="Entities JSON"
        value={text}
        spellCheck={false}
        onChange={(e) => {
          setText(e.target.value);
          try {
            const parsed = JSON.parse(e.target.value) as EntityJson[];
            if (!Array.isArray(parsed)) throw new Error("expected an array");
            setError(null);
            onChange(parsed);
          } catch (err) {
            setError((err as Error).message);
          }
        }}
      />
      {error && <p className="test-error small">{error}</p>}
    </div>
  );
}

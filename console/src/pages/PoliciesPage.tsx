import { useEffect, useState } from "react";
import { RulesView } from "../components/RulesView.tsx";
import { ConfirmButton, ConfirmDialog, Toast, type ToastState } from "../components/Confirm.tsx";
import { removePolicies, rulesNamingAgent } from "../agent-removal.ts";
import { DraftStatus } from "../components/DraftStatus.tsx";
import { Intro, Term } from "../components/Help.tsx";
import { api } from "../api.ts";
import { entityIds, rolesOf, useDraft } from "../draft.tsx";
import type { CellChange, EntityJson, PolicyInfo, TestCase, ValidateResult } from "../types.ts";
import { appendSnippet, CedarEditor } from "../components/CedarEditor.tsx";
import { DecisionBadge, PolicyChips } from "../components/Badges.tsx";
import { useKeys, useSchema, useVersionState } from "./shared.ts";
import { withRole } from "../explain.ts";

type Mode = "rules" | "cedar";
const MODE_KEY = "orbitport-console-policy-mode";

function storedMode(): Mode {
  try {
    return localStorage.getItem(MODE_KEY) === "cedar" ? "cedar" : "rules";
  } catch {
    return "rules";
  }
}

const typingTarget = (t: EventTarget | null) => t instanceof HTMLElement && (t.closest(".cm-editor") !== null || ["INPUT", "TEXTAREA", "SELECT"].includes(t.tagName));

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
  const keys = useKeys();
  const [checked, setChecked] = useState<{ text: string; result: ValidateResult } | null>(null);
  const validation = checked?.result ?? null;
  const [mode, setModeState] = useState<Mode>(storedMode);
  const [toast, setToast] = useState<ToastState | null>(null);
  const setMode = (m: Mode) => {
    setModeState(m);
    try {
      localStorage.setItem(MODE_KEY, m);
    } catch {
      // per-viewer preference only
    }
  };
  // Plain status messages describe the moment they were shown, so any further
  // draft edit clears them; messages asking a question stay until answered.
  const clearStaleStatus = () => setStatus((s) => (s?.actions?.length ? s : null));
  const announce = (text: string) => {
    clearStaleStatus();
    setToast({ text, undo: true });
  };
  const [status, setStatus] = useState<Status | null>(null);
  const [versionsTick, setVersionsTick] = useState(0);
  const versionState = useVersionState(versionsTick);
  const [decisionChanges, setDecisionChanges] = useState<number | null>(null);
  const [message, setMessage] = useState("");
  const [changes, setChanges] = useState<CellChange[] | null>(null);
  const [showPlatform, setShowPlatform] = useState(false);
  const [entitiesJson, setEntitiesJson] = useState(false);

  // First visit with an empty draft: start from the active version.
  // `started` turns true once the draft is the one to edit, so a queued
  // "Grant this…" never applies to a draft that is about to be replaced.
  const [started, setStarted] = useState(false);
  useEffect(() => {
    if (draft.policies === "" && draft.entities.length === 0 && draft.base === null) void loadActive().then(() => setStarted(true));
    else setStarted(true);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // "Grant this…" from an explanation: show the rules, then either add the
  // agent to a role here or let RulesView open the rule form.
  const grant = draft.pendingGrant;
  useEffect(() => {
    if (!grant) return;
    if (mode !== "rules") setMode("rules");
    if (!started || grant.kind !== "addRole") return;
    const next = withRole(draft.entities, grant.agentId, grant.role);
    if (next === draft.entities) {
      announce(`${grant.agentId} already has the ${grant.role} role in your draft.`);
    } else {
      draft.setEntities(next, `add ${grant.agentId} to role ${grant.role}`);
      announce(`Added ${grant.agentId} to the ${grant.role} role in your draft. Save and activate it to enforce the change.`);
    }
    draft.setPendingGrant(null);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [grant, started]);

  // Debounced live validation with the enforcement engine. The result keeps
  // the exact text it describes, because rule cards edit by text position.
  useEffect(() => {
    const text = draft.policies;
    const t = setTimeout(() => {
      api
        .validate(draft.bundle)
        .then((result) => setChecked({ text, result }))
        .catch((e: Error) => setChecked({ text, result: { ok: false, problems: [{ severity: "error", message: e.message }] } }));
    }, 350);
    return () => clearTimeout(t);
  }, [draft.bundle, draft.policies]);

  // How many decisions the draft changes vs the active version (status strip).
  useEffect(() => {
    if (!validation?.ok) return;
    setDecisionChanges(null);
    let cancelled = false;
    const t = setTimeout(() => {
      api
        .diff(undefined, { draft: draft.bundle })
        .then((r) => !cancelled && setDecisionChanges(r.changes.length))
        .catch(() => !cancelled && setDecisionChanges(null));
    }, 500);
    return () => {
      cancelled = true;
      clearTimeout(t);
    };
  }, [validation, draft.bundle, versionState.active]);

  // Undo / redo from the keyboard, except where the field has its own
  // (the Cedar editor keeps per-keystroke undo).
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (!(e.metaKey || e.ctrlKey) || e.key.toLowerCase() !== "z" || typingTarget(e.target)) return;
      e.preventDefault();
      if (e.shiftKey) draft.redo();
      else draft.undo();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [draft]);

  async function loadActive() {
    try {
      const a = await api.active();
      if (a.exists && a.version) {
        draft.load({ policies: a.version.policies, entities: a.version.entities }, a.version.version, `start from active v${a.version.version}`);
        setStatus({ tone: "ok", text: `Your draft now matches the active version v${a.version.version}. Nothing was saved.` });
      } else {
        draft.load({ policies: "", entities: [] }, null, "start an empty draft");
        setStatus({ tone: "ok", text: "No version is active yet. Start writing rules, or start from the 4Orbit template." });
      }
      setChanges(null);
    } catch (e) {
      setStatus({ tone: "error", text: (e as Error).message });
    }
  }

  /** Loads the template into the draft only. Its tests are offered, never written silently. */
  async function loadTemplate() {
    try {
      const [t, current] = await Promise.all([api.template(), api.tests()]);
      draft.load({ policies: t.policies, entities: t.entities }, null, "start from the 4Orbit template");
      setChanges(null);
      offerTemplateTests(t.tests, current.tests);
    } catch (e) {
      setStatus({ tone: "error", text: (e as Error).message });
    }
  }

  function offerTemplateTests(templateTests: TestCase[], current: TestCase[]) {
    const same = JSON.stringify(templateTests) === JSON.stringify(current);
    setStatus({
      tone: "ok",
      text: same
        ? "Your draft now contains the 4Orbit template (not saved yet). Your test suite already matches the template's."
        : `Your draft now contains the 4Orbit template (not saved yet). The template also comes with ${templateTests.length} tests (the 4Orbit permission matrix); you have ${current.length}.`,
      actions: same
        ? []
        : [
            {
              label: current.length ? `Replace my ${current.length} tests with the template's` : `Install the template's ${templateTests.length} tests`,
              danger: current.length > 0,
              run: async () => {
                await api.putTests(templateTests);
                setStatus({ tone: "ok", text: `Test suite replaced with the template's ${templateTests.length} tests. (Tests are saved on the server immediately; Undo in the editor doesn't affect them.)` });
              },
            },
            { label: "Keep my tests", run: async () => setStatus(null) },
          ],
    });
  }

  async function save(allowDuplicate = false) {
    try {
      const r = await api.saveDraft(draft.bundle, message.trim(), allowDuplicate);
      draft.markSaved(r.version);
      setVersionsTick((x) => x + 1);
      if (r.duplicate) {
        setStatus({
          tone: "ok",
          text: `Nothing new was saved: your draft is identical to version ${r.version}.`,
          actions: [
            { label: `Go to v${r.version} on Versions`, run: async () => void (window.location.hash = "#/versions") },
            { label: "Save a separate copy anyway", run: async () => save(true) },
          ],
        });
        return;
      }
      setMessage("");
      setStatus({ tone: "ok", text: `Saved as version ${r.version}. It isn't enforced until you activate it on the Versions page.` });
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
      <Intro page="policies" title="Policies: edit your draft">
        Changes here go into your <Term k="draft" />, which only you see and which isn't enforced. <strong>Save as new version</strong> keeps a permanent copy;
        nothing changes for agents until you <Term k="activate">activate</Term> a version on the Versions page. Write <Term k="rule">rules</Term> as plain-language forms or as
        Cedar code; both edit the same draft.
      </Intro>
      <section className="panel toolbar">
        <div className="segmented mode-switch" role="group" aria-label="Editor">
          <button type="button" aria-pressed={mode === "rules"} onClick={() => setMode("rules")}>
            Plain language
          </button>
          <button type="button" aria-pressed={mode === "cedar"} onClick={() => setMode("cedar")}>
            Cedar code
          </button>
        </div>
        <span className="row">
          <button type="button" className="button" disabled={!draft.undoLabel} title={draft.undoLabel ? `Undo: ${draft.undoLabel} (⌘Z)` : "Nothing to undo"} onClick={draft.undo}>
            ↶ Undo
          </button>
          <button type="button" className="button" disabled={!draft.redoLabel} title={draft.redoLabel ? `Redo: ${draft.redoLabel} (⇧⌘Z)` : "Nothing to redo"} onClick={draft.redo}>
            ↷ Redo
          </button>
        </span>
        <ReplaceDraftButton label="Start from active" dirty={draft.dirty} onRun={() => void loadActive()} />
        <ReplaceDraftButton label="Start from 4Orbit template" dirty={draft.dirty} onRun={() => void loadTemplate()} />
        {mode === "cedar" && (
        <label className="field inline">
          <span>Insert snippet</span>
          <select
            value=""
            onChange={(e) => {
              const s = SNIPPETS[Number(e.target.value)];
              if (s) {
                draft.commit({ policies: appendSnippet(draft.policies, s.text) }, `insert snippet “${s.label}”`);
                clearStaleStatus();
              }
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
        )}
      </section>

      <DraftStatus
        dirty={draft.dirty}
        base={draft.base}
        active={versionState.active}
        known={versionState.loaded}
        valid={validation?.ok ?? true}
        empty={draft.policies.trim() === "" && draft.entities.length === 0}
        changes={decisionChanges}
      />
      {status && <StatusBanner status={status} onClose={() => setStatus(null)} />}
      <Toast toast={toast} onUndo={draft.undo} onClose={() => setToast(null)} />

      <div className="editor-grid">
        <section className="panel">
          <header className="panel-head">
            <h2>{mode === "rules" ? "Rules" : "Tenant policies (Cedar)"}</h2>
            <ValidityBadge validation={validation} />
          </header>
          <div className="panel-body">
            {mode === "rules" ? (
              <RulesView
                validation={validation}
                validatedText={checked?.text ?? ""}
                keys={keys.data ?? []}
                moreKeys={keys.more}
                onEditCedar={() => setMode("cedar")}
                onChanged={announce}
                grant={started && grant?.kind !== "addRole" ? grant : null}
                onGrantHandled={(problem) => {
                  draft.setPendingGrant(null);
                  if (problem) setStatus({ tone: "error", text: problem });
                }}
              />
            ) : (
              <>
                <CedarEditor
                  label="Tenant Cedar policies"
                  value={draft.policies}
                  onChange={(text) => {
                    draft.setPolicies(text);
                    clearStaleStatus();
                  }}
                  problems={problems}
                  minHeight="420px"
                />
                <Problems validation={validation} />
              </>
            )}
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
              {entitiesJson ? (
                <EntitiesJson
                  entities={draft.entities}
                  onChange={(e) => {
                    draft.setEntities(e, "edit entities JSON");
                    clearStaleStatus();
                  }}
                />
              ) : (
                <EntitiesTable
                  entities={draft.entities}
                  policies={draft.policies}
                  checked={checked}
                  onChange={(e, label) => {
                    draft.setEntities(e, label);
                    clearStaleStatus();
                  }}
                  onDeleteAgent={(agentId, rules) => {
                    // One undo step: the agent and (optionally) its rules.
                    const entities = draft.entities.filter((e) => !(e.uid.type === "Agent" && e.uid.id === agentId));
                    const policies = rules.length && checked ? removePolicies(checked.text, rules) : draft.policies;
                    draft.commit({ entities, policies }, rules.length ? `delete agent ${agentId} and ${rules.length} rule${rules.length === 1 ? "" : "s"}` : `delete agent ${agentId}`);
                    clearStaleStatus();
                    announce(rules.length ? `Deleted agent ${agentId} and ${rules.length} rule${rules.length === 1 ? "" : "s"} for it.` : `Deleted agent ${agentId}.`);
                  }}
                  onRemoved={announce}
                />
              )}
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
                <button type="button" className="button primary" disabled={errors.length > 0 || !validation?.ok} onClick={() => void save()} title="Creates a permanent version. Doesn't change what's enforced.">
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

function EntitiesTable({ entities, policies, checked, onChange, onDeleteAgent, onRemoved }: {
  entities: EntityJson[];
  policies: string;
  /** The last validation and the text it describes. */
  checked: { text: string; result: ValidateResult } | null;
  onChange: (e: EntityJson[], label: string) => void;
  /** Delete an agent, and these of its rules, as one change. */
  onDeleteAgent: (agentId: string, rules: PolicyInfo[]) => void;
  onRemoved: (message: string) => void;
}) {
  const roles = entityIds(entities, "Role");
  const agents = entityIds(entities, "Agent");
  const [deleting, setDeleting] = useState<string | null>(null);
  const [newAgent, setNewAgent] = useState("");
  const [newRole, setNewRole] = useState("");

  const toggle = (agent: string, role: string) => {
    const has = rolesOf(entities, agent).includes(role);
    onChange(
      entities.map((e) => {
        if (e.uid.type !== "Agent" || e.uid.id !== agent) return e;
        const has = e.parents.some((p) => p.type === "Role" && p.id === role);
        return { ...e, parents: has ? e.parents.filter((p) => !(p.type === "Role" && p.id === role)) : [...e.parents, { type: "Role", id: role }] };
      }),
      `${has ? "remove" : "give"} ${agent} ${has ? "from" : "the"} ${role} role`,
    );
  };
  const add = (type: "Agent" | "Role", id: string) => {
    if (!ID_RE.test(id) || entities.some((e) => e.uid.type === type && e.uid.id === id)) return;
    onChange([...entities, { uid: { type, id }, attrs: {}, parents: [] }], `add ${type.toLowerCase()} ${id}`);
  };
  const remove = (type: "Agent" | "Role", id: string) => {
    onChange(
      entities
        .filter((e) => !(e.uid.type === type && e.uid.id === id))
        .map((e) => (type === "Role" ? { ...e, parents: e.parents.filter((p) => !(p.type === "Role" && p.id === id)) } : e)),
      `delete ${type.toLowerCase()} ${id}`,
    );
    onRemoved(`Deleted ${type.toLowerCase()} ${id}.`);
  };
  /** What removing an agent or role affects, in words. */
  const impact = (type: "Agent" | "Role", id: string) => {
    const rules = (policies.match(new RegExp(`${type}::"${id.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}"`, "g")) ?? []).length;
    const members = type === "Role" ? agents.filter((a) => rolesOf(entities, a).includes(id)) : [];
    const parts = [
      members.length ? `${members.join(", ")} will lose this role` : "",
      rules ? `${rules} rule${rules === 1 ? "" : "s"} name${rules === 1 ? "s" : ""} it and will match nobody` : "",
    ].filter(Boolean);
    return parts.length ? `${parts.join("; ")}.` : "Nothing uses it.";
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
                {r} <ConfirmButton label="×" ariaLabel={`Remove role ${r}`} confirmLabel={`Delete role ${r}`} impact={impact("Role", r)} onConfirm={() => remove("Role", r)} />
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
                  <button type="button" className="link-button" aria-label={`Remove agent ${a}`} onClick={() => setDeleting(a)}>
                    remove
                  </button>
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
      </div>
      {deleting !== null && (
        <DeleteAgentDialog
          agentId={deleting}
          checked={checked}
          policies={policies}
          onDelete={(rules) => {
            setDeleting(null);
            onDeleteAgent(deleting, rules);
          }}
          onCancel={() => setDeleting(null)}
        />
      )}
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

interface StatusAction {
  label: string;
  danger?: boolean;
  run: () => Promise<void>;
}

interface Status {
  tone: "ok" | "error";
  text: string;
  actions?: StatusAction[];
}

function StatusBanner({ status, onClose }: { status: Status; onClose: () => void }) {
  const [busy, setBusy] = useState(false);
  return (
    <div className={`banner inline-banner status-banner ${status.tone === "error" ? "banner-error" : "banner-ok"}`} role="status">
      <span>{status.text}</span>
      {status.actions?.map((a) => (
        <button
          key={a.label}
          type="button"
          className={`button small${a.danger ? " danger" : ""}`}
          disabled={busy}
          onClick={async () => {
            setBusy(true);
            try {
              await a.run();
            } finally {
              setBusy(false);
            }
          }}
        >
          {a.label}
        </button>
      ))}
      <button type="button" className="icon-button" aria-label="Dismiss" onClick={onClose}>
        ×
      </button>
    </div>
  );
}

/** Replaces the draft; asks first when there are unsaved edits (Undo still works). */
function ReplaceDraftButton({ label, dirty, onRun }: { label: string; dirty: boolean; onRun: () => void }) {
  if (!dirty) {
    return (
      <button type="button" className="button" onClick={onRun} title="Replaces your draft. Nothing is saved.">
        {label}
      </button>
    );
  }
  return (
    <ConfirmButton
      className="button"
      label={label}
      confirmLabel="Replace my draft"
      impact="Your unsaved edits will be replaced (Undo brings them back)."
      onConfirm={onRun}
    />
  );
}

/**
 * Confirms deleting an agent. Rules for it are listed and deleted with it by
 * default: left behind, they would apply again to any agent later registered
 * with the same id. Custom Cedar that mentions it is listed, not changed.
 */
function DeleteAgentDialog({ agentId, checked, policies, onDelete, onCancel }: {
  agentId: string;
  checked: { text: string; result: ValidateResult } | null;
  policies: string;
  onDelete: (rules: PolicyInfo[]) => void;
  onCancel: () => void;
}) {
  // Rule spans index the validated text; wait for validation to catch up.
  const ready = !!checked && checked.text === policies && Array.isArray(checked.result.policies);
  const { owned, mentions } = ready ? rulesNamingAgent(checked.result.policies!, checked.text, agentId) : { owned: [], mentions: [] };
  const n = owned.length;
  const plural = n === 1 ? "" : "s";
  const ruleItem = (p: PolicyInfo) => (
    <li key={`${p.start}-${p.id}`}>
      <span className={`badge decision ${p.effect === "permit" ? "decision-allow" : "decision-deny"}`}>{p.effect === "permit" ? "ALLOWS" : "BLOCKS"}</span> <code>{p.id || `(no name, line ${p.line})`}</code>
    </li>
  );
  return (
    <ConfirmDialog
      title={`Delete agent ${agentId}?`}
      onCancel={onCancel}
      actions={
        !ready
          ? [{ label: "Checking rules…", onClick: () => undefined, disabled: true }]
          : n > 0
            ? [
                { label: `Delete agent and ${n} rule${plural}`, tone: "danger", onClick: () => onDelete(owned) },
                { label: "Delete agent only", onClick: () => onDelete([]) },
              ]
            : [{ label: "Delete agent", tone: "danger", onClick: () => onDelete([]) }]
      }
    >
      {!ready && <p className="muted">Checking which rules name this agent…</p>}
      {ready && n > 0 && (
        <>
          <p>
            {n} rule{plural} {n === 1 ? "is" : "are"} written for <code>{agentId}</code>:
          </p>
          <ul>{owned.map(ruleItem)}</ul>
          {owned.some((p) => p.effect === "permit") ? (
            <p className="builder-warning">
              Rules left behind match nobody now, but if an agent with the id <code>{agentId}</code> is registered again they grant it access immediately.
            </p>
          ) : (
            <p className="muted">Left behind, {n === 1 ? "this rule" : "these rules"} would block any agent later registered with the id <code>{agentId}</code>.</p>
          )}
        </>
      )}
      {ready && mentions.length > 0 && (
        <>
          <p>
            {mentions.length} custom Cedar polic{mentions.length === 1 ? "y mentions" : "ies mention"} this agent. {mentions.length === 1 ? "It is" : "They are"} left unchanged; edit {mentions.length === 1 ? "it" : "them"} by hand:
          </p>
          <ul>{mentions.map(ruleItem)}</ul>
        </>
      )}
      {ready && n === 0 && mentions.length === 0 && <p>No rules name this agent.</p>}
      <p className="muted small">Changes your draft only, as one undo step. Nothing is enforced until you save and activate a version.</p>
    </ConfirmDialog>
  );
}

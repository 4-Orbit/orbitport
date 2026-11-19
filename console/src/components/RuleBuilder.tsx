import { useMemo, useState } from "react";
import { CAPABILITIES, outdatedSuggestedName, REPOSITORY_ID_RE, suggestId, toCedar, validRuleId, type Effect, type On, type Rule, type Who } from "../rules.ts";
import type { KeyInfo } from "../types.ts";
import { Sentence } from "./RuleCard.tsx";
import { toEpoch } from "./SourcePicker.tsx";

interface Props {
  /** The rule being edited, or null for a new rule. */
  initial: Rule | null;
  /** For a new rule: fields to start from ("Grant this…"). The id is suggested. */
  prefill?: Omit<Rule, "id">;
  roles: string[];
  agents: string[];
  keys: KeyInfo[];
  repositories?: string[];
  repositoryError?: string | null;
  /** More keys exist than were loaded; the user can still type any alias. */
  moreKeys?: boolean;
  /** Key ids named anywhere in the policies (may not exist in the KMS yet). */
  referencedKeys: string[];
  takenIds: Set<string>;
  onSave: (rule: Rule) => void;
  onCancel: () => void;
}

/** Key checkboxes shown at once; the rest are reached by searching. */
const KEY_PICKS = 20;

/** Selected keys always show; then the first matches of the search. */
function visibleKeys(all: string[], selected: string[], search: string): { shown: string[]; hidden: number } {
  const q = search.trim().toLowerCase();
  const matches = all.filter((k) => !selected.includes(k) && (!q || k.toLowerCase().includes(q)));
  return { shown: [...selected, ...matches.slice(0, KEY_PICKS)], hidden: Math.max(0, matches.length - KEY_PICKS) };
}

const fromEpochLocal = (s: number) => new Date(s * 1000).toISOString().slice(0, 19);

/** Plain-language form for one rule. Cedar is generated from it. */
export function RuleBuilder({ initial, prefill, roles, agents, keys, repositories = [], repositoryError = null, moreKeys = false, referencedKeys, takenIds, onSave, onCancel }: Props) {
  const seed = initial ?? prefill ?? null;
  const [effect, setEffect] = useState<Effect>(seed?.effect ?? "permit");
  const [who, setWho] = useState<Who>(seed?.who ?? (roles[0] ? { kind: "role", id: roles[0] } : { kind: "anyAgent" }));
  // "Everything" is its own explicit choice: an empty selection must never
  // silently become "every action" (the rule model's encoding of everything).
  const [everything, setEverything] = useState(seed?.can.length === 0);
  const [can, setCan] = useState<string[]>(seed && seed.can.length > 0 ? seed.can : ["kms.Encrypt"]);
  const [on, setOn] = useState<On>(seed?.on ?? { kind: "keys", ids: [] });
  const [expires, setExpires] = useState(seed?.until !== undefined);
  const [until, setUntil] = useState(seed?.until !== undefined ? fromEpochLocal(seed.until) : "");
  const [customId, setCustomId] = useState<string | null>(initial?.id ?? null);
  const [showCedar, setShowCedar] = useState(false);
  const [newKey, setNewKey] = useState("");
  const [keySearch, setKeySearch] = useState("");
  const [newRepository, setNewRepository] = useState("");
  const github = on.kind === "repositories";
  const capabilities = CAPABILITIES.filter((c) => (c.resourceType === "Repository") === github);
  const repositoryIds = [...new Set([...repositories, ...(on.kind === "repositories" ? on.ids : [])])].sort();

  const keyIds = useMemo(() => [...new Set([...keys.map((k) => k.alias), ...referencedKeys, ...(on.kind === "keys" ? on.ids : [])])].sort(), [keys, referencedKeys, on]);
  const tagOptions = useMemo(() => {
    const m = new Map<string, Set<string>>();
    for (const k of keys) for (const t of k.tags) m.set(t.key, (m.get(t.key) ?? new Set()).add(t.value));
    return m;
  }, [keys]);

  const otherIds = new Set([...takenIds].filter((id) => id !== initial?.id));
  const untilEpoch = expires ? toEpoch(until) : undefined;
  const draftRule: Omit<Rule, "id"> = { effect, who, can: everything ? [] : can, on, ...(untilEpoch !== undefined && { until: untilEpoch }) };
  const id = customId ?? suggestId(draftRule, otherIds);
  const rule: Rule = { ...draftRule, id };
  // Editing never renames a rule by itself: say when the name was changed,
  // or when an auto-suggested name no longer describes the rule.
  const renamedFrom = initial && id !== initial.id ? initial.id : null;
  const betterName = initial && !renamedFrom ? outdatedSuggestedName(initial, draftRule, otherIds) : null;

  const errors: string[] = [];
  if ((who.kind === "role" || who.kind === "agent") && !who.id) errors.push(`Choose ${who.kind === "role" ? "a role" : "an agent"}.`);
  if (!everything && can.length === 0) errors.push(github ? "Choose Create issues." : "Choose at least one action, or tick “Everything”.");
  if (on.kind === "keys" && on.ids.length === 0) errors.push("Choose at least one key, or pick “any key”.");
  if (on.kind === "repositories" && (on.ids.length === 0 || on.ids.some((id) => !REPOSITORY_ID_RE.test(id)))) errors.push("Choose at least one repository in owner/name format.");
  if (github && (everything || can.some((id) => !capabilities.some((c) => c.id === id)))) errors.push("Choose a supported GitHub action.");
  if (on.kind === "tag" && (!on.key || !on.value)) errors.push("Enter both the tag name and value.");
  if (expires && untilEpoch === undefined) errors.push("Pick an expiry date and time.");
  if (!validRuleId(id)) errors.push("Rule name: 1–128 of letters, digits, . _ : - (not starting with “platform.”).");
  if (otherIds.has(id)) errors.push("Another rule already uses this name.");
  const warnings: string[] = [];
  if (effect === "forbid" && who.kind === "anyone") warnings.push("This also blocks account tokens, including the operator's. You could lock yourself out of these resources.");
  if (effect === "permit" && who.kind === "anyone" && everything && on.kind === "anyKey") warnings.push("This lets every agent do everything with every key.");
  if (who.kind === "role" && who.id && !roles.includes(who.id)) warnings.push(`Role “${who.id}” isn't declared yet; add it under Agents & roles.`);
  if (who.kind === "agent" && who.id && !agents.includes(who.id)) warnings.push(`Agent “${who.id}” isn't registered yet; add it under Agents & roles.`);

  const children = (g: string) => CAPABILITIES.filter((c) => c.group === g).map((c) => c.id);
  // A group with exactly one action (rotate, admin) is the same as that action,
  // so a rule granting kms.RotateKey shows "Rotate keys" as checked.
  const groupChecked = (g: string) => can.includes(g) || (children(g).length === 1 && can.includes(children(g)[0]));
  const toggleCap = (capId: string) => {
    const cap = CAPABILITIES.find((c) => c.id === capId)!;
    if (!cap.group && groupChecked(capId)) return setCan(can.filter((c) => c !== capId && !children(capId).includes(c)));
    if (can.includes(capId)) return setCan(can.filter((c) => c !== capId));
    // Selecting a whole group replaces its single actions.
    const next = cap.group ? can : can.filter((c) => CAPABILITIES.find((x) => x.id === c)?.group !== capId);
    setCan([...next, capId]);
  };

  return (
    <form
      className="panel rule-builder"
      aria-label={initial ? `Edit rule ${initial.id}` : "New rule"}
      onSubmit={(e) => {
        e.preventDefault();
        if (errors.length === 0) onSave(rule);
      }}
    >
      <header className="panel-head">
        <h2>{initial ? "Edit rule" : "New rule"}</h2>
        <button type="button" className="icon-button" aria-label="Close" onClick={onCancel}>
          ×
        </button>
      </header>

      <div className="panel-body builder-grid">
        <fieldset>
          <legend>This rule</legend>
          <div className="segmented" role="group" aria-label="Allow or block">
            <button type="button" aria-pressed={effect === "permit"} onClick={() => setEffect("permit")}>
              Allows
            </button>
            <button type="button" aria-pressed={effect === "forbid"} onClick={() => setEffect("forbid")}>
              Blocks
            </button>
          </div>
          <p className="muted small">{effect === "permit" ? "Grants access. Agents have no access until a rule allows it." : "Takes access away, even if another rule allows it."}</p>
        </fieldset>

        <fieldset>
          <legend>Service</legend>
          <select aria-label="Service" value={github ? "github" : "kms"} onChange={(e) => {
            const isGithub = e.target.value === "github";
            setEverything(false);
            setCan([isGithub ? "github.issue.Create" : "kms.Encrypt"]);
            setOn({ kind: isGithub ? "repositories" : "keys", ids: [] });
            setShowCedar(false);
          }}>
            <option value="kms">Key management</option>
            <option value="github">GitHub</option>
          </select>
        </fieldset>

        <fieldset>
          <legend>Who</legend>
          <select
            aria-label="Who"
            value={who.kind}
            onChange={(e) => {
              const k = e.target.value as Who["kind"];
              setWho(k === "role" ? { kind: "role", id: roles[0] ?? "" } : k === "agent" ? { kind: "agent", id: agents[0] ?? "" } : { kind: k });
            }}
          >
            <option value="role">Agents with a role</option>
            <option value="agent">One specific agent</option>
            <option value="anyAgent">Any agent</option>
            <option value="anyone">Anyone (agents and account tokens)</option>
          </select>
          {who.kind === "role" && (
            <select aria-label="Role" value={who.id} onChange={(e) => setWho({ kind: "role", id: e.target.value })}>
              {roles.length === 0 && <option value="">no roles declared</option>}
              {roles.map((r) => (
                <option key={r} value={r}>
                  {r}
                </option>
              ))}
            </select>
          )}
          {who.kind === "agent" && (
            <select aria-label="Agent" value={who.id} onChange={(e) => setWho({ kind: "agent", id: e.target.value })}>
              {agents.length === 0 && <option value="">no agents registered</option>}
              {agents.map((a) => (
                <option key={a} value={a}>
                  {a}
                </option>
              ))}
            </select>
          )}
        </fieldset>

        <fieldset className="span-2">
          <legend>Can</legend>
          {!github && <label className="check">
            <input type="checkbox" checked={everything} onChange={(e) => setEverything(e.target.checked)} />
            <span>
              <strong>Everything</strong> <span className="muted">(every key action, now and in future)</span>
            </span>
          </label>}
          {!everything && (
            <div className="caps">
              {capabilities.filter((c) => !c.group).map((g) => (
                <div key={g.id} className="cap-group">
                  <label className="check">
                    <input type="checkbox" checked={groupChecked(g.id)} onChange={() => toggleCap(g.id)} />
                    <strong>{g.label}</strong>
                  </label>
                  <div className="cap-children">
                    {capabilities.filter((c) => c.group === g.id && !c.label.includes("single action")).map((c) => (
                      <label key={c.id} className="check">
                        <input type="checkbox" disabled={groupChecked(g.id)} checked={groupChecked(g.id) || can.includes(c.id)} onChange={() => toggleCap(c.id)} />
                        <span>{c.label}</span>
                      </label>
                    ))}
                  </div>
                </div>
              ))}
            </div>
          )}
          {github && <p className="muted small">Create issues is supported. Editing and closing issues are not available yet.</p>}
          {everything && <p className="muted small">Includes rotating and creating keys.</p>}
        </fieldset>

        <fieldset className="span-2">
          <legend>On</legend>
          {on.kind === "repositories" ? (
            <div className="key-picks">
              <p className="muted small">Choose the repositories this rule covers. A rule does not add repositories to the GitHub App installation.</p>
              {repositoryError && <p className="builder-warning">Configured repositories could not be loaded: {repositoryError}. You can still enter a repository for your draft.</p>}
              {repositoryIds.map((repo) => (
                <label key={repo} className="check">
                  <input type="checkbox" checked={on.ids.includes(repo)} onChange={() => setOn({ kind: "repositories", ids: on.ids.includes(repo) ? on.ids.filter((id) => id !== repo) : [...on.ids, repo] })} />
                  <span className="mono">{repo}</span>
                  {!repositories.includes(repo) && <span className="muted small">not configured for issue creation</span>}
                </label>
              ))}
              <div className="row">
                <input aria-label="Another repository" placeholder="owner/repository" value={newRepository} onChange={(e) => setNewRepository(e.target.value.trim())} />
                <button type="button" className="button small" disabled={!REPOSITORY_ID_RE.test(newRepository) || on.ids.includes(newRepository)} onClick={() => {
                  setOn({ kind: "repositories", ids: [...on.ids, newRepository] });
                  setNewRepository("");
                }}>Add repository</button>
              </div>
            </div>
          ) : <>
          <div className="segmented" role="group" aria-label="Which keys">
            <button type="button" aria-pressed={on.kind === "keys"} onClick={() => setOn({ kind: "keys", ids: on.kind === "keys" ? on.ids : [] })}>
              Specific keys
            </button>
            <button type="button" aria-pressed={on.kind === "tag"} onClick={() => setOn({ kind: "tag", key: on.kind === "tag" ? on.key : "env", value: on.kind === "tag" ? on.value : "" })}>
              Keys with a tag
            </button>
            <button type="button" aria-pressed={on.kind === "anyKey"} onClick={() => setOn({ kind: "anyKey" })}>
              Any key
            </button>
          </div>
          {on.kind === "keys" && (
            <div className="key-picks">
              {keyIds.length > KEY_PICKS && (
                <input aria-label="Find a key" placeholder={`find among ${keyIds.length} keys…`} value={keySearch} onChange={(e) => setKeySearch(e.target.value)} />
              )}
              {visibleKeys(keyIds, on.ids, keySearch).shown.map((k) => {
                const info = keys.find((x) => x.alias === k);
                return (
                  <label key={k} className="check">
                    <input type="checkbox" checked={on.ids.includes(k)} onChange={() => setOn({ kind: "keys", ids: on.ids.includes(k) ? on.ids.filter((x) => x !== k) : [...on.ids, k] })} />
                    <span className="mono">{k}</span>
                    {info ? info.tags.length > 0 && <span className="muted small">{info.tags.map((t) => `${t.key}=${t.value}`).join(", ")}</span> : <span className="muted small">not in the KMS yet</span>}
                  </label>
                );
              })}
              {visibleKeys(keyIds, on.ids, keySearch).hidden > 0 && (
                <p className="muted small">
                  {visibleKeys(keyIds, on.ids, keySearch).hidden} more keys{keySearch ? " match" : ""}; {keySearch ? "refine the search" : "search to find them"}.
                </p>
              )}
              {moreKeys && <p className="muted small">Showing the first {keys.length} keys from the KMS. Type any other key's alias below.</p>}
              <span className="row">
                <input aria-label="Another key" placeholder="another key alias" value={newKey} onChange={(e) => setNewKey(e.target.value.trim())} />
                <button
                  type="button"
                  className="button small"
                  disabled={!newKey || on.ids.includes(newKey)}
                  onClick={() => {
                    setOn({ kind: "keys", ids: [...on.ids, newKey] });
                    setNewKey("");
                  }}
                >
                  Add key
                </button>
              </span>
            </div>
          )}
          {on.kind === "tag" && (
            <div className="row">
              <input aria-label="Tag name" list="tag-names" value={on.key} placeholder="tag" onChange={(e) => setOn({ ...on, key: e.target.value.trim() })} />
              <span>=</span>
              <input aria-label="Tag value" list="tag-values" value={on.value} placeholder="value" onChange={(e) => setOn({ ...on, value: e.target.value.trim() })} />
              <datalist id="tag-names">
                {[...tagOptions.keys()].map((k) => (
                  <option key={k} value={k} />
                ))}
              </datalist>
              <datalist id="tag-values">
                {[...(tagOptions.get(on.key) ?? [])].map((v) => (
                  <option key={v} value={v} />
                ))}
              </datalist>
            </div>
          )}
          {on.kind === "anyKey" && <p className="muted small">Every key in this tenant, including keys created later.</p>}
          </>}
        </fieldset>

        <fieldset>
          <legend>Until</legend>
          <label className="check">
            <input type="checkbox" checked={expires} onChange={(e) => setExpires(e.target.checked)} />
            <span>Expires</span>
          </label>
          {expires && <input type="datetime-local" aria-label="Expires at (UTC)" step={1} value={until} onChange={(e) => setUntil(e.target.value)} />}
          {expires && <p className="muted small">UTC. Checked against the service clock on every request.</p>}
        </fieldset>

        <fieldset>
          <legend>Rule name</legend>
          <input aria-label="Rule name" className="mono" value={id} onChange={(e) => setCustomId(e.target.value.trim())} />
          <p className="muted small">
            Shown in audit and test results.{" "}
            {initial === null && customId !== null && (
              <button type="button" className="link-button" onClick={() => setCustomId(null)}>
                use suggested name
              </button>
            )}
          </p>
          {renamedFrom && (
            <p className="builder-warning">
              Renamed from <code>{renamedFrom}</code>. Past activity and saved versions keep the old name.{" "}
              <button type="button" className="link-button" onClick={() => setCustomId(renamedFrom)}>
                undo rename
              </button>
            </p>
          )}
          {betterName && (
            <p className="muted small">
              This name no longer matches the rule. Suggested: <code>{betterName}</code>{" "}
              <button type="button" className="link-button" onClick={() => setCustomId(betterName)}>
                use suggested name
              </button>
            </p>
          )}
        </fieldset>
      </div>

      <div className="panel-body builder-preview">
        <div className={`rule-sentence effect-${effect}`}>
          <Sentence rule={!everything && can.length === 0 ? { ...rule, can: ["(choose actions)"] } : rule} />
        </div>
        {warnings.map((w) => (
          <p key={w} className="builder-warning">
            {w}
          </p>
        ))}
        {errors.length > 0 && (
          <ul className="problems">
            {errors.map((e) => (
              <li key={e} className="problem problem-error">
                {e}
              </li>
            ))}
          </ul>
        )}
        <button type="button" className="link-button" onClick={() => setShowCedar((v) => !v)}>
          {showCedar ? "Hide Cedar" : "Show the Cedar this writes"}
        </button>
        {showCedar && errors.length === 0 && <pre className="cedar-preview">{toCedar(rule)}</pre>}
        <div className="row">
          <button type="submit" className="button primary" disabled={errors.length > 0}>
            {initial ? "Update rule" : "Add rule"}
          </button>
          <button type="button" className="button" onClick={onCancel}>
            Cancel
          </button>
          <span className="muted small">Changes your draft only; nothing is enforced until you save and activate a version.</span>
        </div>
      </div>
    </form>
  );
}


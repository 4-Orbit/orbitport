import { useMemo, useState } from "react";
import { appendPolicy, fromPolicyJson, removeSpan, replaceSpan, toCedar, type Rule } from "../rules.ts";
import { entityIds, useDraft } from "../draft.tsx";
import type { KeyInfo, ValidateResult } from "../types.ts";
import { RuleCard } from "./RuleCard.tsx";
import { RuleBuilder } from "./RuleBuilder.tsx";

interface Props {
  validation: ValidateResult | null;
  /** The exact text `validation` describes; spans index into it. */
  validatedText: string;
  keys: KeyInfo[];
  onEditCedar: () => void;
  onChanged: (message: string) => void;
}

type Editing = { kind: "new" } | { kind: "edit"; index: number } | null;

/** The plain-language view of the draft's policies, with the rule builder. */
export function RulesView({ validation, validatedText, keys, onEditCedar, onChanged }: Props) {
  const draft = useDraft();
  // Edits use the validated spans, so they wait until validation catches up.
  const stale = validatedText !== draft.policies;
  const [editing, setEditing] = useState<Editing>(null);
  const [filter, setFilter] = useState("");

  const infos = validation?.policies ?? null;
  const cards = useMemo(
    () => (infos ?? []).map((info) => ({ info, rule: fromPolicyJson(info.json), text: validatedText.slice(info.start, info.end) })),
    // The spans index the text that was validated; cards only rebuild with a new validation.
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [infos, validatedText],
  );
  const takenIds = useMemo(() => new Set(cards.map((c) => c.info.id).filter(Boolean)), [cards]);
  const roles = entityIds(draft.entities, "Role");
  const agents = entityIds(draft.entities, "Agent");

  if (infos === null && validation) {
    return (
      <div className="rules-empty">
        <p>
          <strong>The policy text doesn't parse</strong>, so it can't be shown as rules. Fix it in the Cedar view (errors are marked on their lines), or press Undo.
        </p>
        <button type="button" className="button" onClick={onEditCedar}>
          Open Cedar view
        </button>
      </div>
    );
  }

  const save = (rule: Rule) => {
    if (stale) return;
    if (editing?.kind === "edit") {
      const { info } = cards[editing.index];
      draft.commit({ policies: replaceSpan(draft.policies, info.start, info.end, toCedar(rule)) }, `edit rule ${rule.id}`);
      onChanged(`Updated rule ${rule.id}.`);
    } else {
      draft.commit({ policies: appendPolicy(draft.policies, toCedar(rule)) }, `add rule ${rule.id}`);
      onChanged(`Added rule ${rule.id}.`);
    }
    setEditing(null);
  };

  const q = filter.trim().toLowerCase();
  const shown = cards.map((c, index) => ({ ...c, index })).filter((c) => !q || c.text.toLowerCase().includes(q) || c.info.id.toLowerCase().includes(q));
  const allows = cards.filter((c) => c.info.effect === "permit").length;
  const custom = cards.filter((c) => !c.rule).length;

  return (
    <div className="rules-view" aria-busy={stale}>
      <div className="row rules-toolbar">
        <button type="button" className="button primary" disabled={stale || editing !== null} onClick={() => setEditing({ kind: "new" })}>
          + Add rule
        </button>
        <input aria-label="Filter rules" placeholder="filter by agent, role, key…" value={filter} onChange={(e) => setFilter(e.target.value)} />
        <span className="muted small">
          {cards.length} rules · {allows} allow · {cards.length - allows} block{custom ? ` · ${custom} custom` : ""}
        </span>
      </div>

      {editing?.kind === "new" && (
        <RuleBuilder initial={null} roles={roles} agents={agents} keys={keys} referencedKeys={validation?.summary?.referencedKeys ?? []} takenIds={takenIds} onSave={save} onCancel={() => setEditing(null)} />
      )}

      {cards.length === 0 && editing === null && (
        <div className="rules-empty">
          <p>
            <strong>No rules yet.</strong> Agents can't do anything until a rule allows it. Account tokens (such as the operator's) always keep full access.
          </p>
          <button type="button" className="button primary" onClick={() => setEditing({ kind: "new" })}>
            Add your first rule
          </button>
        </div>
      )}

      <div className="rule-list">
        {shown.map((c) =>
          editing?.kind === "edit" && editing.index === c.index && c.rule ? (
            <RuleBuilder
              key={`edit-${c.index}`}
              initial={c.rule}
              roles={roles}
              agents={agents}
              keys={keys}
              referencedKeys={validation?.summary?.referencedKeys ?? []}
              takenIds={takenIds}
              onSave={save}
              onCancel={() => setEditing(null)}
            />
          ) : (
            <RuleCard
              key={`${c.index}-${c.info.id}`}
              info={c.info}
              rule={c.rule}
              text={c.text}
              problems={(validation?.problems ?? []).filter((p) => p.policyId && p.policyId === c.info.id)}
              disabled={stale || editing !== null}
              onEdit={() => setEditing({ kind: "edit", index: c.index })}
              onEditCedar={onEditCedar}
              onDelete={() => {
                if (stale) return;
                draft.commit({ policies: removeSpan(draft.policies, c.info.start, c.info.end) }, `delete rule ${c.info.id}`);
                onChanged(`Deleted rule ${c.info.id}.`);
              }}
            />
          ),
        )}
      </div>
    </div>
  );
}

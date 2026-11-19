import { describe, isExpired, type Rule } from "../rules.ts";
import type { PolicyInfo, Problem } from "../types.ts";
import { ConfirmButton } from "./Confirm.tsx";

export function Sentence({ rule }: { rule: Rule }) {
  return (
    <>
      {describe(rule).parts.map((p, i) =>
        p.strong ? (
          <strong key={i} className="mono-ish">
            {p.text}
          </strong>
        ) : (
          <span key={i}>{p.text}</span>
        ),
      )}
    </>
  );
}

interface Props {
  info: PolicyInfo;
  /** null = a custom policy the builder can't represent. */
  rule: Rule | null;
  text: string;
  problems: Problem[];
  /** Actions are locked while the draft is being re-validated or another rule is open. */
  disabled: boolean;
  /** Registered agent ids; a rule for any other agent is flagged. */
  agents: string[];
  onEdit: () => void;
  onEditCedar: () => void;
  onDelete: () => void;
}

/** One policy as a plain-language card. */
export function RuleCard({ info, rule, text, problems, disabled, agents, onEdit, onEditCedar, onDelete }: Props) {
  const allows = info.effect === "permit";
  const expired = rule ? isExpired(rule) : false;
  const orphan = rule?.who.kind === "agent" && !agents.includes(rule.who.id) ? rule.who.id : null;
  return (
    <article className={`rule-card effect-${info.effect}${expired ? " expired" : ""}${problems.length ? " has-problems" : ""}`} aria-label={`Rule ${info.id || "(no name)"}`}>
      <header className="rule-head">
        <span className={`badge decision ${allows ? "decision-allow" : "decision-deny"}`}>{allows ? "ALLOWS" : "BLOCKS"}</span>
        <code className="rule-id">{info.id || "(no name)"}</code>
        {expired && <span className="badge result result-none" title="The expiry time has passed; this rule no longer applies">EXPIRED</span>}
        {!rule && <span className="badge sim-time">CUSTOM CEDAR</span>}
        {orphan && (
          <span className="badge result result-error" title={`No agent ${orphan} is registered. This rule matches nobody now, but would apply at once to an agent registered later with that id.`}>
            AGENT NOT REGISTERED
          </span>
        )}
        <span className={`rule-actions${disabled ? " locked" : ""}`} aria-disabled={disabled}>
          {rule ? (
            <button type="button" className="link-button" onClick={onEdit}>
              Edit
            </button>
          ) : (
            <button type="button" className="link-button" onClick={onEditCedar}>
              Edit in Cedar
            </button>
          )}
          <ConfirmButton
            label="Delete"
            confirmLabel="Delete rule"
            ariaLabel={`Delete rule ${info.id}`}
            impact={allows ? "Anyone relying on it loses that access." : "Access it blocked may become allowed."}
            onConfirm={onDelete}
          />
        </span>
      </header>
      {rule ? (
        <p className="rule-sentence">
          <Sentence rule={rule} />
        </p>
      ) : (
        <>
          <p className="rule-sentence muted">This rule uses Cedar the plain-language view can't show exactly, so it's displayed as written.</p>
          <pre className="cedar-preview">{text}</pre>
        </>
      )}
      {problems.length > 0 && (
        <ul className="problems">
          {problems.map((p, i) => (
            <li key={i} className={`problem problem-${p.severity}`}>
              {p.message}
            </li>
          ))}
        </ul>
      )}
    </article>
  );
}

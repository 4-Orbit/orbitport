import type { ContextField } from "../types.ts";
import type { ContextValues } from "../context-fields.ts";
import { parseSet } from "../context-fields.ts";
import { EntityPicker } from "./EntityPicker.tsx";

/**
 * Inputs for an action's trusted context (D-035). In enforcement the GitHub
 * plugin computes these from GitHub; here they are a what-if.
 */
export function ContextFields({ fields, values, onChange, agents }: { fields: ContextField[]; values: ContextValues; onChange: (v: ContextValues) => void; agents: string[] }) {
  if (fields.length === 0) return null;
  const set = (name: string, v: ContextValues[string] | undefined) => {
    const next = { ...values };
    if (v === undefined) delete next[name];
    else next[name] = v;
    onChange(next);
  };
  return (
    <fieldset className="context-fields">
      <legend>Trusted context</legend>
      <p className="muted small">Enforcement reads these from GitHub. Here you choose them, to see what the policy would decide.</p>
      {fields.map((f) => {
        const v = values[f.name];
        const label = `${f.name}${f.optional ? " (optional)" : ""}`;
        const hint = <span className="muted small">{f.doc}</span>;
        if (f.type === "Bool")
          return (
            <label key={f.name} className="field inline checkbox" title={f.doc}>
              <input type="checkbox" checked={v === true} onChange={(e) => set(f.name, e.target.checked)} />
              <span>{label}</span>
            </label>
          );
        if (f.type === "Agent")
          return (
            <div key={f.name} title={f.doc}>
              <EntityPicker label={label} value={typeof v === "string" ? v : ""} onChange={(id) => set(f.name, id || undefined)} options={agents} emptyLabel="(none)" allowOther noun="an agent" placeholder="agent id" />
              {hint}
            </div>
          );
        return (
          <label key={f.name} className="field" title={f.doc}>
            <span>{label}</span>
            {f.type === "Long" ? (
              <input type="number" step={1} value={typeof v === "number" ? v : 0} onChange={(e) => set(f.name, Number(e.target.value))} />
            ) : f.type === "Set<String>" ? (
              <input value={Array.isArray(v) ? v.join(", ") : ""} placeholder="comma-separated" onChange={(e) => set(f.name, parseSet(e.target.value))} />
            ) : (
              <input value={typeof v === "string" ? v : ""} onChange={(e) => set(f.name, e.target.value)} />
            )}
            {hint}
          </label>
        );
      })}
    </fieldset>
  );
}

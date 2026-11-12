import type { Source } from "../types.ts";
import { useDraft } from "../draft.tsx";

export type SourceChoice = "active" | "draft" | `v${number}`;

export function toSource(choice: SourceChoice, draft: ReturnType<typeof useDraft>): Source | undefined {
  if (choice === "active") return undefined;
  if (choice === "draft") return { draft: draft.bundle };
  return { version: Number(choice.slice(1)) };
}

/** Pick what to evaluate: the active version, the editor's draft, or a saved version. */
export function SourcePicker({ value, onChange, versions }: { value: SourceChoice; onChange: (v: SourceChoice) => void; versions: number[] }) {
  return (
    <label className="field inline">
      <span>Evaluate against</span>
      <select value={value} onChange={(e) => onChange(e.target.value as SourceChoice)}>
        <option value="active">Active version</option>
        <option value="draft">Editor draft (unsaved)</option>
        {versions.map((v) => (
          <option key={v} value={`v${v}`}>
            Version {v}
          </option>
        ))}
      </select>
    </label>
  );
}

/** Optional simulated time. Empty = now (the same clock enforcement uses). */
export function TimeTravel({ value, onChange }: { value: string; onChange: (v: string) => void }) {
  return (
    <label className="field inline">
      <span>Simulated time (UTC)</span>
      <input type="datetime-local" value={value} onChange={(e) => onChange(e.target.value)} step={1} />
      {value && (
        <button type="button" className="link-button" onClick={() => onChange("")}>
          now
        </button>
      )}
    </label>
  );
}

/** datetime-local (interpreted as UTC) -> Unix seconds, or undefined for "now". */
export function toEpoch(local: string): number | undefined {
  if (!local) return undefined;
  const ms = Date.parse(local.length === 16 ? `${local}:00Z` : `${local}Z`);
  return Number.isNaN(ms) ? undefined : Math.floor(ms / 1000);
}

import { useState } from "react";
import type { Source } from "../types.ts";
import { useDraft } from "../draft.tsx";

export type SourceChoice = "active" | "draft" | `v${number}`;

export function toSource(choice: SourceChoice, draft: ReturnType<typeof useDraft>): Source | undefined {
  if (choice === "active") return undefined;
  if (choice === "draft") return { draft: draft.bundle };
  return { version: Number(choice.slice(1)) };
}

/** How many recent versions the picker lists before "Another version…". */
export const RECENT_VERSIONS = 5;

/**
 * Pick what to evaluate: the active version, the editor's draft, one of the
 * few most recent versions, or any other version by number. Long histories
 * stay one short menu.
 */
export function SourcePicker({ value, onChange, versions }: { value: SourceChoice; onChange: (v: SourceChoice) => void; versions: number[] }) {
  const recent = versions.slice(0, RECENT_VERSIONS);
  const newest = versions[0] ?? 0;
  const chosen = value.startsWith("v") ? Number(value.slice(1)) : null;
  // A version picked by number stays in the list, so the menu always shows
  // the current choice and every option stays one click away.
  const extra = chosen !== null && !recent.includes(chosen) ? chosen : null;
  const [typing, setTyping] = useState(false);
  const [typed, setTyped] = useState("");
  const valid = (t: string) => /^\d+$/.test(t) && Number(t) >= 1 && (newest === 0 || Number(t) <= newest);
  const hasOthers = newest > recent.length;

  return (
    <span className="source-picker">
      <label className="field inline">
        <span>Evaluate against</span>
        <select
          value={typing ? "other" : value}
          onChange={(e) => {
            if (e.target.value === "other") {
              setTyped("");
              setTyping(true);
              return;
            }
            setTyping(false);
            onChange(e.target.value as SourceChoice);
          }}
        >
          <option value="active">Active version</option>
          <option value="draft">Editor draft (unsaved)</option>
          {recent.length > 0 && (
            <optgroup label="Recent versions">
              {recent.map((v) => (
                <option key={v} value={`v${v}`}>
                  Version {v}
                </option>
              ))}
            </optgroup>
          )}
          {extra !== null && <option value={`v${extra}`}>Version {extra}</option>}
          {hasOthers && <option value="other">Another version…</option>}
        </select>
      </label>
      {typing && (
        <form
          className="version-jump"
          onSubmit={(e) => {
            e.preventDefault();
            if (!valid(typed)) return;
            onChange(`v${Number(typed)}`);
            setTyping(false);
          }}
        >
          <label>
            <span className="sr-only">Version number</span>
            <input
              className="version-input"
              inputMode="numeric"
              placeholder={newest ? `1–${newest}` : "number"}
              value={typed}
              autoFocus
              aria-invalid={typed !== "" && !valid(typed)}
              onChange={(e) => setTyped(e.target.value.trim().replace(/^v/i, ""))}
            />
          </label>
          <button type="submit" className="button small" disabled={!valid(typed)}>
            Show
          </button>
          <button type="button" className="button small" onClick={() => setTyping(false)}>
            Cancel
          </button>
          {typed !== "" && !valid(typed) && <span className="field-hint">Enter 1–{newest}</span>}
        </form>
      )}
    </span>
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

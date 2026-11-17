import type { Bundle, EntityJson } from "./types.ts";

/**
 * The working draft shared by the Policies, Simulate, Access and Tests pages,
 * with undo/redo. It is a per-viewer convenience kept in localStorage; the
 * server holds only saved versions.
 */
export interface Snapshot {
  policies: string;
  entities: EntityJson[];
}

export interface DraftState extends Snapshot {
  /** Version the draft was loaded from; null for a fresh draft. */
  base: number | null;
  /** True once edited since loading or saving. */
  dirty: boolean;
}

export interface HistoryEntry {
  snapshot: Snapshot;
  label: string;
}

export interface DraftStore {
  draft: DraftState;
  past: HistoryEntry[];
  future: HistoryEntry[];
  /** When the last typing edit happened; consecutive typing merges into one undo step. */
  lastTypingAt: number;
}

export type DraftAction =
  | { type: "type"; policies: string; at: number }
  | { type: "commit"; next: Partial<Snapshot>; label: string }
  | { type: "load"; bundle: Bundle; base: number | null; label: string }
  | { type: "markSaved"; base: number }
  | { type: "undo" }
  | { type: "redo" };

const MAX_HISTORY = 100;
const TYPING_MERGE_MS = 1500;

const snap = (d: DraftState): Snapshot => ({ policies: d.policies, entities: d.entities });
const push = (list: HistoryEntry[], entry: HistoryEntry) => [...list, entry].slice(-MAX_HISTORY);

export function draftReducer(s: DraftStore, a: DraftAction): DraftStore {
  switch (a.type) {
    case "type": {
      if (a.policies === s.draft.policies) return s;
      const merge = a.at - s.lastTypingAt < TYPING_MERGE_MS && s.past.at(-1)?.label === "edit Cedar";
      return {
        draft: { ...s.draft, policies: a.policies, dirty: true },
        past: merge ? s.past : push(s.past, { snapshot: snap(s.draft), label: "edit Cedar" }),
        future: [],
        lastTypingAt: a.at,
      };
    }
    case "commit": {
      const next = { ...s.draft, ...a.next, dirty: true };
      if (next.policies === s.draft.policies && next.entities === s.draft.entities) return s;
      return { draft: next, past: push(s.past, { snapshot: snap(s.draft), label: a.label }), future: [], lastTypingAt: 0 };
    }
    case "load":
      return {
        draft: { policies: a.bundle.policies, entities: a.bundle.entities ?? [], base: a.base, dirty: false },
        past: s.draft.policies || s.draft.entities.length ? push(s.past, { snapshot: snap(s.draft), label: a.label }) : s.past,
        future: [],
        lastTypingAt: 0,
      };
    case "markSaved":
      return { ...s, draft: { ...s.draft, base: a.base, dirty: false } };
    case "undo": {
      const entry = s.past.at(-1);
      if (!entry) return s;
      return {
        draft: { ...s.draft, ...entry.snapshot, dirty: true },
        past: s.past.slice(0, -1),
        future: [...s.future, { snapshot: snap(s.draft), label: entry.label }],
        lastTypingAt: 0,
      };
    }
    case "redo": {
      const entry = s.future.at(-1);
      if (!entry) return s;
      return {
        draft: { ...s.draft, ...entry.snapshot, dirty: true },
        past: push(s.past, { snapshot: snap(s.draft), label: entry.label }),
        future: s.future.slice(0, -1),
        lastTypingAt: 0,
      };
    }
  }
}


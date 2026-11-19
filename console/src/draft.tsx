import { createContext, useCallback, useContext, useEffect, useMemo, useReducer, useState, type ReactNode } from "react";
import type { Bundle, EntityJson, SimRequest } from "./types.ts";
import type { GrantRequest } from "./explain.ts";
import { draftReducer, type DraftState, type Snapshot } from "./draft-history.ts";

interface DraftApi extends DraftState {
  /** Typing in the Cedar editor (merged into one undo step per pause). */
  setPolicies: (text: string) => void;
  /** A discrete, labeled change ("delete rule x", "add agent y"). */
  commit: (next: Partial<Snapshot>, label: string) => void;
  setEntities: (entities: EntityJson[], label?: string) => void;
  load: (bundle: Bundle, base: number | null, label?: string) => void;
  markSaved: (base: number) => void;
  undo: () => void;
  redo: () => void;
  undoLabel: string | null;
  redoLabel: string | null;
  bundle: Bundle;
  /** A request queued for the simulator (Activity replay, Access cell). */
  pendingSim: SimRequest | null;
  setPendingSim: (r: SimRequest | null) => void;
  /** A "Grant this…" fix queued for the Policies page. */
  pendingGrant: GrantRequest | null;
  setPendingGrant: (g: GrantRequest | null) => void;
}

const STORAGE_KEY = "orbitport-console-draft-v1";
const empty: DraftState = { policies: "", entities: [], base: null, dirty: false };

function loadStored(): DraftState {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return empty;
    const parsed = JSON.parse(raw) as DraftState;
    if (typeof parsed.policies !== "string" || !Array.isArray(parsed.entities)) return empty;
    return parsed;
  } catch {
    return empty;
  }
}

const Ctx = createContext<DraftApi | null>(null);

export function DraftProvider({ children }: { children: ReactNode }) {
  const [store, dispatch] = useReducer(draftReducer, undefined, () => ({ draft: loadStored(), past: [], future: [], lastTypingAt: 0 }));
  const [pendingSim, setPendingSim] = useState<SimRequest | null>(null);
  const [pendingGrant, setPendingGrant] = useState<GrantRequest | null>(null);
  const { draft } = store;

  useEffect(() => {
    try {
      localStorage.setItem(STORAGE_KEY, JSON.stringify(draft));
    } catch {
      // storage unavailable (private window): the draft lives in memory only
    }
  }, [draft]);

  const setPolicies = useCallback((policies: string) => dispatch({ type: "type", policies, at: Date.now() }), []);
  const commit = useCallback((next: Partial<Snapshot>, label: string) => dispatch({ type: "commit", next, label }), []);
  const setEntities = useCallback((entities: EntityJson[], label = "edit agents & roles") => dispatch({ type: "commit", next: { entities }, label }), []);
  const load = useCallback((bundle: Bundle, base: number | null, label = "load") => dispatch({ type: "load", bundle, base, label }), []);
  const markSaved = useCallback((base: number) => dispatch({ type: "markSaved", base }), []);
  const undo = useCallback(() => dispatch({ type: "undo" }), []);
  const redo = useCallback(() => dispatch({ type: "redo" }), []);

  const value = useMemo<DraftApi>(
    () => ({
      ...draft,
      setPolicies,
      commit,
      setEntities,
      load,
      markSaved,
      undo,
      redo,
      undoLabel: store.past.at(-1)?.label ?? null,
      redoLabel: store.future.at(-1)?.label ?? null,
      bundle: { policies: draft.policies, entities: draft.entities },
      pendingSim,
      setPendingSim,
      pendingGrant,
      setPendingGrant,
    }),
    [draft, store.past, store.future, setPolicies, commit, setEntities, load, markSaved, undo, redo, pendingSim, pendingGrant],
  );
  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}

export function useDraft(): DraftApi {
  const v = useContext(Ctx);
  if (!v) throw new Error("useDraft outside DraftProvider");
  return v;
}

/** Agent and role ids declared in an entity list. */
export function entityIds(entities: EntityJson[], type: "Agent" | "Role"): string[] {
  return entities.filter((e) => e.uid.type === type).map((e) => e.uid.id).sort();
}

export function rolesOf(entities: EntityJson[], agentId: string): string[] {
  return (entities.find((e) => e.uid.type === "Agent" && e.uid.id === agentId)?.parents ?? []).filter((p) => p.type === "Role").map((p) => p.id);
}


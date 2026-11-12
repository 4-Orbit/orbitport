import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from "react";
import type { Bundle, EntityJson, SimRequest } from "./types.ts";

/**
 * The working draft shared by the Policies, Simulate, Access and Tests pages.
 * It is a per-viewer convenience kept in localStorage; the server holds only
 * saved versions.
 */
interface DraftState {
  policies: string;
  entities: EntityJson[];
  /** Version the draft was loaded from; null for a fresh draft. */
  base: number | null;
  /** True once edited since loading. */
  dirty: boolean;
}

interface DraftApi extends DraftState {
  setPolicies: (text: string) => void;
  setEntities: (entities: EntityJson[]) => void;
  load: (bundle: Bundle, base: number | null) => void;
  bundle: Bundle;
  /** A request queued for the simulator (Activity replay, Access cell). */
  pendingSim: SimRequest | null;
  setPendingSim: (r: SimRequest | null) => void;
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
  const [state, setState] = useState<DraftState>(loadStored);
  const [pendingSim, setPendingSim] = useState<SimRequest | null>(null);

  useEffect(() => {
    try {
      localStorage.setItem(STORAGE_KEY, JSON.stringify(state));
    } catch {
      // storage unavailable (private window): the draft lives in memory only
    }
  }, [state]);

  const setPolicies = useCallback((policies: string) => setState((s) => ({ ...s, policies, dirty: true })), []);
  const setEntities = useCallback((entities: EntityJson[]) => setState((s) => ({ ...s, entities, dirty: true })), []);
  const load = useCallback((bundle: Bundle, base: number | null) => setState({ policies: bundle.policies, entities: bundle.entities ?? [], base, dirty: false }), []);

  const value = useMemo<DraftApi>(
    () => ({ ...state, setPolicies, setEntities, load, bundle: { policies: state.policies, entities: state.entities }, pendingSim, setPendingSim }),
    [state, setPolicies, setEntities, load, pendingSim],
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

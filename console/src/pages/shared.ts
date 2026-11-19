import { useEffect, useState } from "react";
import { api } from "../api.ts";
import { collectPages } from "../paging.ts";
import { entityIds, type useDraft } from "../draft.tsx";
import type { SourceChoice } from "../components/SourcePicker.tsx";
import type { EntityJson, KeyInfo, SchemaInfo, VersionInfo } from "../types.ts";

/** The newest few saved version numbers, newest first (for the version picker). */
export function useVersions(refreshKey = 0): number[] {
  const [versions, setVersions] = useState<number[]>([]);
  useEffect(() => {
    // The version picker shows only the most recent few; ask for no more.
    api.versions("", 5).then((r) => setVersions(r.versions.map((v) => v.version))).catch(() => setVersions([]));
  }, [refreshKey]);
  return versions;
}

/** Keys loaded at most; beyond this the UI says more exist and lets you type an alias. */
export const MAX_KEYS_LOADED = 2000;

export function useKeys(): { data: KeyInfo[] | null; error: string | null; more: boolean } {
  const [state, setState] = useState<{ data: KeyInfo[] | null; error: string | null; more: boolean }>({ data: null, error: null, more: false });
  useEffect(() => {
    let cancelled = false;
    collectPages(
      async (cursor) => {
        const r = await api.keys(cursor);
        return { items: r.keys, nextCursor: r.nextCursor ?? "" };
      },
      (k) => k.keyId,
      MAX_KEYS_LOADED,
    )
      .then((r) => !cancelled && setState({ data: r.items, error: null, more: r.more }))
      .catch((e: Error) => !cancelled && setState({ data: [], error: e.message, more: false }));
    return () => {
      cancelled = true;
    };
  }, []);
  return state;
}

let schemaCache: Promise<SchemaInfo> | null = null;

export function useSchema(): SchemaInfo | null {
  const [schema, setSchema] = useState<SchemaInfo | null>(null);
  useEffect(() => {
    schemaCache ??= api.schema();
    schemaCache.then(setSchema).catch(() => {
      schemaCache = null;
    });
  }, []);
  return schema;
}

/**
 * The active version number (null = none) and the newest page of versions.
 * The active number comes from policy.GetActive, not the page, so it is right
 * even when the active version is older than the first page.
 */
export function useVersionState(refreshKey = 0): { active: number | null; versions: VersionInfo[]; loaded: boolean } {
  const [state, setState] = useState<{ active: number | null; versions: VersionInfo[]; loaded: boolean }>({ active: null, versions: [], loaded: false });
  useEffect(() => {
    let cancelled = false;
    Promise.all([api.active(), api.versions()])
      .then(([a, r]) => {
        if (!cancelled) setState({ versions: r.versions, active: a.version?.version ?? null, loaded: true });
      })
      .catch(() => !cancelled && setState((s) => ({ ...s, loaded: true })));
    return () => {
      cancelled = true;
    };
  }, [refreshKey]);
  return state;
}

export interface ListState<T> {
  data: T[] | null;
  error: string | null;
}

/** Repositories configured for GitHub issue creation (github.ListRepositories). */
export function useRepositories(): ListState<string> & { mode: "mock" | "real" | null } {
  const [state, setState] = useState<ListState<string> & { mode: "mock" | "real" | null }>({ data: null, error: null, mode: null });
  useEffect(() => {
    let cancelled = false;
    api
      .githubRepositories()
      .then((r) => !cancelled && setState({ data: r.repositories, error: null, mode: r.mode }))
      .catch((e: Error) => !cancelled && setState({ data: null, error: e.message, mode: null }));
    return () => {
      cancelled = true;
    };
  }, []);
  return state;
}

/** The entities of a saved version, or of the active one (null = active). */
async function versionEntities(version: number | null): Promise<EntityJson[]> {
  if (version === null) return (await api.active()).version?.entities ?? [];
  return (await api.version(version)).version.entities;
}

/**
 * Agents declared by what a page evaluates against: the editor draft, the
 * active version or a saved version. The draft needs no request.
 */
export function useSourceAgents(choice: SourceChoice, draft: ReturnType<typeof useDraft>): ListState<string> {
  const [state, setState] = useState<ListState<string> & { for: string }>({ data: null, error: null, for: "" });
  useEffect(() => {
    if (choice === "draft") return;
    let cancelled = false;
    setState({ data: null, error: null, for: choice });
    versionEntities(choice === "active" ? null : Number(choice.slice(1)))
      .then((entities) => !cancelled && setState({ data: entityIds(entities, "Agent"), error: null, for: choice }))
      .catch((e: Error) => !cancelled && setState({ data: null, error: e.message, for: choice }));
    return () => {
      cancelled = true;
    };
  }, [choice]);
  if (choice === "draft") return { data: entityIds(draft.entities, "Agent"), error: null };
  return state.for === choice ? state : { data: null, error: null };
}

/** Versions searched for agents the active version no longer registers. */
export const REMOVED_AGENT_VERSIONS = 20;

/**
 * Agents the active version registers, and agents declared by any of the
 * newest saved versions (which may since have been removed).
 */
export function useKnownAgents(): { registered: string[] | null; declared: string[]; error: string | null } {
  const [state, setState] = useState<{ registered: string[] | null; declared: string[]; error: string | null }>({ registered: null, declared: [], error: null });
  useEffect(() => {
    let cancelled = false;
    (async () => {
      const active = await api.active();
      const registered = entityIds(active.version?.entities ?? [], "Agent");
      if (!cancelled) setState({ registered, declared: [], error: null });
      // Older versions only add removed agents; a failure there is not fatal.
      const { versions } = await api.versions("", REMOVED_AGENT_VERSIONS).catch(() => ({ versions: [] as VersionInfo[] }));
      const all = await Promise.all(versions.map((v) => versionEntities(v.version).catch(() => [] as EntityJson[])));
      if (!cancelled) setState({ registered, declared: [...new Set(all.flatMap((e) => entityIds(e, "Agent")))], error: null });
    })().catch((e: Error) => !cancelled && setState({ registered: null, declared: [], error: e.message }));
    return () => {
      cancelled = true;
    };
  }, []);
  return state;
}

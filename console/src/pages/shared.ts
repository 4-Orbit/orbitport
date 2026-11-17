import { useEffect, useState } from "react";
import { api } from "../api.ts";
import { collectPages } from "../paging.ts";
import type { KeyInfo, SchemaInfo, VersionInfo } from "../types.ts";

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

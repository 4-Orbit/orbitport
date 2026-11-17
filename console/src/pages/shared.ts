import { useEffect, useState } from "react";
import { api } from "../api.ts";
import type { KeyInfo, SchemaInfo, VersionInfo } from "../types.ts";

/** Saved version numbers, newest first. */
export function useVersions(refreshKey = 0): number[] {
  const [versions, setVersions] = useState<number[]>([]);
  useEffect(() => {
    api.versions().then((r) => setVersions(r.versions.map((v) => v.version))).catch(() => setVersions([]));
  }, [refreshKey]);
  return versions;
}

export function useKeys(): { data: KeyInfo[] | null; error: string | null } {
  const [state, setState] = useState<{ data: KeyInfo[] | null; error: string | null }>({ data: null, error: null });
  useEffect(() => {
    api.keys().then((r) => setState({ data: r.keys, error: null })).catch((e: Error) => setState({ data: [], error: e.message }));
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

/** The active version number (null = none) and the saved versions, refetched when refreshKey changes. */
export function useVersionState(refreshKey = 0): { active: number | null; versions: VersionInfo[]; loaded: boolean } {
  const [state, setState] = useState<{ active: number | null; versions: VersionInfo[]; loaded: boolean }>({ active: null, versions: [], loaded: false });
  useEffect(() => {
    let cancelled = false;
    api
      .versions()
      .then((r) => {
        if (!cancelled) setState({ versions: r.versions, active: r.versions.find((v) => v.active)?.version ?? null, loaded: true });
      })
      .catch(() => !cancelled && setState((s) => ({ ...s, loaded: true })));
    return () => {
      cancelled = true;
    };
  }, [refreshKey]);
  return state;
}

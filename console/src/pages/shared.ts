import { useEffect, useState } from "react";
import { api } from "../api.ts";
import type { KeyInfo, SchemaInfo } from "../types.ts";

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

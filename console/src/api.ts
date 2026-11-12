import type * as T from "./types.ts";

export class RpcError extends Error {
  constructor(
    message: string,
    readonly reason?: string,
    readonly status?: number,
  ) {
    super(message);
  }
}

/** Calls one allowlisted JSON-RPC method through the console server. */
export async function rpc<R>(method: string, params: Record<string, unknown> = {}): Promise<R> {
  let res: Response;
  try {
    res = await fetch("/api/rpc", {
      method: "POST",
      headers: { "Content-Type": "application/json", Accept: "application/json" },
      body: JSON.stringify({ method, params }),
    });
  } catch {
    throw new RpcError("console server unreachable");
  }
  const body = (await res.json().catch(() => null)) as { result?: R; error?: string | { message: string; reason?: string } } | null;
  if (!body) throw new RpcError(`HTTP ${res.status}`, undefined, res.status);
  if (body.error) {
    const e = typeof body.error === "string" ? { message: body.error } : body.error;
    throw new RpcError(e.message, "reason" in e ? e.reason : undefined, res.status);
  }
  return body.result as R;
}

export const getHealth = async (): Promise<T.Health> => {
  const res = await fetch("/api/health", { headers: { Accept: "application/json" } });
  if (!res.ok) throw new RpcError(`HTTP ${res.status}`);
  return (await res.json()) as T.Health;
};

export const api = {
  schema: () => rpc<T.SchemaInfo>("policy.GetSchema"),
  active: () => rpc<T.ActiveResult>("policy.GetActive"),
  versions: () => rpc<{ versions: T.VersionInfo[] }>("policy.ListVersions"),
  version: (version: number) => rpc<{ version: T.Version }>("policy.GetVersion", { version }),
  tests: () => rpc<{ tests: T.TestCase[] }>("policy.GetTests"),
  putTests: (tests: T.TestCase[]) => rpc<{ count: number }>("policy.PutTests", { tests }),
  runTests: (source?: T.Source, tests?: T.TestCase[]) => rpc<T.TestReport>("policy.RunTests", { ...(source && { source }), ...(tests && { tests }) }),
  audit: (filter: T.AuditFilter) => rpc<T.AuditResult>("policy.ListAudit", { ...filter }),
  keys: () => rpc<{ keys: T.KeyInfo[]; truncated: boolean }>("policy.ListKeys"),
  validate: (bundle: T.Bundle) => rpc<T.ValidateResult>("policy.Validate", { ...bundle }),
  simulate: (requests: T.SimRequest[], source?: T.Source, at?: number) =>
    rpc<T.SimulateResult>("policy.Simulate", { requests, ...(source && { source }), ...(at && { at }) }),
  matrix: (params: { source?: T.Source; keys?: T.Resource[]; includeAccount?: boolean; at?: number }) => rpc<T.MatrixResult>("policy.Matrix", params),
  diff: (from: T.Source | undefined, to: T.Source | undefined, keys?: T.Resource[]) =>
    rpc<T.DiffResult>("policy.Diff", { ...(from && { from }), ...(to && { to }), ...(keys && { keys }) }),
  saveDraft: (bundle: T.Bundle, message: string) => rpc<{ version: number }>("policy.SaveDraft", { ...bundle, message }),
  loadTemplate: () => rpc<{ version: number; tests: number }>("policy.LoadTemplate", { template: "4orbit" }),
  activate: (version: number, force = false) => rpc<T.ActivateResult>("policy.Activate", { version, ...(force && { force }) }),
  issueAgentToken: (agentId: string, ttlSeconds: number) => rpc<T.IssuedToken>("policy.IssueAgentToken", { agentId, ttlSeconds }),
};

/** Key resources (with tags) for matrix/simulation, from the KMS key list. */
export function keyResources(keys: T.KeyInfo[]): T.Resource[] {
  return keys.map((k) => ({ type: "Key", id: k.alias, attrs: { scheme: k.scheme, keySpec: k.keySpec, keyUsage: k.keyUsage }, tags: Object.fromEntries(k.tags.map((t) => [t.key, t.value])) }));
}

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

/**
 * Waits before each retry of a rate-limited call. The gateway counts requests
 * per token in fixed 10-second windows, so the last wait reaches the next one.
 */
export const RATE_LIMIT_RETRY_MS = [1000, 3000, 7000];

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

/**
 * Calls one allowlisted JSON-RPC method through the console server. A call
 * the gateway rate-limited was never run, so it is retried, even a write.
 */
export async function rpc<R>(method: string, params: Record<string, unknown> = {}): Promise<R> {
  for (let attempt = 0; ; attempt++) {
    try {
      return await rpcOnce<R>(method, params);
    } catch (e) {
      if (!(e instanceof RpcError) || e.status !== 429 || attempt >= RATE_LIMIT_RETRY_MS.length) throw e;
      await sleep(RATE_LIMIT_RETRY_MS[attempt]);
    }
  }
}

async function rpcOnce<R>(method: string, params: Record<string, unknown>): Promise<R> {
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

/** Calls one console-server endpoint (not a gateway method). */
async function consoleCall<R>(path: string, body?: unknown): Promise<R> {
  let res: Response;
  try {
    res = await fetch(path, body === undefined ? { headers: { Accept: "application/json" } } : { method: "POST", headers: { "Content-Type": "application/json", Accept: "application/json" }, body: JSON.stringify(body) });
  } catch {
    throw new RpcError("console server unreachable");
  }
  const out = (await res.json().catch(() => null)) as { result?: R; error?: string } | R | null;
  if (!res.ok) throw new RpcError((out as { error?: string } | null)?.error ?? `HTTP ${res.status}`, undefined, res.status);
  return out as R;
}

export const api = {
  githubRepositories: () => rpc<{ repositories: string[]; mode: "mock" | "real" }>("github.ListRepositories"),
  createGithubIssue: async (agentId: string, repository: string, title: string, body: string) =>
    (await consoleCall<{ result: T.GithubIssueResult }>("/api/github/issues", { agentId, repository, title, body })).result,
  createGeminiGithubIssue: (agentId: string, repository: string, prompt: string, confirmCreate: boolean) =>
    consoleCall<{ result: T.GithubIssueResult; proposal: { title: string; body: string } }>("/api/github/gemini-issues", { agentId, repository, prompt, confirmCreate }),
  /** A multi-step Gemini task; every tool call is decided by the active policy. */
  runGeminiAgent: (agentId: string, repository: string, task: string, confirm: boolean) =>
    consoleCall<{ run: T.AgentRun; mode: "mock" | "real" | null }>("/api/github/gemini-agent", { agentId, repository, task, confirm }),
  /** Run it for real: one KMS request as the agent, decided by enforcement. */
  runForReal: async (agentId: string, action: string, keyId: string) => (await consoleCall<{ result: T.RunResult }>("/api/run", { agentId, action, keyId })).result,
  /** Token hashes of this console's runs (for Activity labels). */
  consoleRuns: async () => (await consoleCall<{ jtiHashes: string[] }>("/api/console-runs")).jtiHashes,
  schema: () => rpc<T.SchemaInfo>("policy.GetSchema"),
  active: () => rpc<T.ActiveResult>("policy.GetActive"),
  /** One page of versions, newest first; pass nextCursor back for older ones. */
  versions: (cursor = "", limit?: number) =>
    rpc<{ versions: T.VersionInfo[]; nextCursor: string }>("policy.ListVersions", { ...(cursor && { cursor }), ...(limit && { limit }) }),
  version: (version: number) => rpc<{ version: T.Version }>("policy.GetVersion", { version }),
  tests: () => rpc<{ tests: T.TestCase[] }>("policy.GetTests"),
  putTests: (tests: T.TestCase[]) => rpc<{ count: number }>("policy.PutTests", { tests }),
  runTests: (source?: T.Source, tests?: T.TestCase[]) => rpc<T.TestReport>("policy.RunTests", { ...(source && { source }), ...(tests && { tests }) }),
  audit: (filter: T.AuditFilter) => rpc<T.AuditResult>("policy.ListAudit", { ...filter }),
  /** One page of keys (≤ 200), in key-id order. */
  keys: (cursor = "", limit?: number) =>
    rpc<{ keys: T.KeyInfo[]; truncated: boolean; nextCursor: string }>("policy.ListKeys", { ...(cursor && { cursor }), ...(limit && { limit }) }),
  validate: (bundle: T.Bundle) => rpc<T.ValidateResult>("policy.Validate", { ...bundle }),
  /** With explain, each DENY carries an explanation (the first 50). */
  simulate: (requests: T.SimRequest[], source?: T.Source, at?: number, explain = false) =>
    rpc<T.SimulateResult>("policy.Simulate", { requests, ...(source && { source }), ...(at && { at }), ...(explain && { explain }) }),
  /** Why one request is (or would be) denied by a source (default: active). */
  explain: (request: T.SimRequest, source?: T.Source, at?: number) =>
    rpc<T.ExplainResult>("policy.Explain", { ...request, ...(source && { source }), ...(at && { at }) }),
  matrix: (params: {
    source?: T.Source;
    keys?: T.Resource[];
    includeAccount?: boolean;
    at?: number;
    keyOffset?: number;
    keyLimit?: number;
    agentOffset?: number;
    agentLimit?: number;
    /** Restrict to these principals ("" = account). */
    agents?: string[];
    /** Only keys where the selected principals have some access. */
    onlyAllowed?: boolean;
    keySearch?: string;
    /** Per-principal counts over every key instead of cells. */
    summary?: boolean;
  }) => rpc<T.MatrixResult>("policy.Matrix", params),
  diff: (from: T.Source | undefined, to: T.Source | undefined, keys?: T.Resource[]) =>
    rpc<T.DiffResult>("policy.Diff", { ...(from && { from }), ...(to && { to }), ...(keys && { keys }) }),
  /** Saves a version; an identical existing version is returned with duplicate=true instead. */
  saveDraft: (bundle: T.Bundle, message: string, allowDuplicate = false) =>
    rpc<{ version: number; duplicate: boolean }>("policy.SaveDraft", { ...bundle, message, ...(allowDuplicate && { allowDuplicate }) }),
  /** The 4Orbit template, read-only: nothing is saved. */
  template: () => rpc<T.Bundle & { tests: T.TestCase[] }>("policy.GetTemplate", { template: "4orbit" }),
  activate: (version: number, force = false) => rpc<T.ActivateResult>("policy.Activate", { version, ...(force && { force }) }),
  issueAgentToken: (agentId: string, ttlSeconds: number) => rpc<T.IssuedToken>("policy.IssueAgentToken", { agentId, ttlSeconds }),
};

/** Key resources (with tags) for matrix/simulation, from the KMS key list. */
export function keyResources(keys: T.KeyInfo[]): T.Resource[] {
  return keys.map((k) => ({ type: "Key", id: k.alias, attrs: { scheme: k.scheme, keySpec: k.keySpec, keyUsage: k.keyUsage }, tags: Object.fromEntries(k.tags.map((t) => [t.key, t.value])) }));
}

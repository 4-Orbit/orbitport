import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { serveStatic } from "./static.ts";
import { callGateway, readToken, type GatewayCall } from "./gateway.ts";
import { parseRunRequest, parseGithubIssueRequest, RunError, Runner } from "./run.ts";
import { GeminiError, type GeminiIssueClient } from "./gemini.ts";

/**
 * The console's backend-for-frontend. It holds the operator (account) PAT,
 * reads it from a file on every call so a re-seed is picked up, and forwards
 * an allowlist of JSON-RPC methods to the gateway. The PAT never appears in a
 * response. The browser sees only results.
 *
 * It replaces 4Orbit GUI v1's read-only server (D-018/D-020 superseded by
 * D-027): the console is now a privileged admin tool, so it stays bound to
 * loopback and checks the Host header against DNS rebinding.
 */
export interface AppOptions {
  gatewayUrl: string;
  tokenFile: string;
  staticDir?: string;
  allowedHosts?: string[];
  fetchImpl?: typeof fetch;
  /** Clock and sleep for console runs (tests replace them). */
  now?: () => number;
  sleep?: (ms: number) => Promise<void>;
  gemini?: GeminiIssueClient;
}

/** Methods the browser may call. Everything else is refused here. */
export const ALLOWED_METHODS = new Set([
  "github.ListRepositories",
  "policy.GetSchema",
  "policy.GetActive",
  "policy.ListVersions",
  "policy.GetVersion",
  "policy.GetTests",
  "policy.GetTemplate",
  "policy.ListAudit",
  "policy.ListKeys",
  "policy.Validate",
  "policy.Simulate",
  "policy.Matrix",
  "policy.Diff",
  "policy.Explain",
  "policy.RunTests",
  "policy.SaveDraft",
  "policy.PutTests",
  "policy.LoadTemplate",
  "policy.Activate",
  "policy.IssueAgentToken",
  "kms.GetCapabilities",
]);

const MAX_BODY_BYTES = 600 * 1024;
const DEFAULT_HOSTS = ["127.0.0.1", "localhost", "[::1]"];

export function createApp(opts: AppOptions): Server {
  let recentGeminiTasks: number[] = [];
  const reserveGeminiTask = (): boolean => {
    const now = (opts.now ?? Date.now)();
    recentGeminiTasks = recentGeminiTasks.filter((time) => now - time < 60_000);
    if (recentGeminiTasks.length >= 5) return false;
    recentGeminiTasks.push(now);
    return true;
  };
  const runner = new Runner({
    gatewayUrl: opts.gatewayUrl,
    fetchImpl: opts.fetchImpl ?? fetch,
    now: opts.now ?? Date.now,
    sleep: opts.sleep ?? ((ms) => new Promise((r) => setTimeout(r, ms))),
  });
  return createServer((req, res) => {
    route(req, res, opts, runner, reserveGeminiTask).catch((err: unknown) => {
      console.error(`[console] ${req.method} ${req.url}: ${err instanceof Error ? err.message : err}`);
      if (!res.headersSent) sendJson(res, 500, { error: "internal error" });
    });
  });
}

async function route(req: IncomingMessage, res: ServerResponse, opts: AppOptions, runner: Runner, reserveGeminiTask: () => boolean): Promise<void> {
  const hosts = new Set(opts.allowedHosts ?? DEFAULT_HOSTS);
  if (!hosts.has(hostnameOf(req.headers.host))) return sendJson(res, 403, { error: "forbidden host" });

  const { pathname } = new URL(req.url ?? "/", "http://localhost");

  if (pathname === "/api/health") {
    if (req.method !== "GET") return sendJson(res, 405, { error: "method not allowed" });
    return sendJson(res, 200, await health(opts));
  }

  if (pathname === "/api/rpc") {
    if (req.method !== "POST") return sendJson(res, 405, { error: "method not allowed" });
    // JSON only: a cross-site HTML form cannot post here.
    if (!/^application\/json\b/.test(req.headers["content-type"] ?? "")) return sendJson(res, 415, { error: "expected application/json" });
    const body = await readJsonBody(req);
    if (!isCall(body)) return sendJson(res, 400, { error: "expected {method, params}" });
    if (!ALLOWED_METHODS.has(body.method)) return sendJson(res, 403, { error: `method ${body.method} is not available in the console` });
    const token = readToken(opts.tokenFile);
    if (!token) return sendJson(res, 503, { error: "operator token missing: run `make 4orbit-seed`" });
    const out = await callGateway(opts.gatewayUrl, token, body, opts.fetchImpl ?? fetch);
    return sendJson(res, out.status, out.body);
  }

  // Run it for real: one KMS request as an agent, with a token minted here.
  // Separate from /api/rpc, whose allowlist never includes KMS operations.
  if (pathname === "/api/run") {
    if (req.method !== "POST") return sendJson(res, 405, { error: "method not allowed" });
    if (!/^application\/json\b/.test(req.headers["content-type"] ?? "")) return sendJson(res, 415, { error: "expected application/json" });
    const parsed = parseRunRequest(await readJsonBody(req));
    if (typeof parsed === "string") return sendJson(res, 400, { error: parsed });
    const token = readToken(opts.tokenFile);
    if (!token) return sendJson(res, 503, { error: "operator token missing: run `make 4orbit-seed`" });
    try {
      return sendJson(res, 200, { result: await runner.run(token, parsed) });
    } catch (e) {
      if (e instanceof RunError) return sendJson(res, e.status, { error: e.message });
      throw e;
    }
  }

  if (pathname === "/api/github/issues") {
    if (req.method !== "POST") return sendJson(res, 405, { error: "method not allowed" });
    if (!/^application\/json\b/.test(req.headers["content-type"] ?? "")) return sendJson(res, 415, { error: "expected application/json" });
    const parsed = parseGithubIssueRequest(await readJsonBody(req));
    if (typeof parsed === "string") return sendJson(res, 400, { error: parsed });
    const token = readToken(opts.tokenFile);
    if (!token) return sendJson(res, 503, { error: "operator token missing: run make 4orbit-seed" });
    try {
      return sendJson(res, 200, { result: await runner.createGithubIssue(token, parsed) });
    } catch (e) {
      if (e instanceof RunError) return sendJson(res, e.status, { error: e.message });
      throw e;
    }
  }

  if (pathname === "/api/github/gemini-issues") {
    if (req.method !== "POST") return sendJson(res, 405, { error: "method not allowed" });
    if (!/^application\/json\b/.test(req.headers["content-type"] ?? "")) return sendJson(res, 415, { error: "expected application/json" });
    if (!opts.gemini) return sendJson(res, 503, { error: "Gemini is not configured: set GEMINI_API_KEY for the console" });
    const input = await readJsonBody(req);
    if (!input || typeof input !== "object" || Array.isArray(input)) return sendJson(res, 400, { error: "expected a Gemini issue request" });
    const { agentId, repository, prompt, confirmCreate, ...rest } = input as Record<string, unknown>;
    if (Object.keys(rest).length || confirmCreate !== true || typeof prompt !== "string" || !prompt.trim() || prompt.length > 4_000) {
      return sendJson(res, 400, { error: "choose an agent and repository, enter a task, and confirm issue creation" });
    }
    const selected = parseGithubIssueRequest({ agentId, repository, title: "placeholder", body: "" });
    if (typeof selected === "string") return sendJson(res, 400, { error: selected });
    const token = readToken(opts.tokenFile);
    if (!token) return sendJson(res, 503, { error: "operator token missing: run make 4orbit-seed" });
    if (!reserveGeminiTask()) return sendJson(res, 429, { error: "at most 5 Gemini tasks per minute; try again shortly" });
    let proposal;
    try { proposal = await opts.gemini.proposeIssue({ prompt, repository: selected.repository }); }
    catch (error) {
      if (error instanceof GeminiError) return sendJson(res, error.httpStatus ?? (error.kind === "timeout" ? 504 : 502), { error: error.message });
      return sendJson(res, 502, { error: "Gemini proposal failed" });
    }
    const issue = parseGithubIssueRequest({ agentId: selected.agentId, repository: selected.repository, title: proposal.title, body: proposal.body });
    if (typeof issue === "string") return sendJson(res, 502, { error: "Gemini proposed an invalid issue" });
    try { return sendJson(res, 200, { result: await runner.createGithubIssue(token, issue), proposal }); }
    catch (error) {
      if (error instanceof RunError) return sendJson(res, error.status, { error: error.message });
      throw error;
    }
  }

  // Token hashes of console runs, so Activity can label those events.
  if (pathname === "/api/console-runs") {
    if (req.method !== "GET") return sendJson(res, 405, { error: "method not allowed" });
    return sendJson(res, 200, { jtiHashes: runner.consoleRuns() });
  }

  if (pathname.startsWith("/api/")) return sendJson(res, 404, { error: "not found" });
  if (opts.staticDir && req.method === "GET") {
    if (serveStatic(opts.staticDir, pathname, res)) return;
    // Hash routing: every non-file path serves the app shell.
    if (serveStatic(opts.staticDir, "/", res)) return;
  }
  sendJson(res, 404, { error: "not found" });
}

async function health(opts: AppOptions) {
  const tokenPresent = readToken(opts.tokenFile) !== null;
  let gateway: "ok" | "unreachable" = "unreachable";
  try {
    const r = await (opts.fetchImpl ?? fetch)(`${opts.gatewayUrl}/healthz`, { signal: AbortSignal.timeout(2000) });
    gateway = r.ok ? "ok" : "unreachable";
  } catch {
    gateway = "unreachable";
  }
  return { gateway, gatewayUrl: opts.gatewayUrl, tokenPresent };
}

function isCall(v: unknown): v is GatewayCall {
  if (typeof v !== "object" || v === null) return false;
  const { method, params } = v as Record<string, unknown>;
  return typeof method === "string" && method.length < 64 && (params === undefined || (typeof params === "object" && !Array.isArray(params)));
}

function hostnameOf(hostHeader: string | undefined): string {
  try {
    return new URL(`http://${hostHeader ?? ""}`).hostname;
  } catch {
    return "";
  }
}

async function readJsonBody(req: IncomingMessage): Promise<unknown> {
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of req) {
    size += (chunk as Buffer).length;
    if (size > MAX_BODY_BYTES) return undefined;
    chunks.push(chunk as Buffer);
  }
  try {
    return JSON.parse(Buffer.concat(chunks).toString("utf8"));
  } catch {
    return undefined;
  }
}

export function sendJson(res: ServerResponse, status: number, body: unknown): void {
  res.writeHead(status, {
    "Content-Type": "application/json; charset=utf-8",
    "Cache-Control": "no-store",
    "X-Content-Type-Options": "nosniff",
  });
  res.end(JSON.stringify(body));
}

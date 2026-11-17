import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { serveStatic } from "./static.ts";
import { callGateway, readToken, type GatewayCall } from "./gateway.ts";

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
}

/** Methods the browser may call. Everything else is refused here. */
export const ALLOWED_METHODS = new Set([
  "policy.GetSchema",
  "policy.GetActive",
  "policy.ListVersions",
  "policy.GetVersion",
  "policy.GetTests",
  "policy.ListAudit",
  "policy.ListKeys",
  "policy.Validate",
  "policy.Simulate",
  "policy.Matrix",
  "policy.Diff",
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
  return createServer((req, res) => {
    route(req, res, opts).catch((err: unknown) => {
      console.error(`[console] ${req.method} ${req.url}: ${err instanceof Error ? err.message : err}`);
      if (!res.headersSent) sendJson(res, 500, { error: "internal error" });
    });
  });
}

async function route(req: IncomingMessage, res: ServerResponse, opts: AppOptions): Promise<void> {
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

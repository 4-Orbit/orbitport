import { readFileSync } from "node:fs";

export interface GatewayCall {
  method: string;
  params?: Record<string, unknown>;
}

export interface GatewayResult {
  status: number;
  body: { result: unknown } | { error: { code?: number; message: string; reason?: string } };
}

/** The operator PAT, or null when the file is missing or empty. */
export function readToken(path: string): string | null {
  try {
    const token = readFileSync(path, "utf8").trim();
    return token.length > 0 ? token : null;
  } catch {
    return null;
  }
}

let nextId = 1;

/**
 * Forwards one JSON-RPC call with the operator token. Error messages come
 * from the gateway, which never echoes the bearer; we still redact it in case
 * an upstream ever does.
 */
export async function callGateway(gatewayUrl: string, token: string, call: GatewayCall, fetchImpl: typeof fetch): Promise<GatewayResult> {
  let res: Response;
  try {
    res = await fetchImpl(`${gatewayUrl}/api/v1/rpc`, {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}` },
      body: JSON.stringify({ jsonrpc: "2.0", id: nextId++, method: call.method, params: call.params ?? {} }),
      signal: AbortSignal.timeout(15000),
    });
  } catch {
    return { status: 502, body: { error: { message: `gateway unreachable at ${gatewayUrl}` } } };
  }
  const text = await res.text();
  const redact = (s: string) => s.split(token).join("[redacted]");
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    return { status: 502, body: { error: { message: `gateway returned HTTP ${res.status}` } } };
  }
  if (!res.ok) {
    const msg = typeof (parsed as { error?: unknown })?.error === "string" ? (parsed as { error: string }).error : `HTTP ${res.status}`;
    // 401 here means the operator token expired or the stack was reset.
    const hint = res.status === 401 ? " (operator token rejected: re-run `make 4orbit-seed`)" : "";
    return { status: res.status === 401 ? 401 : 502, body: { error: { message: redact(msg) + hint } } };
  }
  const envelope = parsed as { result?: unknown; error?: { code?: number; message?: string; data?: { reason?: string } } };
  if (envelope.error) {
    return {
      status: 200,
      body: { error: { code: envelope.error.code, message: redact(cleanMessage(envelope.error.message ?? "error")), reason: envelope.error.data?.reason } },
    };
  }
  return { status: 200, body: { result: envelope.result ?? null } };
}

/** tonic Status strings look like `status: PermissionDenied, message: "...", ...`. */
export function cleanMessage(message: string): string {
  const m = /message: "((?:[^"\\]|\\.)*)"/.exec(message);
  return m ? m[1].replace(/\\"/g, '"') : message;
}

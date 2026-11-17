import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { createServer, request, type IncomingMessage, type Server } from "node:http";
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { AddressInfo } from "node:net";
import { createApp, ALLOWED_METHODS } from "../server/app.ts";
import { cleanMessage } from "../server/gateway.ts";

const TOKEN = "operator-secret-token-value";
let dir: string;
let tokenFile: string;
let gateway: Server;
let gatewayUrl: string;
let console_: Server;
let consoleUrl: string;
const seen: { auth?: string; body?: unknown }[] = [];
let gatewayReply: (body: { method: string }) => { status: number; json: unknown } = (b) => ({ status: 200, json: { jsonrpc: "2.0", id: 1, result: { echoed: b.method } } });

async function readBody(req: IncomingMessage): Promise<string> {
  const chunks: Buffer[] = [];
  for await (const c of req) chunks.push(c as Buffer);
  return Buffer.concat(chunks).toString("utf8");
}

before(async () => {
  dir = mkdtempSync(join(tmpdir(), "console-test-"));
  tokenFile = join(dir, "operator.pat");
  writeFileSync(tokenFile, TOKEN + "\n");
  mkdirSync(join(dir, "dist"));
  writeFileSync(join(dir, "dist", "index.html"), "<!doctype html><title>app</title>");

  gateway = createServer(async (req, res) => {
    if (req.url === "/healthz") {
      res.writeHead(200).end('{"status":"ok"}');
      return;
    }
    const body = JSON.parse(await readBody(req));
    seen.push({ auth: req.headers.authorization, body });
    const out = gatewayReply(body);
    res.writeHead(out.status, { "Content-Type": "application/json" }).end(JSON.stringify(out.json));
  });
  await new Promise<void>((r) => gateway.listen(0, "127.0.0.1", r));
  gatewayUrl = `http://127.0.0.1:${(gateway.address() as AddressInfo).port}`;

  console_ = createApp({ gatewayUrl, tokenFile, staticDir: join(dir, "dist") });
  await new Promise<void>((r) => console_.listen(0, "127.0.0.1", r));
  consoleUrl = `http://127.0.0.1:${(console_.address() as AddressInfo).port}`;
});

after(() => {
  gateway.close();
  console_.close();
  rmSync(dir, { recursive: true, force: true });
});

const post = (method: string, params: unknown = {}, headers: Record<string, string> = {}) =>
  fetch(`${consoleUrl}/api/rpc`, { method: "POST", headers: { "Content-Type": "application/json", ...headers }, body: JSON.stringify({ method, params }) });

test("forwards allowlisted methods with the operator token", async () => {
  seen.length = 0;
  const res = await post("policy.GetSchema");
  assert.equal(res.status, 200);
  const body = (await res.json()) as { result: { echoed: string } };
  assert.equal(body.result.echoed, "policy.GetSchema");
  assert.equal(seen[0].auth, `Bearer ${TOKEN}`);
  assert.deepEqual((seen[0].body as { params: unknown }).params, {});
});

test("refuses methods outside the allowlist without calling the gateway", async () => {
  seen.length = 0;
  for (const m of ["kms.Encrypt", "kms.Decrypt", "kms_keystore.Get", "policy.DropEverything"]) {
    assert.ok(!ALLOWED_METHODS.has(m));
    const res = await post(m);
    assert.equal(res.status, 403, m);
  }
  assert.equal(seen.length, 0);
});

test("the operator token never appears in any response", async () => {
  gatewayReply = () => ({ status: 200, json: { jsonrpc: "2.0", id: 1, error: { code: -32001, message: `status: Internal, message: "boom ${TOKEN}"` } } });
  const res = await post("policy.GetActive");
  const text = await res.text();
  assert.ok(!text.includes(TOKEN), text);
  assert.match(text, /\[redacted\]/);
  const health = await (await fetch(`${consoleUrl}/api/health`)).text();
  assert.ok(!health.includes(TOKEN));
  assert.match(health, /"tokenPresent":true/);
  gatewayReply = (b) => ({ status: 200, json: { jsonrpc: "2.0", id: 1, result: { echoed: b.method } } });
});

test("JSON-RPC errors are mapped with their reason", async () => {
  gatewayReply = () => ({
    status: 200,
    json: { jsonrpc: "2.0", id: 1, error: { code: -32001, message: `status: PermissionDenied, message: "request denied by policy", details: []`, data: { reason: "permission_denied" } } },
  });
  const body = (await (await post("policy.Activate", { version: 1 })).json()) as { error: { message: string; reason: string } };
  assert.equal(body.error.message, "request denied by policy");
  assert.equal(body.error.reason, "permission_denied");
  gatewayReply = (b) => ({ status: 200, json: { jsonrpc: "2.0", id: 1, result: { echoed: b.method } } });
});

test("an expired operator token is reported with a fix", async () => {
  gatewayReply = () => ({ status: 401, json: { error: "pat_expired" } });
  const res = await post("policy.GetActive");
  assert.equal(res.status, 401);
  assert.match(((await res.json()) as { error: { message: string } }).error.message, /4orbit-seed/);
  gatewayReply = (b) => ({ status: 200, json: { jsonrpc: "2.0", id: 1, result: { echoed: b.method } } });
});

test("rejects non-loopback Host headers (DNS rebinding)", async () => {
  // fetch cannot forge Host, so use node:http directly.
  const status = await new Promise<number>((resolve, reject) => {
    const req = request(`${consoleUrl}/api/health`, { headers: { Host: "evil.example:4317" } }, (r) => {
      r.resume();
      resolve(r.statusCode ?? 0);
    });
    req.on("error", reject);
    req.end();
  });
  assert.equal(status, 403);
});

test("requires JSON and an object body", async () => {
  const form = await fetch(`${consoleUrl}/api/rpc`, { method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" }, body: "method=policy.GetSchema" });
  assert.equal(form.status, 415);
  const arr = await fetch(`${consoleUrl}/api/rpc`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ method: "policy.GetSchema", params: [1] }) });
  assert.equal(arr.status, 400);
  const get = await fetch(`${consoleUrl}/api/rpc`);
  assert.equal(get.status, 405);
});

test("reads the token file on every call (re-seed is picked up)", async () => {
  seen.length = 0;
  writeFileSync(tokenFile, "rotated-token\n");
  await post("policy.GetSchema");
  assert.equal(seen[0].auth, "Bearer rotated-token");
  writeFileSync(tokenFile, "");
  const missing = await post("policy.GetSchema");
  assert.equal(missing.status, 503);
  writeFileSync(tokenFile, TOKEN);
});

test("serves the app shell for client routes and blocks traversal", async () => {
  const shell = await fetch(`${consoleUrl}/versions`);
  assert.equal(shell.status, 200);
  assert.match(await shell.text(), /<title>app<\/title>/);
  assert.match(shell.headers.get("content-security-policy") ?? "", /script-src|default-src 'self'/);
  const traversal = await fetch(`${consoleUrl}/..%2f..%2fetc%2fpasswd`);
  assert.ok([200, 404].includes(traversal.status));
  assert.doesNotMatch(await traversal.text(), /root:/);
});

test("cleanMessage extracts the tonic message", () => {
  assert.equal(cleanMessage(`status: NotFound, message: "version 3 not found", details: []`), "version 3 not found");
  assert.equal(cleanMessage("plain"), "plain");
});

import { test, before, after, beforeEach } from "node:test";
import assert from "node:assert/strict";
import { createServer, type IncomingMessage, type Server } from "node:http";
import { mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { AddressInfo } from "node:net";
import { createApp } from "../server/app.ts";
import { hashJti, jtiOf, kmsParams, parseRunRequest, RUN_RATE_PER_MINUTE, RUN_TOKEN_TTL_SECONDS } from "../server/run.ts";

const OPERATOR = "operator-secret-token-value";
const CIPHERTEXT = "vault:v1:SECRET-CIPHERTEXT-BYTES";
let dir: string;
let tokenFile: string;
let gateway: Server;
let gatewayUrl: string;

interface Seen {
  auth?: string;
  method: string;
  params: Record<string, unknown>;
}
let seen: Seen[] = [];
let minted = 0;
/** What the fake KMS decides for the next call. */
let decide: (method: string, params: Record<string, unknown>) => "allow" | "deny" | "kmsError" = () => "allow";
/** Audit events by token hash, as the policy plugin would store them. */
let audit: Record<string, unknown>[] = [];
/** Simulate the KMS's audit arriving late (or never). */
let auditDelayCalls = 0;

const jwt = (claims: Record<string, unknown>) =>
  ["header", Buffer.from(JSON.stringify(claims)).toString("base64url"), "signature"].map((p, i) => (i === 0 ? Buffer.from('{"alg":"EdDSA"}').toString("base64url") : p)).join(".");

async function readBody(req: IncomingMessage): Promise<string> {
  const chunks: Buffer[] = [];
  for await (const c of req) chunks.push(c as Buffer);
  return Buffer.concat(chunks).toString("utf8");
}

const tokens = new Map<string, string>(); // agent token -> jti

before(async () => {
  dir = mkdtempSync(join(tmpdir(), "console-run-"));
  tokenFile = join(dir, "operator.pat");
  writeFileSync(tokenFile, OPERATOR);
  gateway = createServer(async (req, res) => {
    const body = JSON.parse(await readBody(req)) as { method: string; params: Record<string, unknown> };
    const auth = req.headers.authorization;
    seen.push({ auth, method: body.method, params: body.params });
    const reply = (x: unknown) => res.writeHead(200, { "Content-Type": "application/json" }).end(JSON.stringify({ jsonrpc: "2.0", id: 1, ...(x as object) }));

    if (body.method === "policy.IssueAgentToken") {
      if (auth !== `Bearer ${OPERATOR}`) return reply({ error: { code: -32001, message: "denied" } });
      if (body.params.agentId === "ghost-agent") return reply({ error: { code: -32001, message: `status: FailedPrecondition, message: "agent \\"ghost-agent\\" is not registered in the active policy version"` } });
      const jti = `agent-${++minted}`;
      const token = jwt({ jti, agent_id: body.params.agentId });
      tokens.set(token, jti);
      return reply({ result: { agentId: body.params.agentId, token, ttlSeconds: body.params.ttlSeconds } });
    }
    if (body.method === "policy.ListAudit") {
      if (auditDelayCalls > 0) {
        auditDelayCalls--;
        return reply({ result: { events: [], nextCursor: "" } });
      }
      return reply({ result: { events: audit.filter((e) => e.jtiHash === body.params.jtiHash).reverse(), nextCursor: "" } });
    }
    if (body.method.startsWith("kms.")) {
      const token = (auth ?? "").replace(/^Bearer /, "");
      const jti = tokens.get(token);
      const verdict = decide(body.method, body.params);
      audit.push({
        ts: new Date().toISOString(),
        requestId: `req-${audit.length + 1}`,
        action: `Action::"${body.method}"`,
        decision: verdict === "deny" ? "DENY" : "ALLOW",
        determiningPolicies: verdict === "deny" ? [] : ["developer-encrypt-dev-key"],
        policyVersion: 4,
        kmsCalled: verdict !== "deny",
        jtiHash: jti ? hashJti(jti) : "operator",
      });
      if (verdict === "deny") return reply({ error: { code: -32001, message: `status: PermissionDenied, message: "request denied by policy"`, data: { reason: "permission_denied" } } });
      if (verdict === "kmsError") return reply({ error: { code: -32000, message: `status: InvalidArgument, message: "invalid ciphertext"` } });
      return reply({ result: { KeyId: body.params.KeyId, CiphertextBlob: CIPHERTEXT, Plaintext: "UExBSU5URVhU" } });
    }
    reply({ error: { code: -32601, message: "unknown" } });
  });
  await new Promise<void>((r) => gateway.listen(0, "127.0.0.1", r));
  gatewayUrl = `http://127.0.0.1:${(gateway.address() as AddressInfo).port}`;
});

after(() => {
  gateway.close();
  rmSync(dir, { recursive: true, force: true });
});

beforeEach(() => {
  seen = [];
  audit = [];
  auditDelayCalls = 0;
  decide = () => "allow";
});

/** A console app with a controllable clock and instant sleeps. */
async function startConsole(clock = { t: Date.now() }) {
  const app = createApp({ gatewayUrl, tokenFile, now: () => clock.t, sleep: async (ms) => void (clock.t += ms) });
  await new Promise<void>((r) => app.listen(0, "127.0.0.1", r));
  const url = `http://127.0.0.1:${(app.address() as AddressInfo).port}`;
  const run = (body: unknown) => fetch(`${url}/api/run`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
  return { app, url, run, clock };
}

test("runs as the agent: minted token to the KMS, decision from the audit event, no key material", async () => {
  const c = await startConsole();
  const res = await c.run({ agentId: "developer-agent", action: "kms.Encrypt", keyId: "dev-key" });
  const text = await res.text();
  assert.equal(res.status, 200, text);
  const { result } = JSON.parse(text);
  assert.equal(result.decision, "ALLOW");
  assert.equal(result.kmsCalled, true);
  assert.equal(result.failed, false);
  assert.deepEqual(result.determiningPolicies, ["developer-encrypt-dev-key"]);
  assert.equal(result.policyVersion, 4);
  assert.equal(result.requestId, "req-1");
  assert.match(result.outcome, /encrypted the sample text/);

  const mint = seen.find((s) => s.method === "policy.IssueAgentToken")!;
  assert.equal(mint.auth, `Bearer ${OPERATOR}`, "minting uses the operator token");
  assert.deepEqual(mint.params, { agentId: "developer-agent", ttlSeconds: RUN_TOKEN_TTL_SECONDS });
  const kms = seen.filter((s) => s.method.startsWith("kms."));
  assert.equal(kms.length, 1);
  assert.notEqual(kms[0].auth, `Bearer ${OPERATOR}`, "the operator token never reaches the KMS");
  assert.equal(jtiOf(kms[0].auth!.replace("Bearer ", "")), "agent-" + minted);
  assert.deepEqual(kms[0].params, { KeyId: "kms:dev-key", Plaintext: Buffer.from("orbitport console run").toString("base64") });

  assert.ok(!text.includes(CIPHERTEXT) && !text.includes("UExBSU5URVhU"), "no ciphertext or plaintext in the response");
  assert.ok(!text.includes(OPERATOR) && !text.includes(kms[0].auth!.replace("Bearer ", "")), "no token in the response");
  c.app.close();
});

test("a DENY is reported from the audit event with the KMS never called", async () => {
  const c = await startConsole();
  decide = () => "deny";
  const { result } = (await (await c.run({ agentId: "developer-agent", action: "kms.Sign", keyId: "kms:dev-key" })).json()) as { result: Record<string, unknown> };
  assert.equal(result.decision, "DENY");
  assert.equal(result.kmsCalled, false);
  assert.equal(result.failed, true);
  assert.equal(result.outcome, "request denied by policy");
  c.app.close();
});

test("an ALLOW the KMS then refuses (sample ciphertext) is still an ALLOW", async () => {
  const c = await startConsole();
  decide = () => "kmsError";
  const { result } = (await (await c.run({ agentId: "developer-agent", action: "kms.Decrypt", keyId: "dev-key" })).json()) as { result: Record<string, unknown> };
  assert.equal(result.decision, "ALLOW");
  assert.equal(result.failed, true);
  assert.equal(result.outcome, "invalid ciphertext");
  c.app.close();
});

test("waits for a late audit event, and says so when none arrives", async () => {
  const c = await startConsole();
  auditDelayCalls = 3;
  const late = (await (await c.run({ agentId: "developer-agent", action: "kms.Encrypt", keyId: "dev-key" })).json()) as { result: Record<string, unknown> };
  assert.equal(late.result.decision, "ALLOW");

  auditDelayCalls = 1000;
  const none = (await (await c.run({ agentId: "developer-agent", action: "kms.Encrypt", keyId: "dev-key" })).json()) as { result: Record<string, unknown> };
  assert.equal(none.result.decision, null);
  assert.equal(none.result.requestId, null);
  c.app.close();
});

test("reuses an agent's token until shortly before it expires, and lists console runs", async () => {
  const c = await startConsole();
  const before = minted;
  await c.run({ agentId: "developer-agent", action: "kms.Encrypt", keyId: "dev-key" });
  await c.run({ agentId: "developer-agent", action: "kms.GetKeyMetadata", keyId: "dev-key" });
  assert.equal(minted - before, 1, "one token for two runs");
  c.clock.t += (RUN_TOKEN_TTL_SECONDS - 10) * 1000;
  await c.run({ agentId: "developer-agent", action: "kms.Encrypt", keyId: "dev-key" });
  assert.equal(minted - before, 2, "renewed before expiry");

  const runs = (await (await fetch(`${c.url}/api/console-runs`)).json()) as { jtiHashes: string[] };
  assert.deepEqual(runs.jtiHashes, [hashJti(`agent-${before + 1}`), hashJti(`agent-${before + 2}`)]);
  c.app.close();
});

test("rate-limits runs", async () => {
  const c = await startConsole();
  for (let i = 0; i < RUN_RATE_PER_MINUTE; i++) {
    assert.equal((await c.run({ agentId: "developer-agent", action: "kms.GetKeyMetadata", keyId: "dev-key" })).status, 200);
  }
  assert.equal((await c.run({ agentId: "developer-agent", action: "kms.GetKeyMetadata", keyId: "dev-key" })).status, 429);
  c.clock.t += 61_000;
  assert.equal((await c.run({ agentId: "developer-agent", action: "kms.GetKeyMetadata", keyId: "dev-key" })).status, 200);
  c.app.close();
});

test("refuses actions that change keys, bad input, and unregistered agents", async () => {
  const c = await startConsole();
  for (const body of [
    { agentId: "developer-agent", action: "kms.RotateKey", keyId: "dev-key" },
    { agentId: "developer-agent", action: "kms.CreateKey", keyId: "dev-key" },
    { agentId: "developer-agent", action: "policy.Activate", keyId: "dev-key" },
    { agentId: "Developer Agent", action: "kms.Encrypt", keyId: "dev-key" },
    { agentId: "developer-agent", action: "kms.Encrypt", keyId: "" },
    { agentId: "developer-agent", action: "kms.Encrypt", keyId: "dev-key", extra: 1 },
  ]) {
    assert.equal((await c.run(body)).status, 400, JSON.stringify(body));
  }
  assert.equal(seen.length, 0, "nothing reached the gateway");

  const ghost = await c.run({ agentId: "ghost-agent", action: "kms.Encrypt", keyId: "dev-key" });
  assert.equal(ghost.status, 400);
  assert.match(((await ghost.json()) as { error: string }).error, /not registered in the active policy version/);
  assert.equal(seen.filter((s) => s.method.startsWith("kms.")).length, 0, "no KMS call without an agent token");

  const form = await fetch(`${c.url}/api/run`, { method: "POST", headers: { "Content-Type": "text/plain" }, body: "{}" });
  assert.equal(form.status, 415);
  assert.equal((await fetch(`${c.url}/api/run`)).status, 405);
  c.app.close();
});

test("helpers: jti hash matches the gateway and Go, params carry samples only", () => {
  assert.equal(hashJti("abc"), "ba7816bf8f01cfea");
  assert.equal(hashJti(""), "");
  assert.equal(jtiOf("not-a-jwt"), "");
  assert.deepEqual(kmsParams({ agentId: "a", action: "kms.Decrypt", keyId: "dev-key" }), { KeyId: "kms:dev-key", CiphertextBlob: "orbitport-console-sample" });
  assert.equal(kmsParams({ agentId: "a", action: "kms.Sign", keyId: "k", signingAlgorithm: "ED25519" }).SigningAlgorithm, "ED25519");
  assert.equal(typeof parseRunRequest({ agentId: "a", action: "kms.Sign", keyId: "k", signingAlgorithm: "bad algo" }), "string");
});

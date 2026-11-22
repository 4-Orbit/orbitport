import { test } from "node:test";
import assert from "node:assert/strict";
import { createServer, type Server } from "node:http";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { AddressInfo } from "node:net";
import { createApp } from "../server/app.ts";
import type { GeminiAgent } from "../server/gemini-agent.ts";
import { GITHUB_TOOLS } from "../server/github-tools.ts";

const agentToken = `header.${Buffer.from('{"jti":"agent-run"}').toString("base64url")}.signature`;
const body = { agentId: "developer-agent", repository: "owner/repo", task: "fix the README", confirm: true };

async function fixture(agent?: GeminiAgent) {
  const dir = mkdtempSync(join(tmpdir(), "orbitport-agent-route-"));
  const tokenFile = join(dir, "operator.pat");
  writeFileSync(tokenFile, "operator-secret");
  const seen: { method: string; auth: string | null }[] = [];
  const gateway: Server = createServer(async (req, res) => {
    let raw = "";
    for await (const chunk of req) raw += chunk;
    const call = JSON.parse(raw) as { method: string };
    seen.push({ method: call.method, auth: req.headers.authorization ?? null });
    const result = call.method === "policy.IssueAgentToken" ? { token: agentToken } : call.method === "github.ListRepositories" ? { repositories: ["owner/repo"], mode: "mock" } : { decision: "ALLOW", status: "SUCCESS", requestId: "r" };
    res.writeHead(200, { "Content-Type": "application/json" }).end(JSON.stringify({ result }));
  });
  await new Promise<void>((r) => gateway.listen(0, "127.0.0.1", r));
  const app = createApp({ gatewayUrl: `http://127.0.0.1:${(gateway.address() as AddressInfo).port}`, tokenFile, geminiAgent: agent });
  await new Promise<void>((r) => app.listen(0, "127.0.0.1", r));
  const base = `http://127.0.0.1:${(app.address() as AddressInfo).port}`;
  return {
    seen,
    post: (changes: Record<string, unknown> = {}) => fetch(`${base}/api/github/gemini-agent`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ ...body, ...changes }) }),
    close: async () => {
      await new Promise<void>((r) => app.close(() => r()));
      await new Promise<void>((r) => gateway.close(() => r()));
      rmSync(dir, { recursive: true, force: true });
    },
  };
}

test("an unconfigured, unconfirmed or forged request never starts Gemini", async (t) => {
  const none = await fixture();
  t.after(none.close);
  assert.equal((await none.post()).status, 503);
  let runs = 0;
  const f = await fixture({ async run() { runs++; return { steps: [], final: null, stopped: "done", tools: [] }; } });
  t.after(f.close);
  for (const changes of [{ confirm: false }, { task: "" }, { agentId: "Not Valid" }, { repository: "nope" }, { token: "forged" }]) {
    assert.equal((await f.post(changes)).status, 400, JSON.stringify(changes));
  }
  assert.equal(runs, 0);
});

test("tool calls go out with the agent's token, never the operator's", async (t) => {
  const f = await fixture({
    async run({ scope, mode }, call) {
      assert.equal(mode, "mock");
      assert.deepEqual(scope, { agentId: "developer-agent", repository: "owner/repo" });
      const out = await call("github.issue.Create", { repository: "owner/repo", title: "t", body: "b" });
      assert.equal((out.result as { status: string }).status, "SUCCESS");
      // Non-GitHub methods are refused before the gateway.
      assert.ok((await call("policy.Activate", {})).error);
      return { steps: [], final: "ok", stopped: "done", tools: [] };
    },
  });
  t.after(f.close);
  const res = await f.post();
  assert.equal(res.status, 200);
  const issue = f.seen.find((s) => s.method === "github.issue.Create");
  assert.equal(issue?.auth, `Bearer ${agentToken}`);
  assert.ok(!f.seen.some((s) => s.method === "policy.Activate"));
  assert.equal(f.seen.find((s) => s.method === "policy.IssueAgentToken")?.auth, "Bearer operator-secret");
});

test("a preflight that allows nothing never asks Gemini", async (t) => {
  const dir = mkdtempSync(join(tmpdir(), "orbitport-agent-preflight-"));
  const tokenFile = join(dir, "operator.pat");
  writeFileSync(tokenFile, "operator-secret");
  let simulated = 0;
  const gateway: Server = createServer(async (req, res) => {
    let raw = "";
    for await (const chunk of req) raw += chunk;
    const call = JSON.parse(raw) as { method: string; params: { requests?: unknown[] } };
    const result = call.method === "policy.Simulate" ? (simulated++, { results: (call.params.requests ?? []).map(() => ({ decision: "DENY" })) }) : { repositories: ["owner/repo"], mode: "real" };
    res.writeHead(200, { "Content-Type": "application/json" }).end(JSON.stringify({ result }));
  });
  await new Promise<void>((r) => gateway.listen(0, "127.0.0.1", r));
  let offered: Set<string> | undefined;
  const app = createApp({
    gatewayUrl: `http://127.0.0.1:${(gateway.address() as AddressInfo).port}`,
    tokenFile,
    geminiAgent: { async run({ allowedMethods }) { offered = allowedMethods; return { steps: [], final: null, stopped: "nothing_allowed", tools: [] }; } },
  });
  await new Promise<void>((r) => app.listen(0, "127.0.0.1", r));
  t.after(async () => {
    await new Promise<void>((r) => app.close(() => r()));
    await new Promise<void>((r) => gateway.close(() => r()));
    rmSync(dir, { recursive: true, force: true });
  });
  const res = await fetch(`http://127.0.0.1:${(app.address() as AddressInfo).port}/api/github/gemini-agent`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
  assert.equal(res.status, 200);
  assert.equal(simulated, 1);
  assert.equal(offered?.size, 0);
});

test("tools the App installation can't serve are never offered, and none means no Gemini call", async (t) => {
  const dir = mkdtempSync(join(tmpdir(), "orbitport-agent-install-"));
  const tokenFile = join(dir, "operator.pat");
  writeFileSync(tokenFile, "operator-secret");
  let granted: Record<string, string> = { issues: "write", metadata: "read" };
  const gateway: Server = createServer(async (req, res) => {
    let raw = "";
    for await (const chunk of req) raw += chunk;
    const call = JSON.parse(raw) as { method: string; params: { requests?: unknown[] } };
    const result =
      call.method === "policy.Simulate" ? { results: (call.params.requests ?? []).map(() => ({ decision: "ALLOW" })) }
      : call.method === "github.GetInstallation" ? { mode: "real", permissions: granted, required: Object.fromEntries(GITHUB_TOOLS.map((tool) => [tool.method, tool.method === "github.contents.Read" ? { contents: "read" } : { issues: "write" }])) }
      : { repositories: ["owner/repo"], mode: "real" };
    res.writeHead(200, { "Content-Type": "application/json" }).end(JSON.stringify({ result }));
  });
  await new Promise<void>((r) => gateway.listen(0, "127.0.0.1", r));
  let offered: Set<string> | undefined;
  const app = createApp({
    gatewayUrl: `http://127.0.0.1:${(gateway.address() as AddressInfo).port}`,
    tokenFile,
    geminiAgent: { async run({ allowedMethods }) { offered = allowedMethods; return { steps: [], final: null, stopped: allowedMethods?.size ? "done" : "nothing_allowed", tools: [] }; } },
  });
  await new Promise<void>((r) => app.listen(0, "127.0.0.1", r));
  t.after(async () => {
    await new Promise<void>((r) => app.close(() => r()));
    await new Promise<void>((r) => gateway.close(() => r()));
    rmSync(dir, { recursive: true, force: true });
  });
  const post = () => fetch(`http://127.0.0.1:${(app.address() as AddressInfo).port}/api/github/gemini-agent`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
  type Out = { run: { skipped: { method: string; why: string; missing?: string[] }[]; final?: string } };
  let res = (await (await post()).json()) as Out;
  assert.ok(offered?.has("github.issue.Create"));
  assert.ok(!offered?.has("github.contents.Read"));
  assert.deepEqual(res.run.skipped.find((s) => s.method === "github.contents.Read"), { method: "github.contents.Read", why: "app", missing: ["contents: read"] });
  granted = {};
  res = (await (await post()).json()) as Out;
  assert.equal(offered?.size, 0);
  assert.match(String(res.run.final), /installation lacks contents: read, issues: write/);
});

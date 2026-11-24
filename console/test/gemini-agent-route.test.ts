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

/** Starts a run and polls until it finishes; returns the final state. */
async function runToEnd(base: string, payload: Record<string, unknown> = body): Promise<{ status: number; state: { id: string; status: string; run?: Record<string, unknown> } }> {
  const res = await fetch(`${base}/api/github/gemini-agent`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(payload) });
  if (res.status !== 202) return { status: res.status, state: (await res.json()) as never };
  let state = (await res.json()) as { id: string; status: string; run?: Record<string, unknown> };
  for (let i = 0; i < 200 && state.status !== "done"; i++) {
    await new Promise((r) => setTimeout(r, 10));
    state = (await (await fetch(`${base}/api/github/gemini-agent/runs/${state.id}`)).json()) as typeof state;
  }
  return { status: 202, state };
}

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
    base,
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
  const { status, state } = await runToEnd(f.base);
  assert.equal(status, 202);
  assert.equal(state.status, "done");
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
  const { status } = await runToEnd(`http://127.0.0.1:${(app.address() as AddressInfo).port}`);
  assert.equal(status, 202);
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
  const post = async () => (await runToEnd(`http://127.0.0.1:${(app.address() as AddressInfo).port}`)).state;
  type Out = { run: { skipped: { method: string; why: string; missing?: string[] }[]; final?: string } };
  let res = (await post()) as unknown as Out;
  assert.ok(offered?.has("github.issue.Create"));
  assert.ok(!offered?.has("github.contents.Read"));
  assert.deepEqual(res.run.skipped.find((s) => s.method === "github.contents.Read"), { method: "github.contents.Read", why: "app", missing: ["contents: read"] });
  granted = {};
  res = (await post()) as unknown as Out;
  assert.equal(offered?.size, 0);
  assert.match(String(res.run.final), /installation lacks contents: read, issues: write/);
});

test("one run at a time; a run can be stopped and read back", async (t) => {
  let release: () => void = () => undefined;
  const f = await fixture({
    async run({ signal }) {
      await new Promise<void>((resolve) => {
        release = resolve;
        signal?.addEventListener("abort", () => resolve());
      });
      return { steps: [], final: signal?.aborted ? "stopped" : "done", stopped: signal?.aborted ? "stopped" : "done", tools: [] };
    },
  });
  t.after(f.close);
  const first = await f.post();
  assert.equal(first.status, 202);
  const { id } = (await first.json()) as { id: string };
  assert.equal((await f.post()).status, 409, "a second run while one is in progress");
  const latest = (await (await fetch(`${f.base}/api/github/gemini-agent/runs/latest`)).json()) as { id: string; status: string };
  assert.equal(latest.id, id);
  assert.equal(latest.status, "running");
  const stop = await fetch(`${f.base}/api/github/gemini-agent/runs/${id}/stop`, { method: "POST" });
  assert.equal(stop.status, 200);
  let state = { status: "" , run: undefined as undefined | { stopped: string } };
  for (let i = 0; i < 100 && state.status !== "done"; i++) {
    await new Promise((r) => setTimeout(r, 10));
    state = (await (await fetch(`${f.base}/api/github/gemini-agent/runs/${id}`)).json()) as typeof state;
  }
  assert.equal(state.run?.stopped, "stopped");
  assert.equal((await fetch(`${f.base}/api/github/gemini-agent/runs/${id}/stop`, { method: "POST" })).status, 409, "stopping a finished run");
  assert.equal((await fetch(`${f.base}/api/github/gemini-agent/runs/nope`)).status, 404);
  release();
});

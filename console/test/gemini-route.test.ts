import { test } from "node:test";
import assert from "node:assert/strict";
import { createServer, type Server } from "node:http";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { AddressInfo } from "node:net";
import { createApp } from "../server/app.ts";
import { GeminiError, type GeminiIssueClient } from "../server/gemini.ts";

const agentToken = `header.${Buffer.from('{"jti":"gemini-agent-run"}').toString("base64url")}.signature`;
const baseRequest = { agentId: "developer-agent", repository: "owner/repo", prompt: "Report a login bug", confirmCreate: true };

/** decision: what the active policy says in the console's precheck (policy.Simulate). */
async function fixture(gemini?: GeminiIssueClient, decision: "ALLOW" | "DENY" = "ALLOW") {
  const dir = mkdtempSync(join(tmpdir(), "orbitport-gemini-route-"));
  const tokenFile = join(dir, "operator.pat");
  writeFileSync(tokenFile, "operator-secret");
  const seen: Array<{ method: string; auth: string | null; params: Record<string, unknown> }> = [];
  let prechecks = 0;
  const gateway: Server = createServer(async (req, res) => {
    let body = "";
    for await (const chunk of req) body += chunk;
    const call = JSON.parse(body) as { method: string; params: Record<string, unknown> };
    if (call.method === "policy.Simulate") {
      prechecks++;
      res.writeHead(200, { "Content-Type": "application/json" }).end(JSON.stringify({ result: { results: [{ decision }] } }));
      return;
    }
    seen.push({ method: call.method, auth: req.headers.authorization ?? null, params: call.params });
    const result = call.method === "policy.IssueAgentToken" ? { token: agentToken } :
      { decision: "ALLOW", status: "SUCCESS", requestId: "issue-1", mode: "mock", issueNumber: 1 };
    res.writeHead(200, { "Content-Type": "application/json" }).end(JSON.stringify({ result }));
  });
  await new Promise<void>((resolve) => gateway.listen(0, "127.0.0.1", resolve));
  const gatewayUrl = `http://127.0.0.1:${(gateway.address() as AddressInfo).port}`;
  const app = createApp({ gatewayUrl, tokenFile, gemini });
  await new Promise<void>((resolve) => app.listen(0, "127.0.0.1", resolve));
  const base = `http://127.0.0.1:${(app.address() as AddressInfo).port}`;
  return { base, seen, tokenFile, prechecks: () => prechecks, close: async () => {
    await new Promise<void>((resolve) => app.close(() => resolve()));
    await new Promise<void>((resolve) => gateway.close(() => resolve()));
    rmSync(dir, { recursive: true, force: true });
  } };
}

const submit = (base: string, changes: Record<string, unknown> = {}) => fetch(`${base}/api/github/gemini-issues`, {
  method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ ...baseRequest, ...changes }),
});

test("missing key, missing confirmation, and forged fields stop before Gemini", async (t) => {
  const absent = await fixture(); t.after(absent.close);
  assert.equal((await submit(absent.base)).status, 503);
  let proposals = 0;
  const f = await fixture({ async proposeIssue() { proposals++; return { title: "A", body: "B" }; } }); t.after(f.close);
  assert.equal((await submit(f.base, { confirmCreate: false })).status, 400);
  assert.equal((await submit(f.base, { token: "forged" })).status, 400);
  assert.equal((await submit(f.base, { repository: "owner/../other" })).status, 400);
  assert.equal(proposals, 0); assert.equal(f.seen.length, 0);
});

test("one Gemini proposal uses the existing agent-token GitHub issue path", async (t) => {
  let proposals = 0;
  const f = await fixture({ async proposeIssue(input) {
    proposals++;
    assert.deepEqual(input, { prompt: baseRequest.prompt, repository: baseRequest.repository });
    return { title: "Fix login", body: "The button does not respond.", agentId: "security-agent", repository: "other/repo" };
  } }); t.after(f.close);
  const response = await submit(f.base);
  assert.equal(response.status, 200);
  const body = await response.json() as { result: { status: string }; proposal: { title: string } };
  assert.equal(body.result.status, "SUCCESS");
  assert.equal(body.proposal.title, "Fix login");
  assert.equal(proposals, 1);
  assert.deepEqual(f.seen.map((v) => v.method), ["policy.IssueAgentToken", "github.issue.Create"]);
  assert.equal(f.seen[0].auth, "Bearer operator-secret");
  assert.equal(f.seen[1].auth, `Bearer ${agentToken}`);
  assert.deepEqual(f.seen[1].params, { repository: "owner/repo", title: "Fix login", body: "The button does not respond." });
  assert.ok(!JSON.stringify(body).includes("operator-secret"));
  assert.ok(!JSON.stringify(body).includes(agentToken));
});

test("Gemini HTTP errors and invalid proposals never issue an agent PAT", async (t) => {
  let issue: "error" | "invalid" = "error";
  const f = await fixture({ async proposeIssue() { if (issue === "error") throw new GeminiError("provider", 503); return { title: " ", body: "bad" }; } });
  t.after(f.close);
  const unavailable = await submit(f.base);
  assert.equal(unavailable.status, 503);
  assert.equal((await unavailable.json() as { error: string }).error, "Gemini API HTTP 503 Service Unavailable");
  issue = "invalid";
  assert.equal((await submit(f.base)).status, 502);
  assert.equal(f.seen.length, 0);
});

test("Gemini tasks are limited before provider calls", async (t) => {
  let proposals = 0;
  const f = await fixture({ async proposeIssue() { proposals++; return { title: "A", body: "" }; } });
  t.after(f.close);
  for (let i = 0; i < 5; i++) assert.equal((await submit(f.base)).status, 200);
  assert.equal((await submit(f.base)).status, 429);
  assert.equal(proposals, 5);
});

test("an issue the active policy denies never reaches Gemini", async (t) => {
  let proposals = 0;
  const f = await fixture({ async proposeIssue() { proposals++; return { title: "A", body: "B" }; } }, "DENY");
  t.after(f.close);
  const res = await submit(f.base);
  assert.equal(res.status, 403);
  assert.match((await res.json() as { error: string }).error, /Gemini wasn't called/);
  assert.equal(f.prechecks(), 1);
  assert.equal(proposals, 0);
  assert.equal(f.seen.length, 0, "no agent token, no issue");
});

import { test } from "node:test";
import assert from "node:assert/strict";
import { Runner, parseGithubIssueRequest } from "../server/run.ts";
import { ALLOWED_METHODS } from "../server/app.ts";

const valid = { agentId: "developer-agent", repository: "test-owner/test-repo", title: "Title", body: "Private description" };

test("GitHub request validation rejects identity overrides and unsafe paths", () => {
  assert.deepEqual(parseGithubIssueRequest(valid), valid);
  for (const bad of [{ ...valid, tenant: "other" }, { ...valid, token: "operator" }, { ...valid, repository: "test-owner/../other" }, { ...valid, title: " " }, { ...valid, agentId: "" }, { ...valid, title: "é".repeat(129) }]) {
    assert.equal(typeof parseGithubIssueRequest(bad), "string");
  }
  assert.equal(ALLOWED_METHODS.has("github.issue.Create"), false, "operator RPC forwarding must not create issues");
  assert.equal(ALLOWED_METHODS.has("github.ListRepositories"), true);
});

test("issue creation mints an agent credential; operator and token stay off results", async () => {
  const operator = "operator-secret";
  const token = `header.${Buffer.from(JSON.stringify({ jti: "github-run-token" })).toString("base64url")}.signature`;
  const seen: { method: string; auth: string | null; params: Record<string, unknown> }[] = [];
  const result = { decision: "DENY", status: "DENIED", requestId: "request-1", mode: "mock", githubCalled: false };
  const runner = new Runner({ gatewayUrl: "http://gateway", now: Date.now, sleep: async () => {}, fetchImpl: (async (_url, init) => {
    const b = JSON.parse(init?.body as string);
    const auth = new Headers(init?.headers).get("authorization");
    seen.push({ method: b.method, auth, params: b.params });
    return new Response(JSON.stringify({ result: b.method === "policy.IssueAgentToken" ? { token } : result }));
  }) as typeof fetch });
  assert.deepEqual(await runner.createGithubIssue(operator, valid), result);
  assert.equal(seen[0].method, "policy.IssueAgentToken");
  assert.equal(seen[0].auth, `Bearer ${operator}`);
  assert.equal(seen[1].method, "github.issue.Create");
  assert.equal(seen[1].auth, `Bearer ${token}`);
  assert.deepEqual(seen[1].params, { repository: valid.repository, title: valid.title, body: valid.body });
  assert.equal(runner.consoleRuns().length, 1);
});

test("GitHub errors are not retried or converted to mock success", async () => {
  let calls = 0;
  const token = `header.${Buffer.from('{"jti":"run"}').toString("base64url")}.signature`;
  const runner = new Runner({ gatewayUrl: "http://gateway", now: Date.now, sleep: async () => {}, fetchImpl: (async (_url, init) => {
    calls++;
    const method = JSON.parse(init?.body as string).method;
    return new Response(JSON.stringify(method === "policy.IssueAgentToken" ? { result: { token } } : { error: { message: "GitHub plugin not configured" } }));
  }) as typeof fetch });
  await assert.rejects(runner.createGithubIssue("operator", valid), /GitHub plugin not configured/);
  assert.equal(calls, 2);
});

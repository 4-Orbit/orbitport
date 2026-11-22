import { test } from "node:test";
import assert from "node:assert/strict";
import { createGeminiAgent, MAX_TOOL_CALLS, toolResponse, type GithubCaller } from "../server/gemini-agent.ts";

type Part = Record<string, unknown>;
const call = (name: string, args: Record<string, unknown>, id = `c-${name}`): Part => ({ functionCall: { name, args, id }, thoughtSignature: `sig-${id}` });
const text = (t: string): Part => ({ text: t });

/** A fake Gemini that answers with the scripted turns and records each request. */
function fakeGemini(turns: Part[][] | ((n: number) => Part[]), status = 200) {
  const requests: { contents: { role: string; parts: Part[] }[]; systemInstruction: { parts: { text: string }[] } }[] = [];
  const fetchImpl = (async (_url: string, init?: RequestInit) => {
    requests.push(JSON.parse(String(init?.body)));
    const n = requests.length - 1;
    const parts = typeof turns === "function" ? turns(n) : turns[n] ?? [text("done")];
    return new Response(JSON.stringify({ candidates: [{ content: { role: "model", parts } }] }), { status, headers: { "Content-Type": "application/json" } });
  }) as typeof fetch;
  return { fetchImpl, requests };
}

const scope = { agentId: "developer-agent", repository: "owner/repo" };

test("each tool call is one gateway call with the fixed repository, and the result goes back to Gemini", async () => {
  const gemini = fakeGemini([[call("create_issue", { title: "Bug", body: "Steps" })], [text("Created issue 7.")]]);
  const calls: { method: string; params: Record<string, unknown> }[] = [];
  const caller: GithubCaller = async (method, params) => {
    calls.push({ method, params });
    return { result: { decision: "ALLOW", status: "SUCCESS", number: 7, requestId: "r1", determiningPolicies: ["p"] } };
  };
  const run = await createGeminiAgent({ apiKey: "k", fetchImpl: gemini.fetchImpl }).run({ task: "file a bug", scope, mode: "mock" }, caller);
  assert.deepEqual(calls, [{ method: "github.issue.Create", params: { repository: "owner/repo", title: "Bug", body: "Steps" } }]);
  assert.equal(run.stopped, "done");
  assert.equal(run.final, "Created issue 7.");
  assert.equal(run.steps[0].decision, "ALLOW");
  assert.equal(run.steps[0].number, 7);
  // Gemini's turn is sent back verbatim (thought signature kept), then the result.
  const second = gemini.requests[1].contents;
  assert.equal(second[1].parts[0].thoughtSignature, "sig-c-create_issue");
  const response = (second[2].parts[0] as { functionResponse: { name: string; id: string; response: Record<string, unknown> } }).functionResponse;
  assert.equal(response.name, "create_issue");
  assert.equal(response.id, "c-create_issue");
  assert.equal(response.response.decision, "ALLOW");
  assert.match(gemini.requests[0].systemInstruction.parts[0].text, /agent\/developer-agent\//);
});

test("a repository in the arguments is refused, not used", async () => {
  const gemini = fakeGemini([[call("create_issue", { title: "x", body: "y", repository: "other/repo" })], [text("stopped")]]);
  let calls = 0;
  const run = await createGeminiAgent({ apiKey: "k", fetchImpl: gemini.fetchImpl }).run({ task: "t", scope, mode: "mock" }, async () => (calls++, { result: {} }));
  assert.equal(calls, 0);
  assert.ok(run.steps[0].error);
});

test("a denial is reported to Gemini and recorded", async () => {
  const gemini = fakeGemini([[call("create_issue", { title: "x", body: "y" })], [text("I was denied.")]]);
  const run = await createGeminiAgent({ apiKey: "k", fetchImpl: gemini.fetchImpl }).run({ task: "t", scope, mode: "real" }, async () => ({
    result: { decision: "DENY", status: "DENIED", determiningPolicies: [], requestId: "r2" },
  }));
  assert.equal(run.steps[0].decision, "DENY");
  const response = (gemini.requests[1].contents[2].parts[0] as { functionResponse: { response: Record<string, unknown> } }).functionResponse.response;
  assert.equal(response.decision, "DENY");
});

test("unknown tools and gateway errors don't stop the run", async () => {
  const gemini = fakeGemini([[call("rm_rf", {})], [call("create_issue", { title: "x", body: "y" })], [text("ok")]]);
  const run = await createGeminiAgent({ apiKey: "k", fetchImpl: gemini.fetchImpl }).run({ task: "t", scope, mode: "mock" }, async () => ({ error: "gateway unreachable" }));
  assert.equal(run.steps.length, 2);
  assert.equal(run.steps[0].error, "unknown tool rm_rf");
  assert.equal(run.steps[1].error, "gateway unreachable");
  assert.equal(run.stopped, "done");
});

test("the run stops at the tool-call limit", async () => {
  const gemini = fakeGemini((n) => (n <= MAX_TOOL_CALLS ? [call("create_issue", { title: `t${n}`, body: "b" }, `c${n}`)] : [text("summary")]));
  let calls = 0;
  const run = await createGeminiAgent({ apiKey: "k", fetchImpl: gemini.fetchImpl }).run({ task: "t", scope, mode: "mock" }, async () => (calls++, { result: { decision: "ALLOW", status: "SUCCESS" } }));
  assert.equal(calls, MAX_TOOL_CALLS);
  assert.equal(run.stopped, "step_limit");
});

test("the run stops at the time limit", async () => {
  let t = 0;
  const gemini = fakeGemini((n) => [call("create_issue", { title: `t${n}`, body: "b" }, `c${n}`)]);
  const run = await createGeminiAgent({ apiKey: "k", fetchImpl: gemini.fetchImpl, now: () => (t += 50_000) }).run({ task: "t", scope, mode: "mock" }, async () => ({ result: { decision: "ALLOW", status: "SUCCESS" } }));
  assert.equal(run.stopped, "time_limit");
});

test("a Gemini HTTP error ends the run with the status only", async () => {
  const gemini = fakeGemini([[]], 403);
  const run = await createGeminiAgent({ apiKey: "k", fetchImpl: gemini.fetchImpl }).run({ task: "t", scope, mode: "mock" }, async () => ({ result: {} }));
  assert.equal(run.stopped, "gemini_error");
  assert.match(run.error ?? "", /HTTP 403/);
});

test("tool output is trimmed before Gemini sees it", () => {
  const big = toolResponse({ decision: "ALLOW", status: "SUCCESS", output: { content: "x".repeat(40_000) }, secretField: "no" });
  assert.equal(big.secretField, undefined);
  assert.ok(String(big.output).length < 17_000);
});

test("read tools map to github.contents.Read with the fixed repository", async () => {
  const gemini = fakeGemini([[call("read_file", { path: "README.md" }), call("list_directory", {}, "c2")], [text("read")]]);
  const calls: { method: string; params: Record<string, unknown> }[] = [];
  await createGeminiAgent({ apiKey: "k", fetchImpl: gemini.fetchImpl }).run({ task: "t", scope, mode: "mock" }, async (method, params) => (calls.push({ method, params }), { result: { decision: "ALLOW", status: "SUCCESS", output: { type: "file" } } }));
  assert.deepEqual(calls, [
    { method: "github.contents.Read", params: { repository: "owner/repo", path: "README.md" } },
    { method: "github.contents.Read", params: { repository: "owner/repo", path: "" } },
  ]);
});

test("comment_on_issue needs a positive issue number", async () => {
  const gemini = fakeGemini([[call("comment_on_issue", { number: -1, body: "x" }), call("comment_on_issue", { number: 3, body: "looks good" }, "c2")], [text("ok")]]);
  const calls: string[] = [];
  const run = await createGeminiAgent({ apiKey: "k", fetchImpl: gemini.fetchImpl }).run({ task: "t", scope, mode: "mock" }, async (method, params) => (calls.push(`${method} ${params.number}`), { result: { decision: "ALLOW", status: "SUCCESS" } }));
  assert.deepEqual(calls, ["github.issue.Comment 3"]);
  assert.ok(run.steps[0].error);
});

test("create_branch passes the branch and optional base", async () => {
  const gemini = fakeGemini([[call("create_branch", { branch: "agent/developer-agent/fix" }), call("create_branch", { branch: "agent/developer-agent/b", from: "dev" }, "c2")], [text("ok")]]);
  const calls: Record<string, unknown>[] = [];
  await createGeminiAgent({ apiKey: "k", fetchImpl: gemini.fetchImpl }).run({ task: "t", scope, mode: "mock" }, async (_m, params) => (calls.push(params), { result: { decision: "ALLOW", status: "SUCCESS" } }));
  assert.deepEqual(calls, [
    { repository: "owner/repo", branch: "agent/developer-agent/fix" },
    { repository: "owner/repo", branch: "agent/developer-agent/b", from: "dev" },
  ]);
});

test("commit_files sends whole-file changes and refuses malformed ones", async () => {
  const good = { branch: "agent/developer-agent/fix", message: "Fix typo", files: [{ path: "README.md", content: "try" }], deletes: ["old.txt"] };
  const gemini = fakeGemini([[call("commit_files", { ...good, files: [{ path: "a" }] }), call("commit_files", good, "c2")], [text("ok")]]);
  const calls: Record<string, unknown>[] = [];
  const run = await createGeminiAgent({ apiKey: "k", fetchImpl: gemini.fetchImpl }).run({ task: "t", scope, mode: "mock" }, async (_m, params) => (calls.push(params), { result: { decision: "ALLOW", status: "SUCCESS", sha: "abc" } }));
  assert.ok(run.steps[0].error);
  assert.deepEqual(calls, [{ repository: "owner/repo", ...good }]);
  assert.match(run.steps[1].summary, /README\.md, -old\.txt/);
});

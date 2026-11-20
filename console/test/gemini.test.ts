import { test } from "node:test";
import assert from "node:assert/strict";
import { createGeminiClient, GeminiError } from "../server/gemini.ts";

const task = { prompt: "Report the login bug", repository: "owner/repo" };
const proposed = { steps: [{ type: "function_call", name: "create_issue", arguments: { title: "Fix login", body: "The button does not respond." } }] };
const ok = (body: unknown) => new Response(JSON.stringify(body), { status: 200 });

test("Gemini receives only a task and proposes one issue without storing the interaction", async () => {
  let calls = 0;
  const client = createGeminiClient({ apiKey: "server-secret", fetchImpl: (async (url, init) => {
    calls++;
    assert.equal(url, "https://generativelanguage.googleapis.com/v1beta/interactions");
    assert.equal(new Headers(init?.headers).get("x-goog-api-key"), "server-secret");
    const request = JSON.parse(String(init?.body));
    assert.equal(request.model, "gemini-3.5-flash-lite");
    assert.equal(request.store, false);
    assert.equal(request.tools[0].name, "create_issue");
    assert.match(request.input, /Report the login bug/);
    assert.ok(!String(init?.body).includes("server-secret"));
    return ok(proposed);
  }) as typeof fetch });
  assert.deepEqual(await client.proposeIssue(task), { title: "Fix login", body: "The button does not respond." });
  assert.equal(calls, 1);
});

test("Gemini rejects missing, multiple, foreign, and malformed tool calls", async () => {
  const variants = [
    { steps: [] },
    { steps: [proposed.steps[0], proposed.steps[0]] },
    { steps: [{ type: "function_call", name: "other", arguments: proposed.steps[0].arguments }] },
    { steps: [{ type: "function_call", name: "create_issue", arguments: { title: "", body: "" } }] },
    { steps: [{ type: "function_call", name: "create_issue", arguments: { title: "A", body: "", repository: "other/repo" } }] },
  ];
  for (const variant of variants) {
    const client = createGeminiClient({ apiKey: "server-secret", fetchImpl: (async () => ok(variant)) as typeof fetch });
    await assert.rejects(client.proposeIssue(task), (error: unknown) => error instanceof GeminiError && error.kind === "proposal");
  }
});

test("Gemini treats malformed provider JSON shapes as a safe response error", async () => {
  const client = createGeminiClient({ apiKey: "server-secret", fetchImpl: (async () => ok({ steps: {} })) as typeof fetch });
  await assert.rejects(client.proposeIssue(task), (error: unknown) => error instanceof GeminiError && error.kind === "response");
});

test("Gemini retries one HTTP 503 and preserves final provider status", async () => {
  let calls = 0, waits = 0;
  const client = createGeminiClient({ apiKey: "server-secret", waitImpl: async () => { waits++; }, fetchImpl: (async () => {
    calls++;
    return new Response("", { status: 503 });
  }) as typeof fetch });
  await assert.rejects(client.proposeIssue(task), (error: unknown) => error instanceof GeminiError && error.httpStatus === 503 && error.message === "Gemini API HTTP 503 Service Unavailable");
  assert.equal(calls, 2);
  assert.equal(waits, 1);
});

test("Gemini does not retry authentication errors or expose response bodies", async () => {
  let calls = 0;
  const client = createGeminiClient({ apiKey: "server-secret", fetchImpl: (async () => {
    calls++;
    return new Response("server-secret private prompt", { status: 401 });
  }) as typeof fetch });
  await assert.rejects(client.proposeIssue(task), (error: unknown) => error instanceof GeminiError && error.httpStatus === 401 && !error.message.includes("server-secret"));
  assert.equal(calls, 1);
});

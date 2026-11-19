import { test } from "node:test";
import assert from "node:assert/strict";
import { RATE_LIMIT_RETRY_MS, rpc, RpcError } from "../src/api.ts";

// No real waiting in tests.
RATE_LIMIT_RETRY_MS.splice(0, RATE_LIMIT_RETRY_MS.length, 0, 0, 0);

function stubFetch(statuses: number[]): { calls: () => number } {
  let n = 0;
  globalThis.fetch = (async () => {
    const status = statuses[Math.min(n++, statuses.length - 1)];
    const body = status === 200 ? { result: { ok: true } } : { error: { message: status === 429 ? "rate-limited" : "boom", reason: status === 429 ? "rate_limited" : undefined } };
    return new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
  }) as typeof fetch;
  return { calls: () => n };
}

test("a rate-limited call is retried until it goes through", async () => {
  const f = stubFetch([429, 429, 200]);
  assert.deepEqual(await rpc("policy.Validate"), { ok: true });
  assert.equal(f.calls(), 3);
});

test("retries stop after the last wait, with the rate-limit error", async () => {
  const f = stubFetch([429]);
  await assert.rejects(rpc("policy.Validate"), (e: unknown) => e instanceof RpcError && e.status === 429);
  assert.equal(f.calls(), RATE_LIMIT_RETRY_MS.length + 1);
});

test("other errors are not retried", async () => {
  const f = stubFetch([502]);
  await assert.rejects(rpc("policy.Validate"), (e: unknown) => e instanceof RpcError && e.status === 502);
  assert.equal(f.calls(), 1);
});

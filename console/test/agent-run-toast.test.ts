import { test } from "node:test";
import assert from "node:assert/strict";
import { AgentRuns } from "../server/agent-runs.ts";
import { POLL_MS, TOAST_LINGER_MS } from "../src/agent-run-timing.ts";

test("the run registry reports progress, stops, and forgets old runs", async () => {
  let now = 0;
  const runs = new AgentRuns(() => now);
  let finish: () => void = () => undefined;
  const state = runs.start({ agentId: "a", repository: "o/r", mode: "mock" }, (signal, onStep) => {
    onStep([{ tool: "read_file", summary: "read README.md" }]);
    return new Promise((resolve) => {
      finish = () => resolve({ steps: [{ tool: "read_file", summary: "read README.md" }], final: "ok", stopped: signal.aborted ? "stopped" : "done", tools: [] });
    });
  });
  assert.equal(runs.active()?.id, state.id);
  assert.equal(runs.get(state.id)?.steps.length, 1);
  assert.ok(runs.stop(state.id));
  assert.equal(runs.get(state.id)?.status, "stopping");
  finish();
  await new Promise((r) => setTimeout(r, 0));
  assert.equal(runs.get(state.id)?.status, "done");
  assert.equal(runs.get(state.id)?.run?.stopped, "stopped");
  assert.equal(runs.active(), null);
  assert.equal(runs.stop(state.id), false);
  now = 11 * 60_000;
  runs.start({ agentId: "a", repository: "o/r", mode: "mock" }, async () => ({ steps: [], final: null, stopped: "done", tools: [] }));
  assert.equal(runs.get(state.id), null, "finished runs are kept 10 minutes");
});

test("the toast polls every second and lingers three seconds", () => {
  assert.equal(POLL_MS, 1000);
  assert.equal(TOAST_LINGER_MS, 3000);
});

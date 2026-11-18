import { test } from "node:test";
import assert from "node:assert/strict";
import { compareRun } from "../src/run-compare.ts";
import { cannotRun, RUN_ACTIONS } from "../src/run-actions.ts";
import { RUN_ACTIONS as SERVER_RUN_ACTIONS } from "../server/run.ts";
import type { RunResult } from "../src/types.ts";

const real = (decision: RunResult["decision"], policyVersion: number | null = 4): RunResult => ({
  decision,
  kmsCalled: decision === "ALLOW",
  outcome: "",
  failed: decision !== "ALLOW",
  determiningPolicies: [],
  policyVersion,
  requestId: "r",
  jtiHash: "h",
});

test("same version, same decision: agree", () => {
  assert.equal(compareRun({ decision: "DENY", source: "v4", simulatedTime: false }, real("DENY")).tone, "agree");
});

test("same version, now, different decision: a loud disagreement", () => {
  const c = compareRun({ decision: "ALLOW", source: "v4", simulatedTime: false }, real("DENY"));
  assert.equal(c.tone, "disagree");
  assert.match(c.message, /shouldn't happen/);
});

test("draft, other version, cache lag and simulated time explain a difference", () => {
  const draft = compareRun({ decision: "ALLOW", source: "draft", simulatedTime: false }, real("DENY"));
  assert.equal(draft.tone, "expected");
  assert.match(draft.message, /Save and activate the draft/);
  const lag = compareRun({ decision: "ALLOW", source: "v5", simulatedTime: false }, real("DENY"));
  assert.equal(lag.tone, "expected");
  assert.match(lag.message, /within about 5 seconds/);
  assert.equal(compareRun({ decision: "ALLOW", source: "v4", simulatedTime: true }, real("DENY")).tone, "expected");
});

test("agreement across sources is still noted", () => {
  const c = compareRun({ decision: "ALLOW", source: "draft", simulatedTime: false }, real("ALLOW"));
  assert.equal(c.tone, "agree");
  assert.match(c.message, /your draft/);
});

test("no active version on either side compares as the same source", () => {
  assert.equal(compareRun({ decision: "DENY", source: "none (platform policy only)", simulatedTime: false }, real("DENY", null)).tone, "agree");
  assert.equal(compareRun({ decision: "ALLOW", source: "none (platform policy only)", simulatedTime: false }, real("DENY", null)).tone, "disagree");
});

test("a missing audit event is unknown, not a disagreement", () => {
  assert.equal(compareRun({ decision: "ALLOW", source: "v4", simulatedTime: false }, real(null)).tone, "unknown");
});

test("only agents and key actions that don't change keys can run", () => {
  assert.equal(cannotRun({ agentId: "developer-agent", action: "kms.Encrypt", resource: { type: "Key", id: "dev-key" } }), null);
  assert.match(cannotRun({ action: "kms.Encrypt", resource: { id: "dev-key" } }) ?? "", /agents/);
  assert.notEqual(cannotRun({ agentId: "a", action: "kms.RotateKey", resource: { id: "k" } }), null);
  assert.notEqual(cannotRun({ agentId: "a", action: "kms_keystore.Get", resource: { type: "KeyStoreKey", id: "k" } }), null);
});

test("the browser offers exactly what the server allows", () => {
  assert.deepEqual([...RUN_ACTIONS], [...SERVER_RUN_ACTIONS]);
});

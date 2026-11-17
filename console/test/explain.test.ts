import { test } from "node:test";
import assert from "node:assert/strict";
import { explainText, partsText, type ExplainedRequest } from "../src/explain.ts";
import type { Explanation } from "../src/types.ts";

const line = (e: Explanation, r: ExplainedRequest) => {
  const t = explainText(e, r);
  return { headline: partsText(t.headline), details: t.details.map(partsText) };
};

// The first three are verbatim policy.Explain output from the 4Orbit stack
// (default template), so the console is tested against the engine's shapes.
const closest: Explanation = {
  decision: "DENY",
  kind: "closest",
  determiningPolicies: [],
  candidates: [
    { policyId: "security-rotate-dev-key", missing: [{ part: "principal", op: "in", entities: [{ type: "Role", id: "security" }] }] },
    { policyId: "developer-encrypt-dev-key", missing: [{ part: "action", op: "==", entities: [{ type: "Action", id: "kms.Encrypt" }] }] },
    {
      policyId: "security-rotate-demo-key",
      missing: [
        { part: "principal", op: "in", entities: [{ type: "Role", id: "security" }] },
        { part: "resource", op: "==", entities: [{ type: "Key", id: "demo-key" }] },
      ],
    },
  ],
  agentRoles: ["developer"],
};

const expired: Explanation = {
  decision: "DENY",
  kind: "expired",
  determiningPolicies: [],
  candidates: [
    { policyId: "developer-encrypt-demo-key", missing: [{ part: "condition" }], window: { kind: "expired", at: 1800000000 } },
    { policyId: "developer-encrypt-dev-key", missing: [{ part: "resource", op: "==", entities: [{ type: "Key", id: "dev-key" }] }] },
  ],
  agentRoles: ["developer"],
};

const noRule: Explanation = {
  decision: "DENY",
  kind: "noRule",
  determiningPolicies: [],
  candidates: [
    { policyId: "developer-encrypt-dev-key", missing: [{ part: "action", op: "==", entities: [{ type: "Action", id: "kms.Encrypt" }] }] },
    {
      policyId: "security-rotate-dev-key",
      missing: [
        { part: "principal", op: "in", entities: [{ type: "Role", id: "security" }] },
        { part: "action", op: "==", entities: [{ type: "Action", id: "kms.RotateKey" }] },
      ],
    },
  ],
  agentRoles: ["developer"],
};

const dev = (action: string, resource = "dev-key"): ExplainedRequest => ({ agentId: "developer-agent", action, resource });

test("closest rule names the missing role and what the agent has", () => {
  const t = line(closest, dev("kms.RotateKey"));
  assert.equal(t.headline, "No rule allows this. The closest is security-rotate-dev-key, but it needs the security role (it has developer).");
  assert.deepEqual(t.details, [
    "Related: developer-encrypt-dev-key covers only encrypt.",
    "Related: security-rotate-demo-key needs the security role (it has developer); covers only demo-key.",
  ]);
});

test("expired grant gives the end date", () => {
  const t = line(expired, dev("kms.Encrypt", "demo-key"));
  assert.match(t.headline, /^developer-encrypt-demo-key would allow this, but it stopped applying on .*2027/);
  assert.deepEqual(t.details, []);
});

test("no rule says what was asked in words", () => {
  const t = line(noRule, dev("kms.Decrypt"));
  assert.equal(t.headline, "No rule lets developer-agent decrypt with dev-key.");
  assert.equal(t.details[0], "Related: developer-encrypt-dev-key covers only encrypt.");
});

test("blocked by a tenant forbid names the overridden permit", () => {
  const t = line(
    {
      decision: "DENY",
      kind: "blocked",
      determiningPolicies: ["no-prod-for-developers"],
      blockedBy: [{ policyId: "no-prod-for-developers", platform: false }],
      candidates: [{ policyId: "developer-encrypt-prod-key", missing: [] }],
    },
    dev("kms.Encrypt", "prod-key"),
  );
  assert.equal(t.headline, "Blocked by no-prod-for-developers. A rule that forbids always wins over any rule that allows.");
  assert.deepEqual(t.details, ["Without it, developer-encrypt-prod-key would allow this."]);
});

test("blocked by a platform rule says it can't be changed", () => {
  const t = line(
    { decision: "DENY", kind: "blocked", determiningPolicies: ["platform.tenant-fence"], blockedBy: [{ policyId: "platform.tenant-fence", platform: true }] },
    dev("kms.Encrypt"),
  );
  assert.match(t.details[0], /can't be changed/);
});

test("not yet valid, false condition, and the simple kinds", () => {
  assert.match(
    line({ decision: "DENY", kind: "notYet", determiningPolicies: [], candidates: [{ policyId: "x", missing: [{ part: "condition" }], window: { kind: "notYet", at: 1900000000 } }] }, dev("kms.Sign"))
      .headline,
    /^x would allow this, but it only applies from .*2030/,
  );
  assert.match(
    line({ decision: "DENY", kind: "conditionFalse", determiningPolicies: [], candidates: [{ policyId: "tagged", missing: [{ part: "condition" }] }] }, dev("kms.Sign")).headline,
    /^tagged covers developer-agent, this action and this key, but its condition isn't met/,
  );
  assert.match(line({ decision: "DENY", kind: "unknownAgent", determiningPolicies: [] }, { agentId: "ghost", action: "kms.Encrypt", resource: "k" }).headline, /^ghost isn't declared/);
  assert.match(line({ decision: "DENY", kind: "noPolicy", determiningPolicies: [] }, dev("kms.Encrypt")).headline, /^No version is active/);
  assert.equal(
    line({ decision: "DENY", kind: "errored", determiningPolicies: [], erroredPolicies: ["overflows"] }, dev("kms.Encrypt")).headline,
    "A rule failed to evaluate (overflows), and Cedar denies on any error. The details are in the KMS plugin log.",
  );
  assert.match(line({ decision: "DENY", kind: "invalidRequest", determiningPolicies: [], message: "unknown action" }, dev("kms.Teleport")).headline, /malformed \(unknown action\)/);
  assert.equal(line({ decision: "ALLOW", kind: "allowed", determiningPolicies: ["developer-encrypt-dev-key"] }, dev("kms.Encrypt")).headline, "Allowed by developer-encrypt-dev-key.");
});

test("account principal and unknown actions read naturally", () => {
  assert.equal(line({ ...noRule, candidates: [] }, { action: "kms.Teleport", resource: "k" }).headline, "No rule lets the account kms.Teleport on k.");
});

test("rule ids are marked for chips, platform ones included", () => {
  const t = explainText(closest, dev("kms.RotateKey"));
  assert.deepEqual(
    t.headline.filter((p) => p.policy).map((p) => p.text),
    ["security-rotate-dev-key"],
  );
});

import { test } from "node:test";
import assert from "node:assert/strict";
import { explainText, grantActions, partsText, withRole, type ExplainedRequest } from "../src/explain.ts";
import type { EntityJson, Explanation } from "../src/types.ts";

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

// ---- Grant this… ----

const requests = (e: Explanation, r: ExplainedRequest) => grantActions(e, r).map((a) => a.request);

test("closest: a rule for this agent first, then its role, then joining the missing role", () => {
  const actions = grantActions(closest, dev("kms.RotateKey"));
  assert.deepEqual(
    actions.map((a) => a.request),
    [
      { kind: "newRule", rule: { effect: "permit", who: { kind: "agent", id: "developer-agent" }, can: ["kms.RotateKey"], on: { kind: "keys", ids: ["dev-key"] } } },
      { kind: "newRule", rule: { effect: "permit", who: { kind: "role", id: "developer" }, can: ["kms.RotateKey"], on: { kind: "keys", ids: ["dev-key"] } } },
      { kind: "addRole", agentId: "developer-agent", role: "security" },
    ],
  );
  assert.equal(actions[0].label, "Grant this: let developer-agent rotate dev-key…");
  assert.match(actions[2].hint ?? "", /everything else the security role can do/);
});

test("no rule: offer new rules but never joining a role", () => {
  assert.deepEqual(
    requests(noRule, dev("kms.Decrypt")).map((r) => r.kind),
    ["newRule", "newRule"],
  );
});

test("expired: extend the rule that lapsed", () => {
  const [a] = grantActions(expired, dev("kms.Encrypt", "demo-key"));
  assert.deepEqual(a.request, { kind: "editRule", policyId: "developer-encrypt-demo-key" });
  assert.match(a.label, /^Extend developer-encrypt-demo-key/);
});

test("blocked: edit tenant forbids, never platform rules", () => {
  const e: Explanation = {
    decision: "DENY",
    kind: "blocked",
    determiningPolicies: ["no-prod-for-developers", "platform.tenant-fence"],
    blockedBy: [
      { policyId: "no-prod-for-developers", platform: false },
      { policyId: "platform.tenant-fence", platform: true },
    ],
  };
  assert.deepEqual(requests(e, dev("kms.Encrypt", "prod-key")), [{ kind: "editRule", policyId: "no-prod-for-developers" }]);
});

test("nothing to grant for the account, non-key resources, or engine problems", () => {
  assert.deepEqual(grantActions({ ...noRule, agentRoles: [] }, { action: "kms.Encrypt", resource: "dev-key" }), []);
  assert.deepEqual(grantActions(noRule, { agentId: "developer-agent", action: "kms_keystore.Get", resource: "x", resourceType: "KeyStoreKey" }), []);
  for (const kind of ["errored", "noPolicy", "invalidRequest", "unknownAgent", "allowed"] as const) {
    assert.deepEqual(grantActions({ decision: "DENY", kind, determiningPolicies: [] }, dev("kms.Encrypt")), [], kind);
  }
});

test("withRole adds the membership, declaring the role and agent when missing", () => {
  const base: EntityJson[] = [
    { uid: { type: "Role", id: "developer" }, attrs: {}, parents: [] },
    { uid: { type: "Agent", id: "developer-agent" }, attrs: {}, parents: [{ type: "Role", id: "developer" }] },
  ];
  const next = withRole(base, "developer-agent", "security");
  assert.deepEqual(next.find((e) => e.uid.id === "developer-agent")?.parents, [
    { type: "Role", id: "developer" },
    { type: "Role", id: "security" },
  ]);
  assert.ok(next.some((e) => e.uid.type === "Role" && e.uid.id === "security"), "role declared");
  assert.equal(withRole(next, "developer-agent", "security"), next, "no change when already a member");
  const fresh = withRole(base, "new-agent", "developer");
  assert.deepEqual(fresh.at(-1), { uid: { type: "Agent", id: "new-agent" }, attrs: {}, parents: [{ type: "Role", id: "developer" }] });
  assert.equal(fresh.filter((e) => e.uid.type === "Role").length, 1, "existing role not duplicated");
});

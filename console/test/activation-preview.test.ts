import { test } from "node:test";
import assert from "node:assert/strict";
import { changeSummary, decisionChanges, issueRequests } from "../src/activation-preview.ts";

test("one issue request per agent and repository, agents deduplicated and sorted", () => {
  const r = issueRequests(["b", "a", "b"], ["o/x", "o/y"]);
  assert.deepEqual(
    r.map((q) => `${q.agentId} ${q.resource.id}`),
    ["a o/x", "a o/y", "b o/x", "b o/y"],
  );
  assert.ok(r.every((q) => q.action === "github.issue.Create" && q.resource.type === "Repository"));
  assert.deepEqual(issueRequests(["a"], []), []);
});

test("only requests whose decision changes are reported", () => {
  const requests = issueRequests(["a", "b"], ["o/x"]);
  const changes = decisionChanges(
    requests,
    [{ decision: "DENY" }, { decision: "ALLOW" }],
    [
      { decision: "ALLOW", determiningPolicies: ["a-create"] },
      { decision: "ALLOW", determiningPolicies: ["b-create"] },
    ],
  );
  assert.deepEqual(changes, [{ principal: "a", action: "github.issue.Create", resource: "o/x", before: "DENY", after: "ALLOW", afterPolicies: ["a-create"] }]);
});

test("mismatched simulation results are an error, not a silent no-change", () => {
  assert.throws(() => decisionChanges(issueRequests(["a"], ["o/x"]), [], []));
});

test("summary counts each direction", () => {
  const c = (after: "ALLOW" | "DENY") => ({ principal: "a", action: "x", resource: "r", before: after === "ALLOW" ? ("DENY" as const) : ("ALLOW" as const), after, afterPolicies: [] });
  assert.equal(changeSummary([]), "");
  assert.equal(changeSummary([c("ALLOW")]), "1 becomes ALLOW");
  assert.equal(changeSummary([c("ALLOW"), c("ALLOW"), c("DENY")]), "2 become ALLOW, 1 becomes DENY");
});

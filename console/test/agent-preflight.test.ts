import { test } from "node:test";
import assert from "node:assert/strict";
import { allowedMethods, appAllowedMethods, preflightRequests } from "../server/agent-preflight.ts";
import { GITHUB_TOOLS } from "../server/github-tools.ts";

test("every tool's action is checked, in the contexts a working agent meets", () => {
  const checks = preflightRequests("developer-agent", "owner/repo", GITHUB_TOOLS.map((t) => t.method));
  const methods = new Set(checks.map((c) => c.method));
  for (const t of GITHUB_TOOLS) assert.ok(methods.has(t.method), t.method);
  assert.ok(checks.every((c) => c.request.agentId === "developer-agent" && c.request.resource.id === "owner/repo" && c.request.action === c.method));
  const branch = checks.find((c) => c.method === "github.branch.Create")!.request.context!;
  assert.equal(branch.branch, "agent/developer-agent/task");
  assert.equal(branch.branchAgent, "developer-agent");
  assert.equal(branch.isDefaultBranch, false);
  // Reviews and merges are tried on someone else's pull request.
  const merge = checks.find((c) => c.method === "github.pr.Merge")!.request.context!;
  assert.notEqual(merge.headAgent, "developer-agent");
  assert.equal(checks.find((c) => c.method === "github.issue.Create")!.request.context, undefined);
});

test("a method is allowed when any of its checks is", () => {
  const checks = [{ method: "a" }, { method: "a" }, { method: "b" }];
  assert.deepEqual([...allowedMethods(checks, [{ decision: "DENY" }, { decision: "ALLOW" }, { decision: "DENY" }])!], ["a"]);
  assert.deepEqual([...allowedMethods(checks, [{ decision: "DENY" }, { decision: "DENY" }, { decision: "DENY" }])!], []);
  assert.equal(allowedMethods(checks, null), null);
  assert.equal(allowedMethods(checks, [{ decision: "ALLOW" }]), null);
});

test("the installation's grants decide which methods can run", () => {
  const required = { "github.issue.Create": { issues: "write" }, "github.commit.Create": { metadata: "read", contents: "write" }, "github.pr.Get": { contents: "read", pull_requests: "read" } };
  const { allowed, missing } = appAllowedMethods(Object.keys(required), required, { issues: "write", metadata: "read", contents: "read", pull_requests: "write" });
  assert.deepEqual([...allowed].sort(), ["github.issue.Create", "github.pr.Get"]);
  assert.deepEqual(missing, { "github.commit.Create": ["contents: write"] });
  // write covers read; unknown methods aren't blocked.
  assert.ok(appAllowedMethods(["x"], required, {}).allowed.has("x"));
});

import { test } from "node:test";
import assert from "node:assert/strict";
import { needsHelp, stepHelp } from "../src/agent-step-help.ts";

const ctx = { repository: "4-Orbit/orbitport-issue-test", agentId: "developer-agent" };

test("only steps that didn't succeed get help", () => {
  assert.equal(needsHelp({ tool: "t", summary: "", decision: "ALLOW", status: "SUCCESS" }), false);
  assert.equal(needsHelp({ tool: "t", summary: "", decision: "ALLOW", status: "REFUSED" }), true);
  assert.equal(needsHelp({ tool: "t", summary: "", decision: "DENY", status: "DENIED" }), true);
  assert.equal(needsHelp({ tool: "t", summary: "", error: "bad args" }), true);
});

test("each kind of failure gets its own explanation", () => {
  assert.match(stepHelp({ tool: "t", summary: "", decision: "DENY", status: "DENIED", determiningPolicies: [] }, ctx).meaning, /default deny/);
  assert.match(stepHelp({ tool: "t", summary: "", error: "path is required" }, ctx).title, /never sent/);
  const perm = stepHelp({ tool: "t", summary: "", decision: "ALLOW", status: "REFUSED", reason: "GitHub didn't issue a token with contents: read for x (HTTP 422)" }, ctx);
  assert.match(perm.title, /permission/);
  assert.ok(perm.fixes.some((f) => /accept/.test(f)));
  assert.match(stepHelp({ tool: "t", summary: "", decision: "ALLOW", status: "REFUSED", reason: "GitHub refused the pull request: head invalid" }, ctx).fixes.join(" "), /Contents: read/);
  assert.match(stepHelp({ tool: "t", summary: "", decision: "ALLOW", status: "ERROR", reason: "the GitHub request failed" }, ctx).title, /unknown/);
});

test("a 403 points at App permissions and repository rules", () => {
  const help = stepHelp({ tool: "t", summary: "", decision: "ALLOW", status: "ERROR", reason: "GitHub request refused (HTTP 403); check GitHub before retrying" }, ctx);
  assert.match(help.title, /refused the App's token/);
  assert.ok(help.fixes.some((f) => /rulesets/.test(f)));
});

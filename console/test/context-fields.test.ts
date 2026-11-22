import { test } from "node:test";
import assert from "node:assert/strict";
import { contextForRequest, contextProblem, defaultContext, parseSet } from "../src/context-fields.ts";
import type { ContextField } from "../src/types.ts";

const fields: ContextField[] = [
  { name: "branch", type: "String", doc: "" },
  { name: "isDefaultBranch", type: "Bool", doc: "" },
  { name: "humanApprovals", type: "Long", doc: "" },
  { name: "paths", type: "Set<String>", doc: "" },
  { name: "headAgent", type: "Agent", optional: true, doc: "" },
];

test("defaults cover every required field and leave optional ones unset", () => {
  assert.deepEqual(defaultContext(fields), { branch: "", isDefaultBranch: false, humanApprovals: 0, paths: [] });
  assert.deepEqual(defaultContext(undefined), {});
});

test("the request carries declared fields only, and no context for actions without one", () => {
  assert.equal(contextForRequest([], { x: 1 }), undefined);
  assert.deepEqual(contextForRequest(fields, { ...defaultContext(fields), headAgent: "", extra: true }), { branch: "", isDefaultBranch: false, humanApprovals: 0, paths: [] });
  assert.deepEqual(contextForRequest(fields, { ...defaultContext(fields), headAgent: "dev" }).headAgent, "dev");
});

test("problems and set parsing", () => {
  assert.equal(contextProblem(fields, defaultContext(fields)), null);
  assert.match(contextProblem(fields, {}) ?? "", /branch/);
  assert.match(contextProblem(fields, { ...defaultContext(fields), humanApprovals: 1.5 }) ?? "", /whole/);
  assert.deepEqual(parseSet(" a.go, ,b/c.go "), ["a.go", "b/c.go"]);
});

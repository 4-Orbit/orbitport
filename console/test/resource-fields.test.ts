import { test } from "node:test";
import assert from "node:assert/strict";
import { actionGroups, defaultResource, resourceField, resourceForAction, resourceProblem, resourceTypeOf, splitAgents } from "../src/resource-fields.ts";
import type { ActionInfo } from "../src/types.ts";

const schema: ActionInfo[] = [
  { name: "kms.Encrypt", group: "KMS", resourceType: "Key" },
  { name: "kms.Decrypt", group: "KMS", resourceType: "Key" },
  { name: "github.issue.Create", group: "GitHub", resourceType: "Repository" },
];
const options = { keys: ["a-key", "dev-key", "z-key"], repositories: ["octo/repo", "octo/other"] };

test("an action's resource type comes from the schema, else the rule model", () => {
  assert.equal(resourceTypeOf("github.issue.Create", schema), "Repository");
  assert.equal(resourceTypeOf("kms.Encrypt", schema), "Key");
  // Before the schema loads, CAPABILITIES marks the Repository actions.
  assert.equal(resourceTypeOf("github.issue.Create", null), "Repository");
  assert.equal(resourceTypeOf("kms.Decrypt", undefined), "Key");
  assert.equal(resourceTypeOf("kms.Unknown", schema), "Key");
});

test("switching from a key action to GitHub resets the key to a repository", () => {
  assert.equal(resourceForAction("Key", "Repository", "dev-key", options), "octo/repo");
});

test("switching from GitHub back to a key action resets to a key", () => {
  assert.equal(resourceForAction("Repository", "Key", "octo/other", options), "dev-key");
});

test("the resource is kept while the type stays the same", () => {
  assert.equal(resourceForAction("Key", "Key", "z-key", options), "z-key");
  assert.equal(resourceForAction("Repository", "Repository", "octo/other", options), "octo/other");
  // Even an unlisted value someone typed on purpose.
  assert.equal(resourceForAction("Key", "Key", "not-in-kms", options), "not-in-kms");
});

test("defaults: dev-key when it exists, else the first; empty when nothing is known", () => {
  assert.equal(defaultResource("Key", { keys: ["b", "a"], repositories: [] }), "b");
  assert.equal(defaultResource("Key", { keys: [], repositories: ["o/r"] }), "");
  assert.equal(defaultResource("Repository", { keys: ["dev-key"], repositories: [] }), "");
  assert.equal(resourceForAction("Key", "Repository", "dev-key", { keys: ["dev-key"], repositories: [] }), "");
});

test("field labels and problems follow the resource type", () => {
  assert.deepEqual(resourceField("Key"), { label: "Resource (key)", placeholder: "key alias", noun: "key" });
  assert.deepEqual(resourceField("Repository"), { label: "Resource (repository)", placeholder: "owner/repo", noun: "repository" });
  assert.equal(resourceProblem("Key", "dev-key"), null);
  assert.match(resourceProblem("Key", "") ?? "", /key/);
  assert.equal(resourceProblem("Repository", "octo/repo"), null);
  assert.match(resourceProblem("Repository", "dev-key") ?? "", /owner\/repo/);
});

test("actions are grouped in schema order", () => {
  assert.deepEqual(actionGroups(schema), [
    ["KMS", ["kms.Encrypt", "kms.Decrypt"]],
    ["GitHub", ["github.issue.Create"]],
  ]);
});

test("agents split into registered and no longer registered", () => {
  assert.deepEqual(splitAgents(["ops", "dev"], ["old", "dev", "", "old", "batch"]), { registered: ["dev", "ops"], removed: ["batch", "old"] });
  assert.deepEqual(splitAgents([], ["a"]), { registered: [], removed: ["a"] });
});

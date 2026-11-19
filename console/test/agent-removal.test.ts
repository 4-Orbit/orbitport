import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { removePolicies, rulesNamingAgent } from "../src/agent-removal.ts";
import type { PolicyInfo } from "../src/types.ts";

// Engine JSON for each Cedar text comes from the shared rule fixtures.
const fixtures = JSON.parse(readFileSync(new URL("./fixtures/rules.json", import.meta.url), "utf8")) as { name: string; cedar: string; json: unknown }[];
const byName = (n: string) => fixtures.find((f) => f.name === n)!;

/** A policy text made of these fixtures, with the spans validation would report. */
function draft(names: string[]): { text: string; infos: PolicyInfo[] } {
  let text = "";
  const infos: PolicyInfo[] = [];
  for (const n of names) {
    const f = byName(n);
    if (text) text += "\n\n";
    const start = text.length;
    text += f.cedar.trim();
    infos.push({ id: n, effect: f.cedar.includes("forbid") ? "forbid" : "permit", json: f.json, start, end: text.length, line: text.slice(0, start).split("\n").length });
  }
  return { text: text + "\n", infos };
}

test("a builder rule for exactly the agent is owned by it; others are untouched", () => {
  const { text, infos } = draft(["developer-encrypt-dev-key", "ci-sign-release-keys", "admin-agent-everything"]);
  const r = rulesNamingAgent(infos, text, "ci-agent");
  assert.deepEqual(r.owned.map((p) => p.id), ["ci-sign-release-keys"]);
  assert.deepEqual(r.mentions, []);
});

test("custom Cedar that names the agent is listed for review, not owned", () => {
  const { text, infos } = draft(["principal-in-agent", "developer-encrypt-dev-key"]);
  const r = rulesNamingAgent(infos, text, "a");
  assert.deepEqual(r.owned, []);
  assert.deepEqual(r.mentions.map((p) => p.id), ["principal-in-agent"]);
});

test("an agent no rule names has nothing to delete", () => {
  const { text, infos } = draft(["developer-encrypt-dev-key", "ci-sign-release-keys"]);
  assert.deepEqual(rulesNamingAgent(infos, text, "dead-agent"), { owned: [], mentions: [] });
  // An id that is a prefix of another agent's id does not match it.
  assert.deepEqual(rulesNamingAgent(infos, text, "ci").mentions, []);
});

test("removing owned rules leaves the rest of the text intact", () => {
  const { text, infos } = draft(["developer-encrypt-dev-key", "ci-sign-release-keys", "admin-agent-everything"]);
  const out = removePolicies(text, [infos[1], infos[2]]);
  assert.equal(out, byName("developer-encrypt-dev-key").cedar.trim() + "\n\n");
  assert.equal(removePolicies(text, []), text);
});

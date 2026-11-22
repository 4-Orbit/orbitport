// Regenerates test/fixtures/rules.json (rules + the Cedar the builder writes).
// Then run, from plugins/: go test ./pkg/core/authz -run TestConsoleRuleFixtures -update
// which validates every policy against the schema and fills in the engine's JSON.
import { writeFileSync, readFileSync, existsSync } from "node:fs";
import { toCedar, type Rule } from "../src/rules.ts";

const rules: Rule[] = [
  { id: "github-developer-create-issues", effect: "permit", who: { kind: "role", id: "developer" }, can: ["github.issue.Create"], on: { kind: "repositories", ids: ["4-Orbit/orbitport-issue-test"] } },
  { id: "github-agent-create-until", effect: "permit", who: { kind: "agent", id: "developer-agent" }, can: ["github.issue.Create"], on: { kind: "repositories", ids: ["4-Orbit/orbitport-issue-test", "4-Orbit/another-test"] }, until: 1800000000 },
  { id: "github-block-agent-issues", effect: "forbid", who: { kind: "anyAgent" }, can: ["github.issue.Create"], on: { kind: "repositories", ids: ["4-Orbit/private-repo"] } },
  { id: "github-developer-read-and-create", effect: "permit", who: { kind: "role", id: "developer" }, can: ["github.issue.Create", "github.contents.Read", "github.issue.Comment", "github.branch.Create", "github.commit.Create"], on: { kind: "repositories", ids: ["4-Orbit/orbitport-issue-test"] } },
  { id: "developer-encrypt-dev-key", effect: "permit", who: { kind: "role", id: "developer" }, can: ["kms.Encrypt"], on: { kind: "keys", ids: ["dev-key"] } },
  { id: "ci-sign-release-keys", effect: "permit", who: { kind: "agent", id: "ci-agent" }, can: ["kms.Sign", "read"], on: { kind: "keys", ids: ["release-a", "release-b"] }, until: 1800000000 },
  { id: "deny-agents-prod", effect: "forbid", who: { kind: "anyAgent" }, can: [], on: { kind: "tag", key: "env", value: "prod" } },
  { id: "deny-anyone-rotate", effect: "forbid", who: { kind: "anyone" }, can: ["rotate"], on: { kind: "anyKey" } },
  { id: "ops-use-dev-tagged", effect: "permit", who: { kind: "role", id: "ops" }, can: ["use"], on: { kind: "tag", key: "env", value: "dev" }, until: 1799999999 },
  { id: "admin-agent-everything", effect: "permit", who: { kind: "agent", id: "admin-agent" }, can: [], on: { kind: "anyKey" } },
  { id: "security-rotate-or-create", effect: "permit", who: { kind: "role", id: "security" }, can: ["rotate", "admin"], on: { kind: "keys", ids: ["prod-key"] } },
];

// Valid Cedar the model must NOT claim to represent (shown as custom rules).
const custom = [
  `@id("github-unrestricted-resources") permit (principal is Agent, action == Action::"github.issue.Create", resource);`,
  `@id("github-every-action") forbid (principal is Agent, action, resource == Repository::"4-Orbit/private-repo");`,
  `@id("github-read-outside-secrets") permit (principal in Role::"developer", action == Action::"github.contents.Read", resource == Repository::"4-Orbit/orbitport-issue-test") unless { context.path like "secrets/*" };`,
  `@id("unless-clause") permit (principal in Role::"developer", action, resource) unless { resource.hasTag("env") };`,
  `@id("extra-annotation") @reason("audit") permit (principal in Role::"developer", action, resource);`,
  `@id("keys-and-tag") permit (principal in Role::"developer", action, resource == Key::"a") when { resource.hasTag("env") && resource.getTag("env") == "dev" };`,
  `@id("two-tags") permit (principal, action, resource) when { resource.hasTag("env") && resource.hasTag("team") && resource.getTag("team") == "x" };`,
  `@id("principal-in-agent") permit (principal == Agent::"a", action == Action::"kms_keystore.Get", resource);`,
  `@id("or-condition") permit (principal, action, resource) when { context.currentTime < 5 || context.currentTime > 10 };`,
];

const path = new URL("../test/fixtures/rules.json", import.meta.url);
const old = existsSync(path) ? (JSON.parse(readFileSync(path, "utf8")) as { cedar: string; json?: unknown }[]) : [];
const jsonFor = (cedar: string) => old.find((o) => o.cedar === cedar)?.json ?? null;

const fixtures = [
  ...rules.map((rule) => ({ name: rule.id, rule, cedar: toCedar(rule), json: jsonFor(toCedar(rule)) })),
  ...custom.map((cedar) => ({ name: /@id\("([^"]+)"\)/.exec(cedar)![1], rule: null, cedar, json: jsonFor(cedar) })),
];
writeFileSync(path, JSON.stringify(fixtures, null, 2) + "\n");
console.log(`wrote ${fixtures.length} fixtures`);

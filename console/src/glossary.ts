/**
 * One place for the console's vocabulary. Tooltips (<Term>), the Help page
 * and the status strip all read these, so a term means the same everywhere.
 */
export interface GlossaryEntry {
  term: string;
  short: string;
}

export const GLOSSARY = {
  draft: {
    term: "Draft",
    short:
      "What you're editing on the Policies page. It lives only in this browser, nobody else sees it, and the KMS ignores it. Undo works on it. Save it as a version to keep it.",
  },
  version: {
    term: "Version",
    short:
      "A permanent, numbered snapshot of your rules and agents (v1, v2, …), created only by “Save as new version”. Versions can't be edited or deleted, and saving one does not change what's enforced.",
  },
  active: {
    term: "Active version",
    short: "The one saved version the KMS enforces right now. Exactly one version is active at a time; change it with Activate on the Versions page.",
  },
  activate: {
    term: "Activate",
    short:
      "Makes a saved version the one the KMS enforces, within about 5 seconds. It runs your tests first and refuses if any fail, unless you deliberately force it.",
  },
  rollback: {
    term: "Roll back",
    short: "Activate an older version. Nothing is deleted, so you can always go back and forth between versions.",
  },
  rule: {
    term: "Rule",
    short: "One statement such as “developers can encrypt with dev-key”. Written in Cedar underneath; the Plain language view shows each one as a sentence.",
  },
  role: {
    term: "Role",
    short: "A named group of agents (developer, security…). Rules usually grant access to a role, so every agent in it gets that access.",
  },
  agent: {
    term: "Agent",
    short: "An AI agent or service that calls the KMS with its own short-lived agent token. An agent can do nothing until a rule allows it.",
  },
  accountToken: {
    term: "Account token",
    short: "A token without an agent name, such as the operator's. It always has full access to this tenant's keys (a platform rule) and is never limited by your rules.",
  },
  agentToken: {
    term: "Agent token",
    short: "A short-lived token that names one agent. The KMS checks your active rules on every request made with it. Mint one on the Agents page.",
  },
  platform: {
    term: "Platform rules",
    short:
      "Three fixed rules you can't edit: account tokens keep owner access, nothing crosses tenants, and agents can never read or change policy. They apply together with your rules.",
  },
  defaultDeny: {
    term: "Default deny",
    short: "If no rule allows a request, it's denied. A “Blocks” rule wins over any “Allows” rule.",
  },
  test: {
    term: "Test",
    short: "A saved expectation such as “developer-agent must NOT rotate prod-key”. Activation is refused if a version breaks any test.",
  },
  shadow: {
    term: "Shadow mode",
    short: "A KMS setting where decisions are recorded but nothing is blocked. Useful for trying rules on real traffic.",
  },
  whyDenied: {
    term: "Why was this denied?",
    short:
      "Shown on every DENY in Simulate, Access and Activity: the rule that blocked it, the grant that expired, the closest rule and what it's missing, or that no rule covers it. Worked out by the same engine the KMS uses. “Grant this…” prepares the fix in your draft.",
  },
  runForReal: {
    term: "Run it for real",
    short:
      "On Simulate: sends the same request to the KMS as that agent, with sample data and a short-lived token the console mints, and shows the real decision beside the simulated one. Only for actions that don't change a key; marked “from console” on Activity.",
  },
  simulatedTime: {
    term: "Simulated time",
    short: "Ask “what would happen at this date?”, for example after an expiry. Only the simulator can change the time; the KMS always uses its real clock.",
  },
} satisfies Record<string, GlossaryEntry>;

export type GlossaryKey = keyof typeof GLOSSARY;

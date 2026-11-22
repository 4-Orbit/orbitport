export type Decision = "ALLOW" | "DENY";

export interface Health {
  gateway: "ok" | "unreachable";
  gatewayUrl: string;
  tokenPresent: boolean;
}

export interface EntityJson {
  uid: { type: string; id: string };
  attrs: Record<string, unknown>;
  parents: { type: string; id: string }[];
}

export interface Bundle {
  policies: string;
  entities: EntityJson[];
}

export interface Version {
  version: number;
  policies: string;
  entities: EntityJson[];
  message: string;
  author: string;
  createdAt: string;
}

export interface VersionInfo {
  version: number;
  message: string;
  author: string;
  createdAt: string;
  active: boolean;
}

export interface ActiveResult {
  exists: boolean;
  version?: Version;
  activation?: { version: number; activatedAt: string; activatedBy: string };
}

/** A trusted-context field an action declares (D-035). */
export interface ContextField {
  name: string;
  type: "String" | "Bool" | "Long" | "Set<String>" | "Agent";
  optional?: boolean;
  /** Where enforcement takes the value from. */
  doc: string;
}

export interface ActionInfo {
  name: string;
  group: string;
  resourceType: string;
  context?: ContextField[];
}

export interface SchemaInfo {
  schema: string;
  platformPolicies: string;
  platformPolicyIds: string[];
  actions: ActionInfo[];
  keyActions: string[];
}

export type Source = { version: number } | { draft: Bundle };

export interface Resource {
  type?: string;
  id: string;
  attrs?: Record<string, string>;
  tags?: Record<string, string>;
}

export interface SimRequest {
  agentId?: string;
  action: string;
  resource: Resource;
  /** What-if trusted context, for actions that declare it. */
  context?: Record<string, string | boolean | number | string[]>;
}

export interface SimResult {
  request: SimRequest;
  decision: Decision;
  determiningPolicies: string[];
  errored: boolean;
  diagnostics?: string[];
  /** Present on DENYs when simulated with explain: true. */
  explanation?: Explanation;
}

/** Why a request is denied, from the enforcement engine (authz.Explain). */
export type ExplanationKind =
  | "allowed"
  | "invalidRequest"
  | "noPolicy"
  | "errored"
  | "unknownAgent"
  | "blocked"
  | "expired"
  | "notYet"
  | "conditionFalse"
  | "closest"
  | "noRule";

export interface EntityRef {
  type: string;
  id: string;
}

/** One part of a rule the request does not satisfy. */
export interface Requirement {
  part: "principal" | "action" | "resource" | "condition";
  op?: "==" | "in" | "is" | "All";
  entities?: EntityRef[];
  entityType?: string;
}

/** A permit that would allow the request if its missing parts were met. */
export interface Candidate {
  policyId: string;
  missing: Requirement[];
  /** The request falls outside this rule's time window. */
  window?: { kind: "expired" | "notYet"; at: number };
}

export interface Explanation {
  decision: Decision;
  kind: ExplanationKind;
  determiningPolicies: string[];
  message?: string;
  erroredPolicies?: string[];
  blockedBy?: { policyId: string; platform: boolean }[];
  candidates?: Candidate[];
  agentRoles?: string[];
}

export interface ExplainResult {
  source: string;
  /** The version explained against; 0 = draft or none. */
  version: number;
  at: number;
  simulatedTime: boolean;
  explanation: Explanation;
}

export interface SimulateResult {
  source: string;
  at: number;
  simulatedTime: boolean;
  results: SimResult[];
}

export interface Cell {
  principal: string;
  action: string;
  resource: string;
  decision: Decision;
  determiningPolicies: string[];
}

export interface PrincipalSummary {
  /** "" = the account principal. */
  principal: string;
  roles: string[];
  allowedKeys: number;
  byAction: Record<string, number>;
}

export interface MatrixResult {
  source: string;
  at: number;
  simulatedTime: boolean;
  principals: string[];
  actions: string[];
  keys: string[];
  agentRoles: Record<string, string[]>;
  cells: Cell[];
  /** Present when requested with summary: true (no cells then). */
  summary?: PrincipalSummary[];
  /** Paging: totals over the whole key / principal lists and this page's offsets. */
  totalKeys: number;
  keyOffset: number;
  totalPrincipals: number;
  agentOffset: number;
}

export interface CellChange {
  principal: string;
  action: string;
  resource: string;
  before: Decision;
  after: Decision;
  afterPolicies: string[];
}

export interface DiffResult {
  from: string;
  to: string;
  changes: CellChange[];
}

export interface Problem {
  severity: "error" | "warning";
  policyId?: string;
  line?: number;
  column?: number;
  message: string;
}

/** One policy as the engine parsed it; start/end index the source text. */
export interface PolicyInfo {
  id: string;
  effect: "permit" | "forbid";
  json: unknown;
  start: number;
  end: number;
  line: number;
}

export interface ValidateResult {
  ok: boolean;
  problems: Problem[];
  /** null when the text does not parse. */
  policies?: PolicyInfo[] | null;
  summary?: { policyIds: string[]; agents: string[]; roles: string[]; agentRoles: Record<string, string[]>; referencedKeys: string[] };
}

export interface TestCase {
  name: string;
  agentId?: string;
  action: string;
  context?: Record<string, string | boolean | number | string[]>;
  resource: Resource;
  at?: number;
  expect: Decision;
}

export interface TestResult {
  name: string;
  expect: Decision;
  actual: Decision;
  pass: boolean;
  determiningPolicies: string[];
}

export interface TestReport {
  source: string;
  total: number;
  passed: number;
  failed: number;
  results: TestResult[];
}

export interface ActivateResult {
  activated: boolean;
  version?: number;
  forced?: boolean;
  reason?: string;
  tests: TestReport;
}

export interface AuditEvent {
  githubCalled?: boolean;
  githubMode?: "mock" | "real";
  githubResult?: { status: string; issueNumber?: number; number?: number; sha?: string; ref?: string };
  /** The trusted context the decision used (GitHub actions, D-035). */
  context?: Record<string, string | boolean | number | string[]>;
  stage?: "decision" | "outcome";
  ts: string;
  requestId: string;
  tenant: string;
  principal: string;
  action: string;
  resource: string;
  decision: Decision;
  determiningPolicies: string[];
  authzErrors?: string[];
  policyVersion: number;
  mode: "enforce" | "shadow";
  kmsCalled: boolean;
  kmsOperation?: string;
  kmsResult?: { status: "SUCCESS" | "ERROR"; errorCode?: string };
  jtiHash?: string;
}

export interface AuditFilter {
  /** nextCursor of the previous page; empty = newest. */
  cursor?: string;
  limit?: number;
  agentId?: string;
  decision?: Decision | "";
  action?: string;
  resource?: string;
  /** Short token hash: the events of one credential. */
  jtiHash?: string;
}

export interface AuditResult {
  events: AuditEvent[];
  /** Cursor for older matching events; "" = none left. */
  nextCursor: string;
  summary: { total: number; allow: number; deny: number; kmsCalled: number; errors: number };
}

/** POST /api/run: one real KMS request made as an agent by the console. */
export interface RunResult {
  /** The KMS's decision, from its audit event; null if no event was found. */
  decision: Decision | null;
  kmsCalled: boolean | null;
  /** What happened, never the payload. */
  outcome: string;
  failed: boolean;
  determiningPolicies: string[];
  /** The version the KMS enforced. */
  policyVersion: number | null;
  requestId: string | null;
  jtiHash: string;
}

export interface KeyInfo {
  keyId: string;
  alias: string;
  scheme: string;
  keySpec: string;
  keyUsage: string;
  enabled: boolean;
  primaryVersion: number;
  creationDate: string;
  description: string;
  tags: { key: string; value: string }[];
}

export interface IssuedToken {
  agentId: string;
  roles: string[];
  token: string;
  expiresAt: number;
}

/** One tool call of a Gemini agent run (console/server/gemini-agent.ts). */
export interface AgentStep {
  tool: string;
  method?: string;
  summary: string;
  decision?: Decision;
  status?: string;
  determiningPolicies?: string[];
  requestId?: string;
  number?: number;
  sha?: string;
  ref?: string;
  url?: string;
  error?: string;
  reason?: string;
}

export interface AgentRun {
  steps: AgentStep[];
  final: string | null;
  stopped: "done" | "step_limit" | "time_limit" | "gemini_error" | "nothing_allowed" | "denied";
  error?: string;
  /** The tools Gemini was offered (only those the active policy could allow). */
  tools: string[];
}

export interface GithubIssueResult {
  decision: Decision;
  determiningPolicies: string[];
  policyVersion: number;
  requestId: string;
  mode: "mock" | "real";
  githubCalled: boolean;
  status: "DENIED" | "SUCCESS" | "ERROR" | "OUTCOME_AUDIT_UNAVAILABLE";
  issueNumber?: number;
  issueUrl?: string;
}

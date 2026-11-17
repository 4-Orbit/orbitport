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

export interface ActionInfo {
  name: string;
  group: string;
  resourceType: string;
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
}

export interface SimResult {
  request: SimRequest;
  decision: Decision;
  determiningPolicies: string[];
  errored: boolean;
  diagnostics?: string[];
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

export interface MatrixResult {
  source: string;
  at: number;
  simulatedTime: boolean;
  principals: string[];
  actions: string[];
  keys: string[];
  agentRoles: Record<string, string[]>;
  cells: Cell[];
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

export interface ValidateResult {
  ok: boolean;
  problems: Problem[];
  summary?: { policyIds: string[]; agents: string[]; roles: string[]; agentRoles: Record<string, string[]>; referencedKeys: string[] };
}

export interface TestCase {
  name: string;
  agentId?: string;
  action: string;
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
  limit?: number;
  agentId?: string;
  decision?: Decision | "";
  action?: string;
  resource?: string;
}

export interface AuditResult {
  events: AuditEvent[];
  summary: { total: number; allow: number; deny: number; kmsCalled: number; errors: number };
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

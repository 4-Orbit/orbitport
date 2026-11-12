/** Token is a separate server argument, never a property in the JSON request. */
export interface IssueRequest {
  version: 1;
  action: 'github.issue.create';
  repository: string;
  title: string;
  body: string;
}
export interface SharedMetadata {
  requestId: string;
  agentId: 'developer-agent' | 'security-agent' | 'unverified';
  action: 'github.issue.create';
  resource: 'designated-test-repo' | 'other-or-invalid';
  /** Epoch milliseconds, from validation; null for unverified requests. */
  tokenExpiresAt: number | null;
  decision: 'ALLOW' | 'DENY';
}
export interface IssueResponse extends SharedMetadata {
  version: 1;
  result: 'INVALID_REQUEST' | 'CREDENTIAL_REJECTED' | 'POLICY_DENIED' | 'VALIDATION_ERROR' | 'AUTHORIZED' | 'MOCK_CREATED' | 'CREATED' | 'GITHUB_ERROR';
  mode: 'MOCK' | 'REAL';
  githubCalled: boolean;
  issue?: { number: number; url?: string };
}
export interface AuditRecord extends SharedMetadata {
  version: 1;
  timestamp: string;
  mode: IssueResponse['mode'];
  result: IssueResponse['result'];
  githubCalled: boolean;
}
export interface CredentialInterface {
  validate(token: string, scope: { action: IssueRequest['action']; repository: string }): Promise<{
    agentId: 'developer-agent' | 'security-agent'; expiresAt: number;
  } | null>;
}
export interface PolicyInterface {
  authorize(request: { agentId: string; action: IssueRequest['action']; repository: string }): Promise<'ALLOW' | 'DENY'>;
}
export interface AuditInterface { append(record: AuditRecord): Promise<void>; }

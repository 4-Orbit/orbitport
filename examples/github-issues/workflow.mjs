import { randomUUID, randomBytes, createHash } from 'node:crypto';
import { readFileSync, appendFileSync } from 'node:fs';
import { isAuthorized } from '@cedar-policy/cedar-wasm/nodejs';

import { ACTION, repositoryPattern } from './contract.mjs';
export { ACTION, repositoryPattern } from './contract.mjs';
const agents = new Set(['developer-agent', 'security-agent']);
const hash = token => createHash('sha256').update(token).digest('hex');

/** Local development credential validation only. Never a SpaceComputer credential. */
export function localCredentials(now = Date.now) {
  const grants = new Map();
  return {
    issue(agentId, repository, ttlMs = 60_000) {
      if (!agents.has(agentId) || !repositoryPattern.test(repository) || !Number.isSafeInteger(ttlMs) || ttlMs < 1 || ttlMs > 60_000) throw new Error('Invalid grant');
      const token = randomBytes(32).toString('base64url');
      grants.set(hash(token), { agentId, repository, action: ACTION, expiresAt: now() + ttlMs });
      return token;
    },
    async validate(token, { repository, action }) {
      if (typeof token !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(token)) return null;
      const grant = grants.get(hash(token));
      return grant && now() < grant.expiresAt && grant.repository === repository && grant.action === action
        ? { agentId: grant.agentId, expiresAt: grant.expiresAt } : null;
    },
    revoke(token) { grants.delete(hash(token)); },
  };
}

export function cedarPolicy(repository, policy = readFileSync(new URL('./policy.cedar', import.meta.url), 'utf8')) {
  return async ({ agentId, action, repository: requested }) => {
    const answer = isAuthorized({
      principal: { type: 'Agent', id: agentId }, action: { type: 'Action', id: action },
      resource: { type: 'Repository', id: requested === repository ? 'designated-test-repo' : 'other-repository' },
      context: {}, entities: [], policies: { staticPolicies: policy },
    });
    return answer.type === 'success' && answer.response.decision === 'allow' && answer.response.diagnostics.errors.length === 0 ? 'ALLOW' : 'DENY';
  };
}

/** Metadata-only adapter seam: replace with SpaceComputer's durable audit interface. */
export function jsonlAudit(path) {
  return async record => appendFileSync(path, JSON.stringify(record) + '\n', { mode: 0o600 });
}

/**
 * Shared v1 contract. Identity is derived by validateCredential, never body.agentId.
 * validateCredential(token, {action, repository}) -> {agentId, expiresAt: epochMs} | null
 * authorize({agentId, action, repository}) -> ALLOW | DENY
 * audit(metadata) -> void (must reject on failure)
 * github.createIssue({repository, title, body}) -> {number}
 */
export function createWorkflow({ repository, validateCredential, authorize, audit, github }) {
  if (!repositoryPattern.test(repository) || !['MOCK', 'REAL'].includes(github.mode)) throw new Error('Invalid workflow configuration');
  return async (request, token) => {
    const id = randomUUID();
    let decision = 'DENY', result = 'INVALID_REQUEST', agent = 'unverified';
    let githubCalled = false, issue, tokenExpiresAt = null;
    const valid = request && Object.keys(request).every(k => ['version', 'action', 'repository', 'title', 'body'].includes(k)) &&
      request.version === 1 && request.action === ACTION && typeof request.repository === 'string' && repositoryPattern.test(request.repository) &&
      typeof request.title === 'string' && request.title.trim().length > 0 && request.title.length <= 256 &&
      typeof request.body === 'string' && request.body.length <= 16_384;
    const metadata = () => ({ version: 1, requestId: id, timestamp: new Date().toISOString(), agentId: agent, tokenExpiresAt, action: ACTION,
      resource: valid && request.repository === repository ? 'designated-test-repo' : 'other-or-invalid',
      decision, result, githubCalled, mode: github.mode });
    if (valid) {
      try {
        const identity = await validateCredential(token, { action: ACTION, repository: request.repository });
        result = 'CREDENTIAL_REJECTED';
        if (identity && agents.has(identity.agentId) && Number.isSafeInteger(identity.expiresAt) && identity.expiresAt > Date.now()) {
          agent = identity.agentId;
          tokenExpiresAt = identity.expiresAt;
          result = 'POLICY_DENIED';
          if (await authorize({ agentId: agent, action: ACTION, repository: request.repository }) === 'ALLOW') {
            decision = 'ALLOW';
            result = 'AUTHORIZED';
          }
        }
      } catch { result = 'VALIDATION_ERROR'; }
    }
    // Audit failure aborts before any GitHub operation. No request data or errors enter audit.
    await audit(metadata());
    if (decision === 'ALLOW') {
      githubCalled = true;
      try {
        const created = await github.createIssue({ repository: request.repository, title: request.title, body: request.body });
        if (!Number.isSafeInteger(created.number) || created.number < 1) throw new Error('Invalid response');
        issue = { number: created.number, ...(github.mode === 'REAL' ? { url: `https://github.com/${repository}/issues/${created.number}` } : {}) };
        result = github.mode === 'MOCK' ? 'MOCK_CREATED' : 'CREATED';
      } catch { result = 'GITHUB_ERROR'; }
      await audit(metadata());
    }
    const { agentId, action, resource } = metadata();
    return { version: 1, requestId: id, agentId, action, resource, tokenExpiresAt, decision, result, mode: github.mode, githubCalled, ...(issue ? { issue } : {}) };
  };
}

export function mockGitHub() {
  let next = 1;
  return { mode: 'MOCK', async createIssue() { return { number: next++ }; } };
}

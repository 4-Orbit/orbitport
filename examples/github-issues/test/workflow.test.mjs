import test from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createWorkflow, localCredentials, cedarPolicy, mockGitHub, jsonlAudit, ACTION } from '../workflow.mjs';
import { githubApp, verifyInstallation } from '../github.mjs';
import { connectSpaceComputer } from '../integration.mjs';
import { repositoryPattern } from '../contract.mjs';

const repository = 'demo-owner/orbitport-test';
const request = (changes = {}) => ({ version: 1, action: ACTION, repository, title: 'PRIVATE_TITLE', body: 'PRIVATE_BODY', ...changes });
function fixture({ policy, ...overrides } = {}) {
  const credentials = localCredentials(), records = [], calls = [];
  const deps = { repository, validateCredential: credentials.validate, authorize: cedarPolicy(repository, policy),
    audit: async event => records.push(event), github: { mode: 'MOCK', async createIssue(input) { calls.push(input); return { number: 17 }; } }, ...overrides };
  return { credentials, records, calls, run: createWorkflow(deps) };
}
test('developer ALLOW creates exactly one issue and records the shared metadata', async () => {
  const f = fixture(), token = f.credentials.issue('developer-agent', repository);
  const result = await f.run(request(), token);
  assert.equal(result.decision, 'ALLOW'); assert.equal(result.result, 'MOCK_CREATED');
  assert.equal(f.calls.length, 1); assert.deepEqual(f.calls[0], { repository, title: 'PRIVATE_TITLE', body: 'PRIVATE_BODY' });
  assert.equal(f.records.length, 2);
  const row = f.records[1];
  assert.equal(row.requestId, result.requestId); assert.equal(row.agentId, 'developer-agent');
  for (const field of ['requestId', 'agentId', 'action', 'resource', 'tokenExpiresAt', 'decision']) assert.equal(result[field], row[field]);
  assert.equal(row.action, ACTION); assert.equal(row.resource, 'designated-test-repo');
  assert.ok(row.tokenExpiresAt > Date.now()); assert.equal(row.decision, 'ALLOW');
  assert.equal(result.issue.url, undefined);
  for (const secret of [token, 'PRIVATE_TITLE', 'PRIVATE_BODY']) assert.ok(!JSON.stringify(f.records).includes(secret));
});
test('security agent DENY makes no GitHub call', async () => {
  const f = fixture();
  const result = await f.run(request(), f.credentials.issue('security-agent', repository));
  assert.equal(result.decision, 'DENY'); assert.equal(result.result, 'POLICY_DENIED'); assert.equal(f.calls.length, 0);
});
test('other repository denied by Cedar even with a matching credential scope', async () => {
  const f = fixture();
  const result = await f.run(request({ repository: 'other/repo' }), f.credentials.issue('developer-agent', 'other/repo'));
  assert.equal(result.decision, 'DENY'); assert.equal(result.result, 'POLICY_DENIED'); assert.equal(f.calls.length, 0);
  assert.ok(!JSON.stringify(f.records).includes('other/repo'));
});
test('missing, invalid, tampered, wrong-scope and revoked credentials make no call', async () => {
  const f = fixture();
  const token = f.credentials.issue('developer-agent', repository);
  const wrongScope = f.credentials.issue('developer-agent', 'other/repo');
  f.credentials.revoke(token);
  for (const value of [undefined, '', 'forged', token, wrongScope, wrongScope.slice(1)]) {
    assert.equal((await f.run(request(), value)).result, 'CREDENTIAL_REJECTED');
  }
  assert.equal(f.calls.length, 0);
});
test('expiry boundary, bounded lifetime and revocation', async () => {
  let now = Date.now(); const store = localCredentials(() => now);
  const token = store.issue('developer-agent', repository, 100);
  const scope = { action: ACTION, repository };
  now += 99; assert.ok(await store.validate(token, scope));
  now++; assert.equal(await store.validate(token, scope), null);
  assert.throws(() => store.issue('developer-agent', repository, 60_001));
  assert.throws(() => store.issue('unknown-agent', repository));
});
test('default credential lifetime is 60 seconds; shorter grants expire at their boundary', async () => {
  let now = 1_000_000;
  const store = localCredentials(() => now);
  const scope = { action: ACTION, repository };
  const standard = store.issue('developer-agent', repository);
  assert.equal((await store.validate(standard, scope)).expiresAt, now + 60_000);
  const shorter = store.issue('developer-agent', repository, 5_000);
  now += 4_999; assert.ok(await store.validate(shorter, scope));
  now++; assert.equal(await store.validate(shorter, scope), null);
  assert.ok(await store.validate(standard, scope));
  now = 1_060_000; assert.equal(await store.validate(standard, scope), null);
});
test('external validator cannot return expired or malformed identities', async () => {
  for (const identity of [{ agentId: 'developer-agent', expiresAt: Date.now() - 1 }, { agentId: 'developer-agent' }, { agentId: 'unknown-agent', expiresAt: Date.now() + 10_000 }]) {
    const f = fixture({ validateCredential: async () => identity });
    assert.equal((await f.run(request(), 'token')).decision, 'DENY'); assert.equal(f.calls.length, 0);
  }
});
test('caller identity, roles, token expiry and action overrides are rejected', async () => {
  const f = fixture(), token = f.credentials.issue('developer-agent', repository);
  for (const change of [{ agentId: 'developer-agent' }, { context: { role: 'developer' } }, { tokenExpiresAt: 9999999999999 }, { requestId: 'PRIVATE_TITLE' }, { action: 'github.repo.delete' }, { version: 2 }, { title: '' }, { body: 'x'.repeat(16385) }, { repository: '../repos/other' }]) {
    assert.equal((await f.run(request(change), token)).decision, 'DENY');
  }
  assert.equal(f.calls.length, 0);
});
test('policy parse and validation failures fail closed without leaking errors', async () => {
  for (const overrides of [{ policy: 'bad PRIVATE_TITLE' }, { authorize: async () => { throw new Error('PRIVATE_BODY'); } }, { validateCredential: async () => { throw new Error('PRIVATE_TITLE'); } }]) {
    const f = fixture(overrides);
    assert.equal((await f.run(request(), f.credentials.issue('developer-agent', repository))).decision, 'DENY');
    assert.equal(f.calls.length, 0); assert.ok(!JSON.stringify(f.records).includes('PRIVATE'));
  }
});
test('Cedar decides: changing policy changes the decision', async () => {
  const f = fixture({ policy: '' });
  assert.equal((await f.run(request(), f.credentials.issue('developer-agent', repository))).decision, 'DENY');
  assert.equal(f.calls.length, 0);
});
test('audit failure aborts before GitHub', async () => {
  const f = fixture({ audit: async () => { throw new Error('audit unavailable'); } });
  await assert.rejects(f.run(request(), f.credentials.issue('developer-agent', repository)));
  assert.equal(f.calls.length, 0);
});
test('GitHub failure is sanitized and is never retried', async () => {
  let calls = 0;
  const f = fixture({ github: { mode: 'REAL', async createIssue() { calls++; throw new Error('PRIVATE_TITLE PRIVATE_BODY github_secret'); } } });
  const result = await f.run(request(), f.credentials.issue('developer-agent', repository));
  assert.equal(calls, 1); assert.equal(result.result, 'GITHUB_ERROR'); assert.equal(result.issue, undefined);
  assert.ok(!JSON.stringify([result, f.records]).includes('PRIVATE'));
});
test('JSONL persists allowlisted metadata without token, issue text or provider response', async t => {
  const dir = mkdtempSync(join(tmpdir(), 'orbitport-issues-')); t.after(() => rmSync(dir, { recursive: true }));
  const path = join(dir, 'audit.jsonl');
  const f = fixture({ audit: jsonlAudit(path), github: { mode: 'REAL', async createIssue() { return { number: 3, token: 'provider_secret', title: 'PRIVATE_TITLE' }; } } });
  const token = f.credentials.issue('developer-agent', repository);
  const result = await f.run(request(), token);
  assert.equal(result.issue.url, `https://github.com/${repository}/issues/3`);
  const log = readFileSync(path, 'utf8');
  for (const secret of [token, 'PRIVATE_TITLE', 'PRIVATE_BODY', 'provider_secret', '/issues/3']) assert.ok(!log.includes(secret));
  assert.equal(log.trim().split('\n').length, 2);
});
test('App transport: ALLOW creates one issue; DENY makes zero API calls including token exchange', async () => {
  const { privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
  const calls = [];
  const github = githubApp({ appId: '123', installationId: '456', privateKey: privateKey.export({ type: 'pkcs8', format: 'pem' }), repository,
    fetchImpl: async (url, options) => { calls.push({ url, options }); return { ok: true, async json() { return url.endsWith('access_tokens') ? { token: 'INSTALLATION_SECRET' } : { number: 42, body: 'PRIVATE_BODY' }; } }; } });
  const f = fixture({ github });
  assert.equal((await f.run(request(), f.credentials.issue('security-agent', repository))).decision, 'DENY');
  assert.equal((await f.run(request({ repository: 'other/repo' }), f.credentials.issue('developer-agent', 'other/repo'))).decision, 'DENY');
  assert.equal(calls.length, 0);
  const result = await f.run(request(), f.credentials.issue('developer-agent', repository));
  assert.equal(result.issue.url, `https://github.com/${repository}/issues/42`);
  assert.equal(calls.length, 2); assert.equal(calls.filter(c => c.url.endsWith('/issues')).length, 1);
  assert.deepEqual(JSON.parse(calls[0].options.body), { repositories: ['orbitport-test'], permissions: { issues: 'write' } });
  assert.equal(calls[1].options.headers.Authorization, 'Bearer INSTALLATION_SECRET');
  assert.equal(calls[1].options.redirect, 'error');
  assert.ok(!JSON.stringify(f.records).includes('INSTALLATION_SECRET'));
});
test('mock numbers distinguish outcomes without fabricating GitHub URLs', async () => {
  const github = mockGitHub(); assert.deepEqual(await github.createIssue({}), { number: 1 }); assert.deepEqual(await github.createIssue({}), { number: 2 });
});
test('shared schema and implementation agree on action and repository boundaries', () => {
  const schema = JSON.parse(readFileSync(new URL('../contract.schema.json', import.meta.url), 'utf8'));
  assert.equal(schema.properties.action.const, ACTION);
  const pattern = new RegExp(schema.properties.repository.pattern);
  for (const resource of [repository, 'another/repo', 'owner/.', 'owner/..', '../repo', 'a/b/c', 'a/b?token=secret']) {
    assert.equal(pattern.test(resource), repositoryPattern.test(resource));
  }
  assert.equal(repositoryPattern.test('owner/..'), false);
});
test('SpaceComputer wiring uses all three supplied interfaces and never falls back', async () => {
  assert.throws(() => connectSpaceComputer({ repository }));
  const { privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
  const events = [], scopes = [], policyRequests = [];
  let networkCalls = 0;
  const run = connectSpaceComputer({ repository,
    credentials: { async validate(token, scope) { assert.equal(token, 'external-token'); scopes.push(scope); return { agentId: 'developer-agent', expiresAt: Date.now() + 60_000 }; } },
    policy: { async authorize(input) { policyRequests.push(input); return input.repository === repository ? 'ALLOW' : 'DENY'; } },
    audit: { async append(record) { events.push(record); } },
    app: { appId: '12', installationId: '34', privateKey: privateKey.export({ type: 'pkcs8', format: 'pem' }),
      fetchImpl: async url => { networkCalls++; return { ok: true, async json() { return url.endsWith('access_tokens') ? { token: 'provider-secret' } : { number: 7 }; } }; } },
  });
  assert.equal((await run(request({ repository: 'other/repo' }), 'external-token')).decision, 'DENY');
  assert.equal(networkCalls, 0);
  const result = await run(request(), 'external-token');
  assert.equal(result.mode, 'REAL'); assert.equal(result.issue.number, 7); assert.equal(networkCalls, 2);
  assert.deepEqual(scopes[1], { action: ACTION, repository });
  assert.deepEqual(policyRequests[1], { agentId: 'developer-agent', action: ACTION, repository });
  assert.equal(events.length, 3);
  assert.ok(!JSON.stringify(events).includes('external-token')); assert.ok(!JSON.stringify(events).includes('provider-secret'));
});
test('installation discovery requires the correct active App and Issues write', async () => {
  const { privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
  const key = privateKey.export({ type: 'pkcs8', format: 'pem' });
  const valid = { app_id: 123, id: 456, suspended_at: null, permissions: { issues: 'write' } };
  let body = valid, calls = 0;
  const options = { appId: '123', privateKey: key, repository, fetchImpl: async (url, init) => {
    calls++; assert.equal(url, `https://api.github.com/repos/${repository}/installation`);
    assert.equal(init.redirect, 'error'); assert.match(init.headers.Authorization, /^Bearer /);
    return { ok: true, async json() { return body; } };
  } };
  assert.deepEqual(await verifyInstallation(options), { installationId: '456', appId: '123', issues: 'write' });
  for (const change of [{ app_id: 999 }, { suspended_at: '2026-11-10' }, { permissions: { issues: 'read' } }, { id: -1 }]) {
    body = { ...valid, ...change }; await assert.rejects(verifyInstallation(options));
  }
  assert.equal(calls, 5);
});

import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createDemo } from '../server.mjs';
import { createGeminiClient, GeminiError } from '../gemini.mjs';
import http from 'node:http';

test('console serves UI and operator requests; rejects cross-origin and forged identity', async t => {
  const dir = mkdtempSync(join(tmpdir(), 'orbitport-console-'));
  const server = createDemo({ auditPath: join(dir, 'audit.jsonl') });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(async () => { await new Promise(resolve => server.close(resolve)); rmSync(dir, { recursive: true }); });
  const base = `http://127.0.0.1:${server.address().port}`;
  const html = await fetch(base); assert.equal(html.status, 200); assert.match(await html.text(), /Operator request/);
  assert.match(await (await fetch(base)).text(), /Gemini agent/);
  assert.match(html.headers.get('content-security-policy'), /frame-ancestors 'none'/);
  const submit = (input, origin = base) => fetch(`${base}/api/operator/requests`, { method: 'POST', headers: { Origin: origin, 'Content-Type': 'application/json' }, body: JSON.stringify({ agentId: 'developer-agent', repository: 'demo-owner/orbitport-test', title: 'Secret title', body: 'Secret body', ...input }) });
  assert.equal((await (await submit({})).json()).result, 'MOCK_CREATED');
  assert.equal((await (await submit({ agentId: 'security-agent' })).json()).decision, 'DENY');
  assert.equal((await (await submit({ repository: 'other/repo' })).json()).decision, 'DENY');
  assert.equal((await submit({}, 'https://evil.example')).status, 403);
  assert.equal((await submit({ agentId: 'unknown' })).status, 400);
  assert.equal((await submit({ tokenExpiresAt: 9999999999999 })).status, 400);
  const events = await (await fetch(`${base}/api/events`)).json();
  assert.equal(events.events.length, 3); assert.equal(events.mode, 'MOCK'); assert.equal(events.geminiEnabled, false);
  assert.equal(events.events.filter(r => r.decision === 'ALLOW').length, 1);
  assert.ok(!JSON.stringify(events).includes('Secret'));
  assert.equal((await fetch(`${base}/.env`)).status, 404);
  const badHostStatus = await new Promise((resolve, reject) => {
    http.get(`${base}/api/events`, { headers: { Host: 'evil.example' } }, response => { response.resume(); resolve(response.statusCode); }).on('error', reject);
  });
  assert.equal(badHostStatus, 403);
});

test('live console requires confirmation, denies before GitHub, and retains safe issue links', async t => {
  const dir = mkdtempSync(join(tmpdir(), 'orbitport-live-console-'));
  let calls = 0;
  const repository = 'laurenc06/orbitport-issue-test';
  const server = createDemo({ repository, auditPath: join(dir, 'audit.jsonl'), github: {
    mode: 'REAL', async createIssue() { calls++; return { number: 8 }; },
  } });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(async () => { await new Promise(resolve => server.close(resolve)); rmSync(dir, { recursive: true }); });
  const base = `http://127.0.0.1:${server.address().port}`;
  const submit = (changes = {}) => fetch(`${base}/api/operator/requests`, { method: 'POST', headers: { Origin: base, 'Content-Type': 'application/json' },
    body: JSON.stringify({ agentId: 'developer-agent', repository, title: 'private live title', body: 'private live body', ...changes }) });
  assert.equal((await submit()).status, 400); assert.equal(calls, 0);
  assert.equal((await (await submit({ confirmLive: true, agentId: 'security-agent' })).json()).decision, 'DENY');
  assert.equal((await (await submit({ confirmLive: true, repository: 'other/repo' })).json()).decision, 'DENY');
  assert.equal(calls, 0);
  const response = await (await submit({ confirmLive: true })).json();
  assert.equal(response.result, 'CREATED'); assert.equal(response.mode, 'REAL'); assert.equal(calls, 1);
  const events = await (await fetch(`${base}/api/events`)).json();
  assert.equal(events.mode, 'REAL'); assert.equal(events.credentialMode, 'LOCAL_STUB');
  assert.equal(events.operations[response.requestId].issue.url, `https://github.com/${repository}/issues/8`);
  assert.ok(!JSON.stringify(events).includes('private live'));
});

test('Gemini operator request uses the same policy workflow and requires live confirmation', async t => {
  const dir = mkdtempSync(join(tmpdir(), 'orbitport-gemini-console-'));
  let geminiCalls = 0, githubCalls = 0;
  const repository = 'owner/test-repo';
  const server = createDemo({ repository, auditPath: join(dir, 'audit.jsonl'),
    gemini: createGeminiClient({ apiKey: 'test-key', fetchImpl: async (_url, options) => {
      geminiCalls++;
      assert.equal(options.headers['x-goog-api-key'], 'test-key');
      return { ok: true, json: async () => ({ steps: [{ type: 'function_call', name: 'create_issue', arguments: { title: 'Model title', body: 'Model body' } }] }) };
    } }),
    github: { mode: 'REAL', async createIssue() { githubCalls++; return { number: 27 }; } },
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(async () => { await new Promise(resolve => server.close(resolve)); rmSync(dir, { recursive: true }); });
  const base = `http://127.0.0.1:${server.address().port}`;
  const submit = (changes = {}, origin = base) => fetch(`${base}/api/operator/gemini`, { method: 'POST', headers: { Origin: origin, 'Content-Type': 'application/json' },
    body: JSON.stringify({ agentId: 'developer-agent', repository, prompt: 'Report the login bug', ...changes }) });
  assert.equal((await submit()).status, 400);
  assert.equal((await submit({ confirmLive: true }, 'https://evil.example')).status, 403);
  assert.equal((await submit({ confirmLive: true, apiKey: 'forged' })).status, 400);
  assert.equal(geminiCalls, 0);
  const denied = await (await submit({ confirmLive: true, agentId: 'security-agent' })).json();
  assert.equal(denied.decision, 'DENY'); assert.equal(githubCalls, 0);
  const allowed = await (await submit({ confirmLive: true })).json();
  assert.equal(allowed.result, 'CREATED'); assert.equal(allowed.issue.number, 27);
  assert.equal(allowed.proposal.title, 'Model title');
  assert.equal(geminiCalls, 2); assert.equal(githubCalls, 1);
  const events = await (await fetch(`${base}/api/events`)).json();
  assert.equal(events.geminiEnabled, true);
  assert.equal(events.events.length, 2);
  assert.ok(!JSON.stringify(events).includes('Model body'));
  assert.ok(!JSON.stringify(events).includes('Report the login bug'));
});

test('Gemini provider failure returns a safe error without contacting GitHub', async t => {
  const dir = mkdtempSync(join(tmpdir(), 'orbitport-gemini-error-'));
  let githubCalls = 0;
  let providerError = new Error('provider-secret');
  const repository = 'owner/test-repo';
  const server = createDemo({ repository, auditPath: join(dir, 'audit.jsonl'),
    gemini: { async proposeIssue() { throw providerError; } },
    github: { mode: 'REAL', async createIssue() { githubCalls++; return { number: 1 }; } },
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(async () => { await new Promise(resolve => server.close(resolve)); rmSync(dir, { recursive: true }); });
  const base = `http://127.0.0.1:${server.address().port}`;
  const response = await fetch(`${base}/api/operator/gemini`, { method: 'POST', headers: { Origin: base, 'Content-Type': 'application/json' },
    body: JSON.stringify({ agentId: 'developer-agent', repository, prompt: 'Create an issue', confirmLive: true }) });
  assert.equal(response.status, 502);
  assert.ok(!(await response.text()).includes('provider-secret'));
  providerError = new GeminiError('overloaded', 503, 'Service Unavailable');
  const overloaded = await fetch(`${base}/api/operator/gemini`, { method: 'POST', headers: { Origin: base, 'Content-Type': 'application/json' },
    body: JSON.stringify({ agentId: 'developer-agent', repository, prompt: 'Create an issue', confirmLive: true }) });
  assert.equal(overloaded.status, 503);
  assert.equal((await overloaded.json()).error, 'Gemini API HTTP 503 Service Unavailable');
  assert.equal(githubCalls, 0);
});

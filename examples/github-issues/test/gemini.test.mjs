import test from 'node:test';
import assert from 'node:assert/strict';
import { createGeminiClient } from '../gemini.mjs';

test('Gemini proposes exactly one issue through a declared tool; the key stays in the header', async () => {
  let called = 0;
  const client = createGeminiClient({ apiKey: 'server-secret', model: 'gemini-3.8-flash', fetchImpl: async (url, options) => {
    called++;
    assert.equal(url, 'https://generativelanguage.googleapis.com/v1beta/interactions');
    assert.equal(options.headers['x-goog-api-key'], 'server-secret');
    const body = JSON.parse(options.body);
    assert.equal(body.model, 'gemini-3.8-flash');
    assert.equal(body.store, false);
    assert.match(body.input, /Fix the login bug/);
    assert.equal(body.tools[0].name, 'create_issue');
    assert.ok(!options.body.includes('server-secret'));
    return { ok: true, json: async () => ({ steps: [{ type: 'function_call', name: 'create_issue', arguments: { title: 'Fix login', body: 'The login flow fails.' } }] }) };
  } });
  assert.deepEqual(await client.proposeIssue({ prompt: 'Fix the login bug', repository: 'owner/repo' }), { title: 'Fix login', body: 'The login flow fails.' });
  assert.equal(called, 1);
});

test('the default model is the verified Flash-Lite model', async () => {
  const client = createGeminiClient({ apiKey: 'server-secret', fetchImpl: async (_url, options) => {
    assert.equal(JSON.parse(options.body).model, 'gemini-3.5-flash-lite');
    return { ok: true, json: async () => ({ steps: [{ type: 'function_call', name: 'create_issue', arguments: { title: 'A', body: '' } }] }) };
  } });
  await client.proposeIssue({ prompt: 'Create an issue', repository: 'owner/repo' });
});

test('Gemini 503 is classified without exposing provider response text', async () => {
  const client = createGeminiClient({ apiKey: 'server-secret', waitImpl: async () => {}, fetchImpl: async () => ({ ok: false, status: 503, statusText: 'Service Unavailable', text: async () => 'server-secret private prompt' }) });
  await assert.rejects(client.proposeIssue({ prompt: 'Create an issue', repository: 'owner/repo' }), error => {
    assert.equal(error.kind, 'overloaded');
    assert.equal(error.httpStatus, 503);
    assert.equal(error.message, 'Gemini API HTTP 503 Service Unavailable');
    assert.ok(!error.message.includes('server-secret'));
    return true;
  });
});

test('Gemini returns the provider HTTP status for a rejected key', async () => {
  const client = createGeminiClient({ apiKey: 'server-secret', fetchImpl: async () => ({ ok: false, status: 401, statusText: 'Unauthorized' }) });
  await assert.rejects(client.proposeIssue({ prompt: 'Create an issue', repository: 'owner/repo' }), error => {
    assert.equal(error.httpStatus, 401);
    assert.equal(error.message, 'Gemini API HTTP 401 Unauthorized');
    return true;
  });
});

test('Gemini retries one 503 before proposing an issue', async () => {
  let calls = 0, waits = 0;
  const client = createGeminiClient({ apiKey: 'server-secret', waitImpl: async ms => { assert.ok(ms > 0); waits++; }, fetchImpl: async () => {
    calls++;
    if (calls === 1) return { ok: false, status: 503 };
    return { ok: true, json: async () => ({ steps: [{ type: 'function_call', name: 'create_issue', arguments: { title: 'A', body: '' } }] }) };
  } });
  assert.deepEqual(await client.proposeIssue({ prompt: 'Create an issue', repository: 'owner/repo' }), { title: 'A', body: '' });
  assert.equal(calls, 2); assert.equal(waits, 1);
});

test('Gemini does not retry authentication failures', async () => {
  let calls = 0;
  const client = createGeminiClient({ apiKey: 'server-secret', waitImpl: async () => { throw new Error('unexpected retry'); }, fetchImpl: async () => { calls++; return { ok: false, status: 401 }; } });
  await assert.rejects(client.proposeIssue({ prompt: 'Create an issue', repository: 'owner/repo' }), error => error.kind === 'auth');
  assert.equal(calls, 1);
});

test('Gemini rejects missing, multiple, unknown, and malformed tool calls', async () => {
  const responses = [
    { steps: [] },
    { steps: [{ type: 'function_call', name: 'create_issue', arguments: { title: 'A', body: '' } }, { type: 'function_call', name: 'create_issue', arguments: { title: 'B', body: '' } }] },
    { steps: [{ type: 'function_call', name: 'other', arguments: { title: 'A', body: '' } }] },
    { steps: [{ type: 'function_call', name: 'create_issue', arguments: { title: '', body: '' } }] },
    { steps: [{ type: 'function_call', name: 'create_issue', arguments: { title: 'A', body: '', repository: 'other/repo' } }] },
  ];
  for (const response of responses) {
    const client = createGeminiClient({ apiKey: 'server-secret', fetchImpl: async () => ({ ok: true, json: async () => response }) });
    await assert.rejects(client.proposeIssue({ prompt: 'Create an issue', repository: 'owner/repo' }));
  }
});

test('Gemini fails closed on provider errors and never exposes raw provider text', async () => {
  const client = createGeminiClient({ apiKey: 'server-secret', fetchImpl: async () => ({ ok: false, status: 429, text: async () => 'server-secret private prompt' }) });
  await assert.rejects(client.proposeIssue({ prompt: 'Create an issue', repository: 'owner/repo' }), error => {
    assert.ok(!error.message.includes('server-secret'));
    assert.ok(!error.message.includes('private prompt'));
    return true;
  });
});

import assert from 'node:assert/strict';
import { readFileSync, writeFileSync } from 'node:fs';
import { createDemo } from './server.mjs';
import { githubApp, verifyInstallation } from './github.mjs';

// This intentionally creates ONE real issue. It is never part of npm test.
if (!process.argv.includes('--create-one-issue')) {
  console.error('Use npm run test:live -- --create-one-issue to explicitly create one real issue.');
  process.exit(1);
}
let server;
try {
  const repository = process.env.GITHUB_TEST_REPOSITORY;
  const privateKey = readFileSync(process.env.GITHUB_APP_PRIVATE_KEY_PATH, 'utf8');
  const appId = process.env.GITHUB_APP_ID;
  const { installationId } = await verifyInstallation({ appId, privateKey, repository });
  const calls = [], secrets = [privateKey];
  const trackedFetch = async (url, options) => {
    calls.push({ path: new URL(url).pathname, method: options.method });
    secrets.push(options.headers.Authorization);
    const response = await fetch(url, options);
    if (url.endsWith('/access_tokens') && response.ok) secrets.push((await response.clone().json()).token);
    return response;
  };
  const auditPath = new URL('./audit.live.jsonl', import.meta.url);
  const auditBefore = (() => { try { return readFileSync(auditPath, 'utf8').length; } catch { return 0; } })();
  server = createDemo({ repository, auditPath,
    github: githubApp({ appId, installationId, privateKey, repository, fetchImpl: trackedFetch }) });
  await new Promise((resolve, reject) => { server.once('error', reject); server.listen(0, '127.0.0.1', resolve); });
  const base = `http://127.0.0.1:${server.address().port}`;
  const title = 'Orbitport live boundary verification';
  const body = 'One developer request authorized by Cedar with a locally issued credential. Security-agent and other-repository requests were denied before any GitHub operation. SpaceComputer integration remains pending.';
  const submit = async changes => {
    const response = await fetch(`${base}/api/operator/requests`, { method: 'POST',
      headers: { 'Content-Type': 'application/json', Origin: base },
      body: JSON.stringify({ agentId: 'developer-agent', repository, title, body, confirmLive: true, ...changes }) });
    assert.equal(response.status, 200); return response.json();
  };
  assert.equal((await submit({ agentId: 'security-agent' })).decision, 'DENY');
  assert.equal((await submit({ repository: 'other/repo' })).decision, 'DENY');
  assert.equal(calls.length, 0, 'Denied requests must not contact GitHub');
  const allowed = await submit({});
  assert.equal(allowed.decision, 'ALLOW'); assert.equal(allowed.result, 'CREATED');
  assert.equal(calls.length, 2);
  assert.equal(calls.filter(call => call.method === 'POST' && call.path === `/repos/${repository}/issues`).length, 1);
  const log = readFileSync(auditPath, 'utf8').slice(auditBefore);
  for (const secret of [title, body, ...secrets]) if (secret) {
    assert.ok(!log.includes(secret));
    if (secret.startsWith('Bearer ')) assert.ok(!log.includes(secret.slice(7)));
  }
  const fields = ['version', 'requestId', 'timestamp', 'agentId', 'tokenExpiresAt', 'action', 'resource', 'decision', 'result', 'githubCalled', 'mode'];
  for (const line of log.trim().split('\n')) assert.deepEqual(Object.keys(JSON.parse(line)).sort(), [...fields].sort());
  const summary = { verifiedAt: new Date().toISOString(), repository, mode: 'REAL', credentialMode: 'LOCAL_STUB',
    deniedRequests: 2, deniedGitHubCalls: 0, allowedRequests: 1, issueCreationPosts: 1,
    auditMetadataOnly: true, issue: allowed.issue };
  writeFileSync(new URL('./live-verification.json', import.meta.url), JSON.stringify(summary, null, 2) + '\n');
  console.log(JSON.stringify(summary, null, 2));
} catch {
  console.error('Live verification did not complete. Check the test repository before retrying; an issue may already exist. No automatic retry was made.');
  process.exitCode = 1;
} finally {
  if (server?.listening) await new Promise(resolve => server.close(resolve));
}

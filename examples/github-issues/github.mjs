import { createPrivateKey, sign } from 'node:crypto';
import { repositoryPattern } from './contract.mjs';

function appJwt(appId, key, now) {
  const seconds = Math.floor(now() / 1000);
  const encode = value => Buffer.from(JSON.stringify(value)).toString('base64url');
  const unsigned = `${encode({ alg: 'RS256', typ: 'JWT' })}.${encode({ iat: seconds - 60, exp: seconds + 540, iss: String(appId) })}`;
  return `${unsigned}.${sign('RSA-SHA256', Buffer.from(unsigned), key).toString('base64url')}`;
}

/** Read-only App authentication check; returns no credentials or raw provider data. */
export async function verifyInstallation({ appId, privateKey, repository, fetchImpl = fetch, now = Date.now }) {
  if (!/^\d+$/.test(String(appId)) || !repositoryPattern.test(repository)) throw new Error('Invalid App configuration');
  const key = createPrivateKey(privateKey);
  if (key.asymmetricKeyType !== 'rsa') throw new Error('GitHub App requires an RSA key');
  const response = await fetchImpl(`https://api.github.com/repos/${repository}/installation`, {
    headers: { Authorization: `Bearer ${appJwt(appId, key, now)}`, Accept: 'application/vnd.github+json',
      'X-GitHub-Api-Version': '2022-11-28', 'User-Agent': 'Orbitport-issue-demo' },
    redirect: 'error', signal: AbortSignal.timeout(15_000),
  });
  if (!response.ok) throw new Error('Could not verify App installation');
  const installation = await response.json();
  if (String(installation.app_id) !== String(appId) || !Number.isSafeInteger(installation.id) || installation.id < 1 || installation.suspended_at || installation.permissions?.issues !== 'write') {
    throw new Error('App must be active and installed with Issues write permission');
  }
  return { installationId: String(installation.id), appId: String(appId), issues: 'write' };
}

/** Server-only GitHub App credentials. No automatic retry of issue creation. */
export function githubApp({ appId, installationId, privateKey, repository, fetchImpl = fetch, now = Date.now }) {
  if (!/^\d+$/.test(String(appId)) || !/^\d+$/.test(String(installationId)) || !repositoryPattern.test(repository)) throw new Error('Invalid GitHub App configuration');
  const key = createPrivateKey(privateKey);
  if (key.asymmetricKeyType !== 'rsa') throw new Error('GitHub App requires an RSA key');
  const headers = token => ({ Authorization: `Bearer ${token}`, Accept: 'application/vnd.github+json',
    'X-GitHub-Api-Version': '2022-11-28', 'User-Agent': 'Orbitport-issue-demo', 'Content-Type': 'application/json' });
  const post = async (path, token, body) => {
    const response = await fetchImpl(`https://api.github.com${path}`, { method: 'POST', headers: headers(token),
      redirect: 'error', signal: AbortSignal.timeout(15_000), body: JSON.stringify(body) });
    if (!response.ok) throw new Error('GitHub operation failed');
    return response.json();
  };
  return {
    mode: 'REAL',
    async createIssue(request) {
      if (request.repository !== repository) throw new Error('Repository mismatch');
      const jwt = appJwt(appId, key, now);
      const installation = await post(`/app/installations/${installationId}/access_tokens`, jwt,
        { repositories: [repository.split('/')[1]], permissions: { issues: 'write' } });
      if (typeof installation.token !== 'string' || !installation.token) throw new Error('Missing installation token');
      const issue = await post(`/repos/${repository}/issues`, installation.token, { title: request.title, body: request.body });
      return { number: issue.number };
    },
  };
}

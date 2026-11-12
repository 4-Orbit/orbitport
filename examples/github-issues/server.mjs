import http from 'node:http';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { createWorkflow, localCredentials, cedarPolicy, jsonlAudit, mockGitHub, ACTION } from './workflow.mjs';
import { githubApp, verifyInstallation } from './github.mjs';

/** Trusted local operator console. Agent identity remains locally issued in both modes. */
export function createDemo({ auditPath = new URL('./audit.jsonl', import.meta.url), repository = 'demo-owner/orbitport-test', github = mockGitHub() } = {}) {
  const credentials = localCredentials();
  const events = new Map();
  const operations = new Map();
  const writeAudit = jsonlAudit(auditPath);
  const workflow = createWorkflow({ repository, validateCredential: credentials.validate,
    authorize: cedarPolicy(repository), github,
    audit: async event => { await writeAudit(event); events.set(event.requestId, event); if (events.size > 500) events.delete(events.keys().next().value); },
  });
  const assets = { '/': ['index.html', 'text/html'], '/app.js': ['app.js', 'text/javascript'], '/style.css': ['style.css', 'text/css'] };
  const server = http.createServer(async (req, res) => {
    const reply = (status, data) => { res.writeHead(status, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' }); res.end(JSON.stringify(data)); };
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'");
    const host = `127.0.0.1:${server.address()?.port}`;
    if (req.headers.host !== host || (req.headers.origin && req.headers.origin !== `http://${host}`)) return reply(403, { error: 'Local requests only' });
    try {
      if (req.method === 'GET' && assets[req.url]) {
        const [file, type] = assets[req.url];
        res.writeHead(200, { 'Content-Type': type });
        return res.end(readFileSync(new URL(`./public/${file}`, import.meta.url)));
      }
      if (req.method === 'GET' && req.url === '/api/events') return reply(200, { repository, mode: github.mode, credentialMode: 'LOCAL_STUB', events: [...events.values()].reverse(), operations: Object.fromEntries(operations) });
      if (req.method === 'POST' && req.url === '/api/operator/requests') {
        if (req.headers.origin !== `http://${host}` || req.headers['content-type'] !== 'application/json') return reply(403, { error: 'Same-origin JSON required' });
        let body = '';
        for await (const chunk of req) { body += chunk; if (Buffer.byteLength(body) > 24_000) return reply(413, { error: 'Request too large' }); }
        const input = JSON.parse(body);
        if (!input || !['developer-agent', 'security-agent'].includes(input.agentId) || Object.keys(input).some(k => !['agentId', 'repository', 'title', 'body', 'confirmLive'].includes(k))) return reply(400, { error: 'Invalid operator request' });
        if (github.mode === 'REAL' && input.confirmLive !== true) return reply(400, { error: 'Confirm real GitHub issue creation' });
        // This trusted loopback operator chooses a simulated agent; agents cannot self-assert identity in workflow requests.
        const token = credentials.issue(input.agentId, repository);
        try {
          const result = await workflow({ version: 1, action: ACTION, repository: input.repository, title: input.title, body: input.body }, token);
          if (result.issue) {
            operations.set(result.requestId, { mode: result.mode, issue: result.issue });
            if (operations.size > 500) operations.delete(operations.keys().next().value);
          }
          return reply(200, result);
        } finally { credentials.revoke(token); }
      }
      return reply(404, { error: 'Not found' });
    } catch { return reply(400, { error: 'Request could not be completed; check local configuration' }); }
  });
  return server;
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  try {
    let options = {};
    if (process.argv.includes('--real')) {
      const repository = process.env.GITHUB_TEST_REPOSITORY;
      const privateKey = readFileSync(process.env.GITHUB_APP_PRIVATE_KEY_PATH, 'utf8');
      const appId = process.env.GITHUB_APP_ID;
      const { installationId } = await verifyInstallation({ appId, privateKey, repository });
      options = { repository, github: githubApp({ appId, installationId, privateKey, repository }) };
    }
    const mode = options.github?.mode ?? 'MOCK';
    const port = Number(process.env.CONSOLE_PORT ?? 4321);
    if (!Number.isSafeInteger(port) || port < 1 || port > 65535) throw new Error('Invalid port');
    const server = createDemo(options);
    server.on('error', () => { console.error(`Console could not start. Check whether port ${port} is in use.`); process.exitCode = 1; });
    server.listen(port, '127.0.0.1', () => console.log(`${mode} GitHub / LOCAL credentials: http://127.0.0.1:${port}`));
  } catch {
    console.error('Live startup failed. Check App configuration, installation, key path, and Issues write permission. No mock fallback was started.');
    process.exitCode = 1;
  }
}

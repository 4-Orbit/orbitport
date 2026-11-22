# GitHub issue workflow (standalone prototype)

> **Superseded.** This was the first GitHub prototype: a standalone Node server with its own Cedar engine (`@cedar-policy/cedar-wasm`), an operator-picked agent identity, and local audit. The same flow now runs inside the stack, enforced by `plugin-github` with the shared engine, signed agent PATs and the console's Activity feed. Use the console's **GitHub** page instead ([`docs/4orbit/github.md`](../../docs/4orbit/github.md)). This example is kept for reference.

## Run it

Node 22+, from this directory:

```sh
npm ci
npm test            # stubbed GitHub transport; never contacts GitHub
npm start           # mock mode on http://127.0.0.1:4321
```

| Simulated agent | Repository | Expected |
| --- | --- | --- |
| Developer | `demo-owner/orbitport-test` | ALLOW; one simulated issue |
| Security | `demo-owner/orbitport-test` | DENY; zero GitHub operations |
| Developer | `another/repo` | DENY; zero GitHub operations |

For real issues, copy `.env.example` to `.env` (App ID, repository, the private key's **file path**, port) and run `npm run start:real`. Startup checks that the App is installed on the repository with Issues write permission, and fails instead of falling back to mock. `npm run test:live -- --create-one-issue` creates one real issue and checks that two DENY requests made zero GitHub calls.

The identity selector is trusted only because the server binds loopback. It is not an agent authentication endpoint.

## Run the Gemini prototype

Add `GEMINI_API_KEY=...` to this directory's git-ignored `.env`. The default model is `gemini-3.5-flash-lite`; `GEMINI_MODEL` overrides it. The key stays on the server and is never sent to the browser, GitHub, or audit records. Gemini requests set `store: false` because the demo does not resume interactions.

Run `npm run start:gemini` for simulated GitHub issues, or `npm run start:real` for real issues after configuring the GitHub App. In the Gemini panel, select an agent and repository above, enter a task, and confirm real issue creation when in REAL mode. Gemini proposes one title and body; the standalone demo's local credential, Cedar policy, audit, and GitHub workflow decide whether to create it. A denied request makes no GitHub call. Gemini retries one HTTP 503 before giving up; GitHub issue creation is never retried.

This Gemini prototype still uses the standalone demo's operator-picked identity. It is separate from the main stack's signed agent PATs and `plugin-github` enforcement.

## What carried over into `plugin-github`

- A DENY never calls GitHub, not even the installation-token exchange.
- Installation tokens are narrowed per call to one repository and `issues: write`.
- The decision is audited **before** the GitHub call, and an audit failure blocks it. Audit holds metadata only: no titles, bodies, tokens, keys or provider errors.
- Fixed API endpoints, redirects disabled, bounded timeouts, no automatic retries, and no exactly-once guarantee.

## Files

| File | Purpose |
| --- | --- |
| `workflow.mjs`, `integration.mjs` | The request workflow, and `connectSpaceComputer` for plugging in real credential, policy and audit adapters |
| `github.mjs`, `configure-github.mjs` | GitHub App JWT, narrowed installation tokens, the issue POST |
| `contract.schema.json`, `contract.d.ts` | The proposed request and response shape (v1, never agreed) |
| `policy.cedar` | The prototype's policy: developers may create issues in the configured repository |
| `server.mjs`, `public/` | The operator page |
| `gemini.mjs` | Server-side Gemini issue proposal adapter |
| `live-verification.json` | Evidence from the live check on 2026-11-10 ([issue #1](https://github.com/laurenc06/orbitport-issue-test/issues/1)) |

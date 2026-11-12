# GitHub issue workflow and operator demo

Local, runnable increment on branch `github-issue-workflow`, based on `ucsb-capstone` commit `8669055`. The requested earlier reference commit was not supplied; this records the exact starting point without claiming it was agreed.

## Run the simulation

Requires Node 22+. From this directory:

```sh
npm ci
npm test
npm start
```

Open <http://127.0.0.1:4321>. The console follows the dark neutral palette, compact activity table, decision badges, and operator form in `4orbit/web`. It has no dependency on that sibling checkout.

Try these cases:

| Simulated agent | Repository | Expected |
| --- | --- | --- |
| Developer | `demo-owner/orbitport-test` | ALLOW; one simulated issue |
| Security | `demo-owner/orbitport-test` | DENY; zero GitHub operations |
| Developer | `another/repo` | DENY; zero GitHub operations |

Click a request ID to inspect audit metadata, including validated token expiry. The form selects a simulated identity through a trusted loopback operator endpoint; it is not an agent authentication endpoint. Local random credentials are scoped, expire within 60 seconds, are stored by hash, and are revoked after each operator request. Shorter lifetimes can be supplied by the trusted issuer; requests cannot extend them. Scope means the allowed agent, action, and repository; lifetime means how long the credential is valid. The console never receives tokens or GitHub App credentials. Mock issue numbers are not links to real issues.

## Run with real GitHub issues

The local operator console now supports real GitHub App operations. Agent identities, delegated credentials, Cedar policy, and JSONL audit remain local; this is not yet a live SpaceComputer integration.

The configured `.env` is ignored by Git and stores the App ID, repository, private-key **file path**, and console port. The key itself stays in its original location and is read only by server code. For another checkout, copy `.env.example` to `.env` and fill in those settings. Never copy the PEM contents into source files or the browser.

```sh
npm run start:real
```

Open the URL printed by the server. This checkout uses <http://127.0.0.1:4322> because port 4321 was already in use. The bind address is always loopback. Startup verifies that the App is installed on the configured repository with Issues write permission and fails without falling back to mock if verification fails.

The console must display **REAL GITHUB · LOCAL CREDENTIALS** and the real repository. Check the confirmation box and submit a developer request to create a real issue; the result includes its GitHub link. Security-agent and other-repository requests deny without calling the GitHub adapter. The confirmation resets after each request. The operator's identity selector is trusted only because this tool is restricted to the local machine; it must not be exposed as a production agent authentication endpoint.

For an explicit repeatable live boundary check:

```sh
npm run test:live -- --create-one-issue
```

**Each run creates one real issue.** It first proves two DENY requests send no GitHub calls, then checks one ALLOW sends one installation-token request and one issue POST. It checks audit field allowlisting and absence of keys, tokens, and issue text. Audit goes to ignored `audit.live.jsonl`; safe verification metadata goes to `live-verification.json`. This check is separate from `npm test`, which never contacts GitHub. Startup's read-only installation lookup is separate from per-request call counts. No failed creation is automatically retried.

## Shared contract v1

`contract.schema.json` is the proposed common request shape. No existing team contract was supplied. Identity fields in a request are rejected rather than trusted.

```json
{
  "version": 1,
  "action": "github.issue.create",
  "repository": "demo-owner/orbitport-test",
  "title": "Example issue",
  "body": "Example description"
}
```

The credential is passed separately to `workflow(request, token)` by the authenticated server transport. It never belongs in the request JSON or audit records. Responses include all six shared metadata fields below, plus `version`, `result`, `mode`, and `githubCalled`; successful responses also have `issue.number`. `contract.d.ts` describes the request, response, and adapter interfaces for both paths. Real responses construct `issue.url` from the configured repository and validated issue number. GitHub response bodies and raw errors are not returned.

Audit records contain the requested contract fields:

| Field | Trusted source |
| --- | --- |
| `agentId` | Validated credential, or `unverified` |
| `action` | Fixed action mapping: `github.issue.create` |
| `resource` | `designated-test-repo` or `other-or-invalid` (trusted resource aliases) |
| `tokenExpiresAt` | Validated expiry in epoch milliseconds, or null |
| `requestId` | Server-generated UUID |
| `decision` | ALLOW/DENY from policy after credential validation |

Additional metadata: contract version, timestamp, mode, operation result, and whether the GitHub adapter was invoked. `githubCalled` means adapter invocation, including in MOCK mode; it is not an HTTP request count. No raw repository strings from untrusted requests, title, description, bearer token, installation token, JWT, key, provider response, or error text enter the audit. JSONL files are created with owner-only permissions and ignored by Git.

An authorization record is appended **before** the GitHub adapter runs; an outcome record follows for ALLOW. Both have the same request ID. Audit failure before execution prevents the operation. A failure to persist the outcome can occur after issue creation, and network timeouts can leave creation uncertain. There are no automatic retries or exactly-once guarantees across resubmissions. Inspect the test repository before retrying an uncertain operation. The console collapses records by request ID and shows up to 500 requests from the current process; JSONL survives restart but is not replayed into the UI.

## Connect real credentials, policy, audit, and GitHub

`integration.mjs` exports `connectSpaceComputer`. It requires all three team-owned adapters and has no simulated fallback:

```js
const workflow = connectSpaceComputer({
  repository: 'laurenc06/orbitport-issue-test',
  credentials: { validate: validateCredential },
  policy: { authorize: evaluatePolicy },
  audit: { append: appendAuditMetadata },
  app: { appId, installationId, privateKey },
});
// Trusted server transport extracts bearer credentials; never trust body.agentId.
const response = await workflow(requestBody, bearerToken);
```

Adapters must implement:

- `credentials.validate(token, {action, repository})`: verify issuer/signature or server-side credential lookup, revocation, expiry, and exact action/resource scope. Return `{agentId, expiresAt}` (epoch milliseconds) or null. The workflow independently rejects expired and unknown identities.
- `policy.authorize({agentId, action, repository})`: return exactly `ALLOW` or `DENY`. Errors and other values deny. Match the provided Cedar policy semantics: only developer issue creation in the configured test repository. `cedarPolicy(repository)` is an executable local policy implementation.
- `audit.append(metadata)`: durably persist the supplied metadata, rejecting on failure. Do not enrich it with credentials or issue contents.

The GitHub App must be installed on the designated test repository with Issues write permission. Its private RSA key stays in server memory, loaded by the hosting server's secret mechanism. The adapter creates a short-lived App JWT and requests an installation token restricted to the configured repository and Issues write. DENY never calls this adapter, so it does not even request an installation token. Requests use fixed GitHub API endpoints, disabled redirects, and bounded timeouts. The browser has no connection to the GitHub API or credential issuance.

The private real test repository is [laurenc06/orbitport-issue-test](https://github.com/laurenc06/orbitport-issue-test), created and verified with Issues enabled on November 10, 2026. The mock console continues to use `demo-owner/orbitport-test`; creating the real repository does not enable live operations. The 60-second limit applies to local delegated credentials, not to GitHub's independently managed installation-token lifetime.

The operator server supports MOCK and REAL GitHub modes and stays loopback-only. Both modes use local operator-selected identities. For production agent use, mount the connected workflow behind the team's authenticated server transport; do not expose the operator's identity selector. Successful issue numbers and links are retained separately from audit records in bounded process memory so they survive a browser reload, but not a server restart.

## Validation and remaining checklist

- 4Orbit baseline: backend 140 passed, 1 live test skipped; console 30 passed; both typechecks passed.
- Orbitport baseline attempted: `make test` stopped because Go is unavailable; `cargo test --locked --workspace` stopped because Cargo is unavailable. No upstream source changes were made.
- All 20 automated tests pass, including live-mode confirmation and safe result links, App installation discovery, developer ALLOW, security/other-repo DENY, zero GitHub calls including token exchange on DENY, one issue POST on ALLOW, credential expiry/revocation, audit failure/privacy, and loopback/origin restrictions. The normal suite uses stubbed GitHub transport.
- Live GitHub verification passed on November 10, 2026: [issue #1](https://github.com/laurenc06/orbitport-issue-test/issues/1) was created by `laurenc06-orbitport-test[bot]`. Two DENY requests made zero GitHub calls; one ALLOW made exactly one issue POST. Audit privacy checks passed. See `live-verification.json` for machine-readable evidence.
- Browser verification passed the mock workflow, activity counts, and inspection of all six agreed metadata fields. The live console also loaded with the real repository, REAL GITHUB label, local-credential notice, and required confirmation checkbox. Previews are saved as `console-preview.png` and `console-live-preview.png`.
- Pending external details: the team's reference commit and agreement on this contract, and concrete SpaceComputer validation/policy/audit adapters. Live GitHub works; live SpaceComputer integration has not been verified.

This example does not change Orbitport's existing gateway or plugin routes. Go/Rust baseline checks remain required in a configured development environment before merge.

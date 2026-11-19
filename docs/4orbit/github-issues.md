# GitHub issue creation in the console

This increment adds `github.issue.Create`, a separate Go `plugin-github`, and
**GitHub** in the existing operator console. It uses the same `authz.Evaluate`
engine, active policy bundle, signed agent PAT identity, and Activity feed as KMS.

The scope is **one configured repository belonging to one configured tenant**.
Repository discovery, Gemini/MCP tools, autonomous runs, comments, and PRs are
not included. `github.ListRepositories` returns the operator-configured registry,
not a live inventory of the App installation. Repository owner/name attributes
are derived from that trusted registry; request-supplied attrs/tags are rejected.

## 1. Start with mock mode

From this checkout's root, with Docker Desktop running:

```sh
make 4orbit-up
```

The Makefile uses the stable `orbitport` Compose project, including from a
worktree. To target a different existing stack, set `COMPOSE_PROJECT_NAME`
or `FOURORBIT_PROJECT` to its project name.

Open <http://127.0.0.1:4317/#/github>.

1. Confirm the page says **MOCK**.
2. Choose `developer-agent` and `demo-owner/orbitport-test`.
3. Enter a title and description.
4. Click **Check active policy**. The default template allows the developer.
5. Click **Run mock issue creation**. Expect ALLOW and a clearly marked mock result.
6. Open **View audit decision**. Expect `github.issue.Create`, the repository,
   active policy version, and `MOCK · SUCCESS`.
7. Repeat as `security-agent`. Expect DENY and no provider call.

If your existing active policy predates this integration, it is deliberately not
changed by startup. In **Policies**, add the rule below, substituting
`demo-owner/orbitport-test`; save a version, run its tests, and activate it.
Alternatively, to reload the complete demo template as a new version:

```sh
make FOURORBIT_RESEED=true 4orbit-seed
```

Reloading the template replaces the active demo configuration. Use a targeted
policy edit when you want to retain existing policy changes.

## 2. Configure the real GitHub App

Use a GitHub App installed on the intended account/org with only the intended
test repository selected and repository **Issues: Read and write** permission.
The installation must be on the repository owner. Existing demo App credentials
can be reused when their installation covers this repository.

Keep the App private key local. Create `.4orbit/github/` and copy it to `.4orbit/github/app.pem` in this
checkout and restrict permissions:

```sh
chmod 600 .4orbit/github/app.pem
```

The `.4orbit/` directory is git-ignored. The key file must be readable by the
plugin container's user; the Makefile passes your user/group for the local
GitHub container, just as it does for the seed container. Do not paste the key
into the browser or commit it. A mounted PEM is the local-demo credential
storage choice; OpenBao/Transit-backed signing is future work.

Copy `.4orbit.env.example` to `.4orbit.env` only if you do not already have one.
Edit these settings in `.4orbit.env`:

```dotenv
ORBITPORT_GITHUB_MODE=real
ORBITPORT_GITHUB_REPOSITORY=4-Orbit/orbitport-issue-test
ORBITPORT_GITHUB_TENANT=noop-tenant
ORBITPORT_GITHUB_APP_ID=YOUR_NUMERIC_APP_ID
ORBITPORT_GITHUB_INSTALLATION_ID=YOUR_NUMERIC_INSTALLATION_ID
```

`noop-tenant` is the local demo stack's tenant. Do not use it as a tenant mapping
for a production installation.

Restart the updated stack with `make 4orbit` (images were built in step 1).
The real mode must start successfully; it never falls back to mock if credentials
are missing or invalid. The GitHub page should now say **LIVE**.

## 3. Grant the developer access to the real repository

In **Policies**, choose **Plain language**, then **Add rule**:

1. Choose **Allows**, service **GitHub**, and **Agents with a role** → `developer`.
2. Leave **Create issues** selected.
3. Select the configured repository under **On**. You can enter another
   `owner/repository` to draft a policy, but this does not configure the App or
   make an unconfigured repository executable.
4. Optionally set an expiry. Give the rule a unique name, then **Add rule**.
5. Save a new version. Add tests for developer ALLOW, security DENY and a different
   repository DENY; run them and activate the version.

The preview reads “Agents with the developer role can create issues in
4-Orbit/orbitport-issue-test.” Existing repository-specific GitHub rules also
open in this form. Advanced rules that cannot be represented exactly remain
editable in **Cedar code**. Create issues is the only supported GitHub action;
close/edit operations and autonomous agents are separate work.

A denied GitHub policy check can also offer **Grant this…**, which prepares a
rule for that agent, action and repository in your draft. It never activates the
rule automatically. Changing the GitHub repository configuration never broadens
existing policies.

In **GitHub**, check the active policy first. A click on **Create GitHub issue**
then performs one real issue creation. Success returns the issue number and a
link constructed from the configured repository. Test a denied agent as well:
DENY happens before any token exchange or GitHub request.

## Request flow and audit

- `/api/github/issues` accepts only JSON and a registered agent ID, repository,
  title and description. It shares the existing console rate limit and Host check.
- The console backend obtains a short-lived **agent** PAT through
  `policy.IssueAgentToken`. Its operator token is used only for that issuance;
  the agent token stays in server memory and is used for `github.issue.Create`.
- The gateway validates the PAT, resolves the account tenant, and sends those
  trusted identity fields to the separate internal gRPC GitHub service.
- The plugin refuses unconfigured repositories and foreign tenants, reads the
  active policy without a stale cache, and evaluates through the shared engine.
- It synchronously records the decision before any GitHub access. A policy or
  decision-audit outage blocks execution. The acknowledged audit is the policy
  service's in-memory ring; it is not a durable transaction guarantee.
- On ALLOW in real mode it signs an App JWT, mints an installation token narrowed
  to the configured repository and `issues: write`, and makes one issue POST.
  URLs are fixed to `api.github.com`, redirects are disabled, requests time out,
  and no automatic retry is performed.
- The outcome updates the decision's Activity row. Optional policy JSONL keeps
  both decision and outcome records. A missing outcome remains visibly pending.
- Audit records omit title, description, keys, bearer tokens, installation tokens,
  raw provider errors and unconfigured repository input. `githubCalled` means a
  real provider attempt, including token exchange; it does not count HTTP calls.

A timeout may occur after GitHub creates the issue. An `ERROR`, pending outcome,
or `OUTCOME_AUDIT_UNAVAILABLE` is not proof that nothing was created. Check
Activity and GitHub before manually retrying. Exactly-once/idempotency support
is not included.

## Validation

```sh
cd console
npm ci
npm test
npm run typecheck
npm run build

# From plugins/, with Go 1.26+
go test ./pkg/core/authz ./pkg/plugin/githubissues ./pkg/plugin/policy

# From the repository root, with Rust/protoc installed
cargo test --locked -p gateway services::github
```

Tests use fake providers/transports; they create no real issues. They cover
allow/deny, tenant/repository isolation, strict parameters, audit-before-call,
policy/audit outages, narrowed GitHub tokens, fixed endpoints, credential
separation, sanitized failures, and no automatic retries.

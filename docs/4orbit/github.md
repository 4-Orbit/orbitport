# GitHub agents

GitHub is a second service enforced the same way as KMS: `github.issue.Create` on a `Repository` resource, checked by `plugin-github` (`plugins/pkg/plugin/githubissues`) with the same `authz.Evaluate` engine, active policy, signed agent PAT identity and Activity feed.

**What works today:** one operator-configured repository for one tenant, issue creation only, from the console's **GitHub** page. `github.ListRepositories` returns that configured registry, not the App installation's repositories. Repository owner and name come from the registry; attributes or tags in the request are rejected.

The remaining work is listed in [`TODO.md`](TODO.md) (Phases 5 and 7), and the design for it is in [What's next](#whats-next).

---

## 1. Try it in mock mode

With the stack running (`make 4orbit-up`), open <http://127.0.0.1:4317/#/github>.

1. The page says **MOCK**.
2. Choose `developer-agent` and `demo-owner/orbitport-test`, and enter a title and description.
3. **Check active policy**: the default template allows the developer.
4. **Run mock issue creation**: ALLOW, with a clearly marked mock result.
5. **View audit decision**: `github.issue.Create`, the repository, the active version, and `MOCK · SUCCESS`.
6. Repeat as `security-agent`: DENY, and no provider call.

If your active policy predates the GitHub integration, startup doesn't change it. Add the rule in **Policies** (see §3), or reload the whole demo template as a new version, which replaces your active demo configuration:

```sh
make FOURORBIT_RESEED=true 4orbit-seed
```

To target a stack under another Compose project name, set `COMPOSE_PROJECT_NAME` or `FOURORBIT_PROJECT`.

## 2. Use a real GitHub App

You need a GitHub App installed on the repository's owner, with only the test repository selected and **Issues: Read and write**.

1. Copy the App's private key to `.4orbit/github/app.pem` and `chmod 600` it. For example, from the repo root: `mkdir -p .4orbit/github && cp /path/to/downloaded-key.pem .4orbit/github/app.pem && chmod 600 .4orbit/github/app.pem`. `.4orbit/` is git-ignored; Compose mounts that fixed path into the GitHub plugin, so you do not set a PEM path in `.4orbit.env`. Never paste the key into the browser or commit it.
2. In `.4orbit.env` (copy `.4orbit.env.example` if you don't have one):

   ```dotenv
   ORBITPORT_GITHUB_MODE=real
   ORBITPORT_GITHUB_REPOSITORY=4-Orbit/orbitport-issue-test
   ORBITPORT_GITHUB_TENANT=noop-tenant
   ORBITPORT_GITHUB_APP_ID=YOUR_NUMERIC_APP_ID
   ORBITPORT_GITHUB_INSTALLATION_ID=YOUR_NUMERIC_INSTALLATION_ID
   ```

   `noop-tenant` is the local stack's tenant; don't use it for a real installation.
3. `make 4orbit`. The GitHub page says **LIVE**. Real mode fails to start rather than falling back to mock when credentials are missing or wrong.

## 3. Grant access to the repository

In **Policies → Plain language → Add rule**: **Allows**, service **GitHub**, **Agents with a role** → `developer`, **Create issues**, and the configured repository under **On**. The preview reads "Agents with the developer role can create issues in 4-Orbit/orbitport-issue-test." Save a version with tests for developer ALLOW, security DENY and another-repository DENY, then activate it.

You can type another `owner/repository` to draft a rule, but that doesn't configure the App or make the repository usable. A denied check on the GitHub page offers **Grant this…**, which prepares the rule in your draft and never activates it. Rules the form can't represent stay editable in **Cedar code**.

On the GitHub page, **Check active policy**, then **Create GitHub issue** creates one real issue and links to it.

### Create an issue with Gemini

To let Gemini write the issue title and description, set `GEMINI_API_KEY` in `.4orbit.env` (copy `.4orbit.env.example` if needed), then run `make 4orbit-up` to recreate the console container. You can optionally set `GEMINI_MODEL`; its default is `gemini-3.5-flash-lite`. The key is passed to the console at runtime and is not included in its image or sent to the browser.

Open <http://127.0.0.1:4317/#/github>, choose an agent and repository, enter a task in **Ask Gemini to create an issue**, check the confirmation box, and submit. Gemini proposes one title and description; the console immediately submits that proposal through the same `github.issue.Create` path as the manual form. In MOCK mode no GitHub issue is created. In LIVE mode an allowed request creates a real issue. The active policy can deny either request. There is no draft review step, so check the chosen repository and task before submitting.

The console accepts at most five Gemini tasks per minute per process. A task can be up to 4,000 characters. Gemini errors show the HTTP status; if a request is interrupted after submission, check Activity and GitHub before retrying. Without `GEMINI_API_KEY`, manual creation still works and the Gemini endpoint reports that it is unconfigured.

## 4. How a request flows

1. The console's `/api/github/issues` accepts JSON only: a registered agent, the repository, a title and a description. `/api/github/gemini-issues` accepts a task and explicit confirmation, gets one Gemini proposal, then uses the same issue path. Both endpoints have the console Host check.
2. The console server gets a short-lived **agent** PAT through `policy.IssueAgentToken`. The operator token is used only to issue it; the agent token stays in server memory.
3. The gateway verifies the PAT, resolves the tenant, and calls `plugin-github` over internal gRPC with those trusted identity fields.
4. The plugin refuses unconfigured repositories and foreign tenants, reads the active policy **without** a stale cache, and evaluates it.
5. It records the decision **before** any GitHub access. If the policy service or audit is down, nothing runs.
6. On ALLOW in real mode it signs an App JWT, gets an installation token narrowed to the one repository and `issues: write`, and makes one issue POST. Endpoints are fixed to `api.github.com`, redirects are off, requests time out, and nothing is retried.
7. The outcome updates the decision's Activity row; a missing outcome stays visibly pending.

Audit records never contain the title, description, keys, tokens, raw provider errors, or unconfigured repository input. `githubCalled` means a real provider attempt, including the token exchange.

**No exactly-once guarantee.** A timeout can happen after GitHub created the issue, so an `ERROR`, a pending outcome or `OUTCOME_AUDIT_UNAVAILABLE` doesn't prove nothing was created. Check Activity and the repository before retrying.

## 5. Tests

```sh
cd console && npm ci && npm test && npm run typecheck && npm run build
cd plugins && go test ./pkg/core/authz ./pkg/plugin/githubissues ./pkg/plugin/policy
cargo test --locked -p gateway services::github          # from the repo root
```

They use fake providers and create no real issues. They cover allow and deny, tenant and repository isolation, strict parameters, audit-before-call, policy and audit outages, narrowed tokens, fixed endpoints and no retries.

---

## What's next

The goal is a Gemini agent doing real work in GitHub (issues, comments, pull requests) under the same identity, policy versions, tests, simulator and audit as KMS, managed from the console.

```text
 Gemini CLI (sandboxed) ── MCP stdio ── orbitport MCP server (kms_* + github_* tools)
                                              │ agent PAT
                                              v
 console :4317 ── policy.*, runs.* ──>   gateway ── kms.* ──> plugin-kms ──> OpenBao
                                              └── github.* ──> plugin-github
                                                     guard → authz.Evaluate ─DENY─> audit, zero GitHub calls
                                                     │ALLOW
                                                     v
                                     App JWT → installation token (1 repo, minimum permissions) → api.github.com
```

### Actions

| Group | Actions | Permission minted |
|---|---|---|
| `github.read` | `github.contents.Read`, `github.issue.List`, `github.issue.Get` | `contents: read`, `issues: read` |
| `github.write` | `github.issue.Create` (done), `github.issue.Comment`, `github.pr.Propose` | `issues: write`, or `contents: write` + `pull_requests: write` |
| `github.admin` | `github.pr.Merge`, `github.issue.Close` | usually forbidden for agents |

Repository attributes and tags come from GitHub through the installation, never from the caller. An unknown repository, unknown action, a repository the installation doesn't cover, or a failed metadata lookup is a DENY with zero write calls.

### Rules for agents that write code

- **No other path to GitHub.** If the agent can reach GitHub another way (a `gh` login, git credentials, a PEM on disk, an unrestricted shell with network access), Cedar doesn't matter. Run Gemini in a container or Gemini CLI's sandbox, restrict its built-in tools, and mount no GitHub credentials.
- **No push tokens.** An installation token lasts about an hour and `contents: write` can push to `main`. Writes go through `github.pr.Propose`: the plugin creates `agent/<agent-id>/<request-id>`, commits through the Git Data API, and opens a PR. Keep branch protection on default branches as a second layer.
- **Treat issue bodies, comments and files as untrusted.** Write policies as if the agent is already compromised; limiting the damage is the point.

### What Cedar can't do alone

| Need | Approach |
|---|---|
| Which agents, actions and repositories | Tenant policy |
| Only during a time window | `context.currentTime` |
| At most N issues per hour | Quotas in `plugin-github` |
| Ask a human first | Allow `pr.Propose`, forbid `pr.Merge` (a human merging is the approval); later, a `PENDING` result and an approval queue |
| Only `agent/*` branches, never `.github/workflows/` | Trusted context computed by the plugin, or `Branch`/`Path` resources. Needs a new decision (open question 8) |

### Many repositories, one App

One App per org, installed with "Only select repositories", is the outer limit. Cedar narrows it per agent by naming repositories, using `resource in Org::"…"`, or tags. Each call mints a token for the one repository it touches.

### Where the App key lives

Best first: (1) imported into OpenBao Transit so the JWT is signed without the key ever being readable (needs a platform-only key import path in the KMS plugin); (2) stored in the KMS key-store, readable only by `plugin-github`; (3) a mounted file, as today, which is fine only locally.

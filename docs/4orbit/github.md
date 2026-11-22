# GitHub agents

GitHub is a second service enforced the same way as KMS: every `github.*` operation on a `Repository` resource is checked by `plugin-github` (`plugins/pkg/plugin/githubissues`) with the same `authz.Evaluate` engine, active policy, signed agent PAT identity and Activity feed. Agents never hold a GitHub credential: they call the gateway, Cedar decides, and only then does the plugin mint a short-lived installation token narrowed to the one repository and the operation's permissions.

**Scope:** one operator-configured repository for one tenant. `github.ListRepositories` returns that configured registry, not the App installation's repositories. Repository owner and name come from the registry; attributes or tags in the request are rejected.

## Operations

| Action | Group | Trusted context (D-035) | Token permissions | 4Orbit template |
|---|---|---|---|---|
| `github.issue.Create` | `github.write` | — | issues: write | developers |
| `github.issue.Comment` | `github.write` | — | issues: write | developers |
| `github.contents.Read` | `github.read` | `path` | contents: read | developers, except `secrets/` |
| `github.pr.Get` | `github.read` | — | pull_requests: read, contents: read | any agent |
| `github.branch.Create` | `github.code` | `branch`, `isDefaultBranch`, `branchAgent?` | contents: write | developers, own `agent/<id>/` branches |
| `github.commit.Create` | `github.code` | branch fields + `paths`, `touchesWorkflows` | contents: write | developers, own branches, never `.github/workflows/` |
| `github.pr.Create` | `github.pr` | `headBranch`, `baseBranch`, `isDefaultBase`, `headAgent?` | pull_requests: write, contents: read | developers, from own branches |
| `github.pr.Review` | `github.review` | `event`, `headBranch`, `headAgent?`, `authorIsApp` | pull_requests: write, contents: read | security comments or requests changes; no agent reviews its own PR |
| `github.pr.Merge` | `github.merge` | `headBranch`, `baseBranch`, `isDefaultBase`, `headAgent?`, `humanApprovals`, `mergeableState` | contents + pull_requests: write | deployment, with ≥ 1 human approval and `mergeableState == "clean"`; never its own PR |

**Trusted context** is computed by the plugin from GitHub with read-only lookups (default branch, the pull request, its reviews) before deciding, never taken from the caller's params. A failed lookup is a DENY with no write (`LOOKUP_FAILED`). Simulate and Tests show these fields as inputs, as a what-if. Policies use them like any attribute:

```cedar
@id("developer-commit-own-branches")
permit (principal in Role::"developer", action == Action::"github.commit.Create", resource == Repository::"demo-owner/orbitport-test")
when { context has branchAgent && context.branchAgent == principal }
unless { context.touchesWorkflows };
```

**Guarantees that don't depend on tenant policy:**

- `platform.agents-never-write-default-branch`: agents never create or commit to a repository's default branch; changes go through a pull request.
- Commits are fast-forward only: a branch that moved while committing is refused, never overwritten.
- A merge names the head commit it expects (`expectedHeadSha`); a newer head is refused before deciding, and GitHub's merge `sha` parameter enforces it again. `humanApprovals` counts only people (not the App) whose latest review approves *that* commit.
- GitHub never lets an App approve a pull request it opened, and every agent acts as the App, so agents can't approve agent pull requests. A person approves on GitHub. (In mock mode, a review made with the account token stands in for a person.)
- Writes are never retried. Issue, comment, PR and review texts carry a footer naming the agent and request id; commits carry `Orbitport-Agent` and `Orbitport-Request` trailers. None of these texts, file contents or commit messages reach the audit log; it keeps the decision, the trusted context, and stable outcome metadata (number, commit id, branch).

## 1. Try it in mock mode

With the stack running (`make 4orbit-up`), open <http://127.0.0.1:4317/#/github>.

1. The page says **MOCK**.
2. Choose `developer-agent` and `demo-owner/orbitport-test`, and enter a title and description.
3. **Check active policy**: the default template allows the developer.
4. **Run mock issue creation**: ALLOW, with a clearly marked mock result.
5. **View audit decision**: `github.issue.Create`, the repository, the active version, and `MOCK · SUCCESS`.
6. Repeat as `security-agent`: DENY, and no provider call.

Mock mode keeps an in-memory repository (`README.md` with a deliberate typo, `docs/`, `src/`, `secrets/`), so every operation runs end to end with real policy and audit. It resets when `plugin-github` restarts.

To try the other operations, load the template (it grants them on `demo-owner/orbitport-test`, see [Operations](#operations)) and use **Gemini agent** on the GitHub page, or the simulator: pick an action such as `github.pr.Merge`, fill in the trusted context, and evaluate.

If your active policy predates the GitHub integration, startup doesn't change it. Add the rule in **Policies** (see §3), or reload the whole demo template as a new version, which replaces your active demo configuration:

```sh
make FOURORBIT_RESEED=true 4orbit-seed
```

To target a stack under another Compose project name, set `COMPOSE_PROJECT_NAME` or `FOURORBIT_PROJECT`.

## 2. Use a real GitHub App

You need a GitHub App installed on the repository's owner, with only the test repository selected and these repository permissions:

| Permission | Access | Used by |
|---|---|---|
| Metadata | Read | default-branch lookups (always granted) |
| Issues | Read and write | issues and comments |
| Contents | Read and write | reading files, branches, commits, merges |
| Pull requests | Read and write | opening, reading, reviewing and merging pull requests |
| Workflows | **none** | so GitHub itself refuses agent edits to `.github/workflows/` |

Pull request operations also ask for `contents: read`: on a private repository, a token without it can't see branches, and GitHub rejects the pull request's head as invalid. Each call mints a token with only the permissions in the [Operations](#operations) table; the App must have at least those, or the call fails (a `LOOKUP_FAILED` or `ERROR` status) without writing anything. **After changing the App's permissions, an owner of the organization it's installed on must accept them** (the org's Settings → Third-party Access → GitHub Apps → Configure → Review request). Until then the installation keeps its old permissions, and the run log reports "GitHub didn't issue a token with …". Each failed step in the run log has a **Details** button explaining it.

Recommended on the repository, as a second layer that doesn't depend on Orbitport: a ruleset on the default branch requiring a pull request with one approval, and a ruleset restricting creation of `agent/**` branches to the App, so `headAgent`/`branchAgent` (read from branch names) can't be spoofed by people.

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

### Gemini

Set `GEMINI_API_KEY` in `.4orbit.env` (copy `.4orbit.env.example` if needed), then run `make 4orbit-up` to recreate the console container. You can optionally set `GEMINI_MODEL`; its default is `gemini-3.5-flash-lite`. The key is passed to the console at runtime and is not included in its image or sent to the browser. The GitHub page then offers two things:

- **Ask Gemini to create an issue:** Gemini writes one title and description from your task, and the console submits it through the same `github.issue.Create` path as the manual form.
- **Gemini agent:** Gemini works on a multi-step task as the selected agent in the selected repository, with tools for every operation above (`read_file`, `list_directory`, `create_issue`, `comment_on_issue`, `create_branch`, `commit_files`, `open_pull_request`, `get_pull_request`, `review_pull_request`, `merge_pull_request`). **Each tool call is one `github.*` request made with the agent's own token**, so Cedar decides every step; denials go back to Gemini (which usually adapts or explains) and appear in Activity like any other request. The run log lists each call with its decision and the rule that decided it.

Gemini can't choose the agent or the repository, and has no other path to GitHub. A run is limited to 12 tool calls and 2 minutes, and the console accepts at most five Gemini tasks per minute. Repository text (files, issues, pull requests) is untrusted input to Gemini; write policies as if the agent were already compromised. In LIVE mode, allowed calls make real changes; check the agent, repository and task before you confirm.

Without `GEMINI_API_KEY`, everything else still works and the Gemini endpoints report that they are unconfigured.

## 4. How a request flows

1. The console's `/api/github/issues` accepts JSON only: a registered agent, the repository, a title and a description. `/api/github/gemini-issues` accepts a task and explicit confirmation, gets one Gemini proposal, then uses the same issue path. `/api/github/gemini-agent` runs the agent loop; every tool call goes through steps 2–7. All have the console Host check. Agents connecting directly (MCP, Gemini CLI) call the gateway's `github.*` methods with their own PAT and start at step 3.
2. The console server gets a short-lived **agent** PAT through `policy.IssueAgentToken`. The operator token is used only to issue it; the agent token stays in server memory.
3. The gateway verifies the PAT, resolves the tenant, and calls `plugin-github` over internal gRPC with those trusted identity fields.
4. The plugin refuses unconfigured repositories and foreign tenants, reads the active policy **without** a stale cache, and evaluates it.
5. It records the decision **before** any GitHub access. If the policy service or audit is down, nothing runs.
6. On ALLOW in real mode it signs an App JWT, gets an installation token narrowed to the one repository and the operation's permissions, and performs the operation. Endpoints are fixed to `api.github.com`, redirects are off, requests time out, and nothing is retried. Actions with trusted context first make read-only lookups (before step 5's audit, never a write); a failed lookup is a DENY.
7. The outcome updates the decision's Activity row; a missing outcome stays visibly pending.

Audit records never contain the title, description, keys, tokens, raw provider errors, or unconfigured repository input. `githubCalled` means a real provider attempt, including the token exchange.

**No exactly-once guarantee.** A timeout can happen after GitHub created the issue, so an `ERROR`, a pending outcome or `OUTCOME_AUDIT_UNAVAILABLE` doesn't prove nothing was created. Check Activity and the repository before retrying.

## 5. Tests

```sh
cd console && npm ci && npm test && npm run typecheck && npm run build
cd plugins && go test ./pkg/core/authz ./pkg/plugin/githubissues ./pkg/plugin/policy
cargo test --locked -p gateway services::github          # from the repo root
```

They use fake providers and create nothing on GitHub. They cover every operation's allow and deny, trusted context and failed lookups, tenant and repository isolation, strict parameters, audit-before-call, policy and audit outages, narrowed tokens per operation, fixed endpoints, no retries, the default-branch rule, fast-forward-only commits, merge-the-reviewed-head, and a full mock flow under the 4Orbit template (read → branch → commit → PR → review → approve → merge). The console tests cover the Gemini agent loop with a scripted Gemini.

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

### Remaining

Repository discovery from the installation, an Access grid for repositories, the App key in OpenBao, idempotency keys and per-agent quotas, and MCP `github_*` tools for agents that connect directly (see [`TODO.md`](TODO.md), Phases 5 and 7).

### Rules for agents that write code

- **No other path to GitHub.** If the agent can reach GitHub another way (a `gh` login, git credentials, a PEM on disk, an unrestricted shell with network access), Cedar doesn't matter. Run Gemini in a container or Gemini CLI's sandbox, restrict its built-in tools, and mount no GitHub credentials.
- **No push tokens.** An installation token lasts about an hour and `contents: write` can push to `main`. Agents write through `github.branch.Create`, `github.commit.Create` (the Git Data API, fast-forward only) and `github.pr.Create`, each decided by Cedar, and never receive a token. Keep branch protection on default branches as a second layer.
- **Treat issue bodies, comments and files as untrusted.** Write policies as if the agent is already compromised; limiting the damage is the point.

### What Cedar can't do alone

| Need | Approach |
|---|---|
| Which agents, actions and repositories | Tenant policy |
| Only during a time window | `context.currentTime` |
| At most N issues per hour | Quotas in `plugin-github` |
| Ask a human first | `context.humanApprovals >= 1` on `github.pr.Merge` (done); later, a `PENDING` result and an approval queue |
| Only `agent/*` branches, never `.github/workflows/` | Trusted context (D-035, done): `branchAgent`, `paths`, `touchesWorkflows` |

### Many repositories, one App

One App per org, installed with "Only select repositories", is the outer limit. Cedar narrows it per agent by naming repositories, using `resource in Org::"…"`, or tags. Each call mints a token for the one repository it touches.

### Where the App key lives

Best first: (1) imported into OpenBao Transit so the JWT is signed without the key ever being readable (needs a platform-only key import path in the KMS plugin); (2) stored in the KMS key-store, readable only by `plugin-github`; (3) a mounted file, as today, which is fine only locally.

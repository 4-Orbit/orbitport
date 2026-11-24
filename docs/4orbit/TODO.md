# 4Orbit: status and remaining work

What's built, what's left, and the order to build it in. How to run the stack is in [`DEPLOY.md`](../../DEPLOY.md). The design is in [`README.md`](README.md).

Sizes: **S** ≈ ½–1 day, **M** ≈ 2–3 days, **L** ≈ 4–5 days.

---

## Done

| Area | What exists | Where |
|---|---|---|
| Cedar engine | One `cedar-go` engine for enforcement and the playground: schema, platform policy, fail-closed evaluation, `@id`-named policies, denial explanations (`authz.Explain`) | `plugins/pkg/core/authz` |
| Agent identity | Signed `agent_id` PAT claim (patissuer), verified by `plugin-auth`, forwarded as gRPC metadata. Agent PATs last 60 s–24 h | patissuer, auth, `gateway/src/caller.rs` |
| KMS enforcement | Every KMS RPC is checked before OpenBao is touched; a DENY makes zero backend calls. `enforce` and `shadow` modes | `plugins/pkg/plugin/kms/{guarded,agent_authz}.go` |
| Policy store | Immutable versions in OpenBao KV v2, test suites, activation gated by tests, rollback, duplicate detection, decision audit ring, paging | `plugins/pkg/plugin/policy` |
| Console | Activity, Access, Policies (Cedar editor and plain-language rule builder), Simulate, Tests, Versions, Agents, GitHub, Help | `console/` |
| Console usability | Undo and confirmations; Draft → Saved → Active status strip; glossary and help; **Why was this denied?** with **Grant this…** (PR #13); **Run it for real** (PR #13); paging for versions, activity, keys and the access grid (PR #10); deleting an agent offers to delete its rules; pickers for agents, keys and repositories; rate-limit handling | `console/src` |
| Save and activate | Activate straight from the Policies page, after a preview of what changes (KMS decisions, GitHub issue creation, tests), with the test gate in place (PR #19) | `console/src/pages/PoliciesPage.tsx` |
| GitHub operations | Issues, comments, file reads, branches, commits, pull requests, reviews and merges on a `Repository` resource, enforced by `plugin-github` with the same engine and audit, with trusted context (D-035). Mock and real (GitHub App) modes; plain-language GitHub rules; a console Gemini agent whose every tool call is decided by Cedar, with a preflight (policy and App installation permissions) so denied work costs no Gemini tokens, live progress, Stop, and a progress toast | `plugins/pkg/plugin/githubissues`, [`github.md`](github.md) |
| Delegated credentials | Process-local, scoped, short-lived credentials for one external action (PRs #1–#4). Not yet wired to an operation route | `gateway/src/agent_delegation.rs`, [`docs/ucsb-capstone-agent-delegation.md`](../ucsb-capstone-agent-delegation.md) |
| Tooling | `4orbit.compose.yaml`, the seed, `scripts/4orbit/rpc.sh`, `make 4orbit-*`, `make 4orbit-e2e`, console CI, the console browser e2e (`npm run e2e:browser`) | repo root, `scripts/4orbit` |

---

## Remaining, in order

Each phase unblocks the next. Within a phase the order is a suggestion.

### Next up

Since the console can now act in GitHub (branch, commit, open and merge pull requests) with no sign-in, the order below moves the first slice of Phase 2 ahead of the rest of Phase 1:

1. **Land PR #23** (GitHub operations and the console Gemini agent). One check left: a real comment on a pull request.
2. **Durable audit** (Phase 1). Every restart (`make 4orbit-up`) erases Activity, including the record of what agents did in GitHub.
3. **CI e2e** (Phase 1). The 4Orbit e2e and the browser specs only run when someone remembers to.
4. **Sign-in, then separate permissions for actions with side effects** (Phase 2). Gemini runs, commits and merges shouldn't be one click away for anyone who can reach the console.
5. **Idempotency and quotas** (Phase 5). Agents now run in loops; a per-agent quota should trip before GitHub's limits, and a retry after a timeout shouldn't duplicate an issue or pull request.
6. The rest of Phase 1 (**Export and import**, **Version names and hiding**), then Phase 2's roles and attribution.

Phase 7's MCP tools and the Gemini CLI sandbox are with the agents team; their method contract is the [Operations](github.md#operations) table.

### Phase 0: merge what's in flight

- [ ] **PR #23: GitHub operations and the console Gemini agent.** Draft; CI green. Real-mode check left: commenting on a pull request.

### Phase 1: keep work and prove it (≈ 1 week)

Cheap, and everything later depends on it: dev OpenBao forgets everything on restart, and nothing checks the 4Orbit e2e in CI. Do the two S items first; the M items come after Phase 2's sign-in and side-effect permissions (see [Next up](#next-up)).

- [ ] **Durable audit (S).** Set `ORBITPORT_POLICY_AUDIT_DIR` on a volume in `4orbit.compose.yaml`, and replay it into the ring on start. A real store waits for open question 4. First: every restart erases Activity today, including agents' GitHub actions.
- [ ] **CI e2e (S).** Add a job to `.github/workflows/e2e.yml` that runs `make 4orbit-up && make 4orbit-e2e` with the public runtime images. Include the console browser specs that only need mock mode (`npm run e2e:browser`).
- [ ] **Export and import (M).** Export a JSON bundle (`orbitport-policy-bundle-v1`: policies, agents and roles, tests, version info). Import loads it into the draft only: validate, show the diff against active, and ask before replacing the tests. Done when export → `make 4orbit-down && make 4orbit` → import → activate gives identical decisions (e2e).
- [ ] **Version names and hiding (M).** Editable name, description, *hidden* and *pinned*, stored at `tenants/<t>/versioninfo/<n>` apart from the immutable version; `policy.UpdateVersionInfo` (a `policy.Write` action, audited); a stored "+1 rule · 1 decision changes" summary per version; a "Show hidden versions" toggle. The active version can't be hidden.

### Phase 2: console sign-in (≈ 1.5 weeks)

Today anyone who can reach `127.0.0.1:4317` acts as the operator, and the console can already change real state in GitHub through the Gemini agent (commits, pull requests, merges). The console has to know who is acting. Sign-in and side-effect permissions come before the rest of Phase 1 (see [Next up](#next-up)).

- [ ] **Sign-in (L).** OIDC login (Orbitport already uses Auth0 for service tokens). The BFF keeps holding the operator PAT; the browser gets a session cookie only.
- [ ] **Separate permissions for actions with side effects (S).** Gemini agent runs, GitHub issue creation, Save and activate, Run it for real, and later key creation, each behind its own permission checked in the BFF. Do right after sign-in.
- [ ] **Console roles (M).** At least *viewer* (read, simulate), *editor* (save versions, edit tests) and *activator* (activate, roll back), checked in the BFF.
- [ ] **Record who did it (S).** `activatedBy`, version authors and console-run labels name the signed-in user, not the operator token.

### Phase 3: connect your own agents (≈ 2 weeks)

Agents can already use KMS through `kms-mcp` with a minted agent PAT. What's missing is managing them from the console and making the credentials safe to hand out.

- [ ] **Register and remove agents on the Agents page (M).** Today agents are added in the Policies entities editor. Registration should be one form (id, roles, description), saved through the draft like every other change.
- [ ] **Per-agent pages (L).** `#/agents/<id>`: role chips, what the agent can do on each key and repository in plain language (each line naming its rule), what expires soon, recent Activity, and **Grant…**, **Copy permissions to a new agent**, **Mint token**, **Remove agent**. Uses Matrix, Explain and ListAudit; no new backend.
- [ ] **Roles editor that scales (S).** Replace the agents × roles checkbox grid with role chips per agent and a Roles list with member counts. Fold into the agent pages where possible.
- [ ] **Require `agent_id` (S).** A tenant setting that rejects account PATs on KMS calls, so an account PAT handed to an agent can't skip agent policies.
- [ ] **Revoke agent tokens (M).** Today revocation is expiry-only (`accountnoop` doesn't check `jti`). Keep a revocation list checked at enforcement, with **Revoke** on the agent page. Depends on open question 1.
- [ ] **Long-running agents (M).** A narrow capability to refresh one agent's token, so a runner doesn't need the operator PAT.
- [ ] **Client setup in the console (S).** The ready-to-paste config after **Mint token** for Claude Code, Claude Desktop, Codex and Gemini CLI, using `mcp/scripts/kms-mcp-from-file.sh`.

### Phase 4: real key creation (≈ 1.5 weeks)

The seeded keys are real Transit keys, but OpenBao runs in dev mode (in memory, root token `root`) and keys can only be created over JSON-RPC.

- [ ] **Persistent OpenBao profile (M).** A compose profile (or deploy notes) with integrated Raft storage, TLS, a real unseal (auto-unseal through a cloud KMS or HSM), and scoped credentials for `openbao-proxy` instead of the root token. `KMS_OPENBAO_PROXY_URL` is the only plugin change.
- [ ] **Authorize `kms.CreateKey` for agents (S).** Evaluate it against a synthetic `Key` built from the request (alias, spec, usage, tags).
- [ ] **Keys page (M).** List keys with scheme, spec, usage and tags; **Create key** with only the specs that fit each scheme. A dedicated BFF endpoint that validates the input (like `console/server/run.ts`), not a raw `kms.CreateKey` passthrough. Requires the Phase 2 permission.
- [ ] **Decide on key removal (S).** The KMS has no delete. Either add disable/delete, or hide keys in the console so test keys don't clutter pickers.
- [ ] **Ethereum, PQC and threshold policy tests**, once the private OpenBao plugin repos are available (open question 5).

### Phase 5: GitHub operations (≈ 3 weeks)

Issues, comments, file reads, branches, commits, pull requests, reviews and merges work on one configured repository ([`github.md`](github.md#operations)). The design for the rest is in [`github.md`](github.md#whats-next).

- [ ] **Idempotency and quotas (M).** An idempotency key (a hidden `requestId` marker checked before creating), and per-agent rate quotas in `plugin-github` that trip before GitHub's limits. First in this phase: Gemini agents now run in loops.
- [ ] **Repository discovery (M).** Fill `github.ListRepositories` from `GET /installation/repositories`, so a repository selected in the App becomes governable with no config change.
- [ ] **`github.issue.List` / `Get` (S).** Read issues, for triage agents.
- [ ] **App private key in OpenBao (M).** Store the PEM in the KMS key-store, readable only by `plugin-github`. Later, Transit key import so the key can't be read back out (needs a platform-only import path in the KMS plugin).
- [ ] **Access grid for repositories (M).** Agents × GitHub actions × repositories on Access, and repositories in Simulate's explanations.
  *Partly there:* Simulate, Tests and Activity handle repositories and their trusted context; the Access grid is still keys only.
- [x] **More actions (L).** `github.contents.Read`, `issue.Comment`, `branch.Create`, `commit.Create`, `pr.Create`, `pr.Get`, `pr.Review` and `pr.Merge`, with trusted context (D-035) and a console Gemini agent that uses them. See [`github.md`](github.md#operations).
- [ ] **Generalize the audit fields (S).** `providerCalled`, `providerOperation` and `providerResult` instead of `kms*`/`github*`, and update the e2e redaction checks.
- [ ] **Delegated credentials: wire or retire (S).** Either route an operation through `agent_delegation.rs` and `authz.Evaluate`, or remove it in favor of agent PATs (recommended unless the external call happens outside the gateway).

### Phase 6: change safely (≈ 1.5 weeks)

Before agents act on their own, operators need to see what a change would break.

- [ ] **Shadow trials of one version (L).** **Try in shadow** on Versions: the KMS enforces the active version and also evaluates the trial one, Activity marks disagreements, and the trial ends by itself (≤ 24 h, one per tenant). `policy.StartShadow` / `StopShadow`; `GetActive` returns the trial version.
- [ ] **Warn before removing access that's in use (M).** Delete confirmations and the diff show "used 14× in the last 24 h". `policy.Usage` aggregates allowed decisions from the audit. Needs durable audit (Phase 1).
- [ ] **Readable tests (M).** Optional test groups and a `why`, failures as sentences, "Lock this in?" to turn a changed decision into a test, failures first after a run.

### Phase 7: Gemini agents (≈ 2–3 weeks)

- [ ] **MCP GitHub tools (M).** `github_*` tools in `crates/mcp-core/src/tools.rs` that call the gateway with the agent's own PAT, like the KMS tools.
- [ ] **Gemini CLI in a sandbox (M).** A container with Gemini CLI, the MCP server and an agent PAT, and **no other path to GitHub**: no `gh` login, no git credentials, no App key, and the built-in shell and web tools off or restricted. Done when Gemini creates and comments on issues, and a denied action shows on Activity with an explanation.
- [ ] **Runner and Runs page (L).** Start a run (agent, repository, task, time limit), see status and logs, stop it (kill the container, then optionally a policy change). The runner is a separate service, as privileged as the console. Uses the Phase 3 token refresh.
  *Partly there:* the console's Gemini agent already starts a run, shows each step live, stops at the next safe point, and reattaches after a reload. What's left: a separate runner service and container, a chosen time limit (fixed at 2 minutes today), a Runs page with history, and token refresh for runs longer than the agent token.
- [ ] **Approvals (M, later).** A `PENDING` result and an approval queue for actions marked as needing a human. Until then, `context.humanApprovals` on `github.pr.Merge` is the approval.

### Phase 8: polish and scale (≈ 1.5 weeks)

- [ ] **One message area (S).** One area below the status strip for the newest message and its action; older messages fold into "2 earlier".
- [ ] **Access grid at scale (M).** Filters for role, agent, key tag and action group; **Only show differences**; collapsed agents past 10. 50 agents × 100 keys in under 1 s.
- [ ] **Tabs organized around tasks (M).** Overview · Agents · Rules · Activity · History, with Simulate as a panel available everywhere. Old links redirect. Do it after the agent pages and shadow trials.
- [ ] **Accessibility (M).** Keyboard order and focus handling in the rule form, Escape closes, `aria-live` messages, WCAG AA contrast, reduced motion, a VoiceOver pass, axe-core in the browser e2e.
- [ ] **First-visit tour (S).** Only if people new to the console still get lost.

---

## Open questions

For mentors and SpaceComputer:

1. **Agent PATs in production.** Should the dashboard own agent registration and the `jti` rows? `policy.IssueAgentToken` is a dev-only shortcut until then.
2. **Upstream Cedar.** Does SpaceComputer's planned KMS-side Cedar match our model? Align before Phase 4.
3. **Credit pricing** for `policy.*` and denied KMS calls. Our proposal: free for both.
4. **Where audit should live long term:** an OpenBao audit device, a dashboard DB, or an external log pipeline.
5. **Access to the private OpenBao plugins** (`openbao-eth-plugin`, `openbao-pqc-plugin`, `openbao-threshold-plugin`) for Ethereum and PQC policy tests.
6. **Is GitHub in scope for the gateway**, as a core plugin, or does it stay an extension? This decides how mergeable Phases 5 and 7 are.

For the team:

7. **GitHub repository tags.** Should custom properties or topics (e.g. `agents=allowed`) become Cedar tags? Anyone with repo admin rights could then grant agents access.
8. ~~**Branch and path rules**~~ Decided in D-035 (trusted context computed by `plugin-github`).
9. **Version names:** unique or not? Recommendation: not unique, warn on duplicates.
10. **Who reads the plain-language view?** If non-engineers, keep it the default; if engineers, remember the last mode per user.

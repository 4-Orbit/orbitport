# Plan: Cedar-governed GitHub agents in the main console

**Status:** broader proposal. A first, local-demo issue-creation increment is implemented; see [setup and scope](github-issues.md). It uses a single operator-configured repository and a mounted App key; installation discovery, OpenBao-backed key storage, Access repository axes and later phases remain planned.
**Written against:** `ucsb-capstone` at `970c9ed`, plus the open `feat/why-denied` PR (denial explanations and "Run it for real").

## Goal

Let a Gemini agent do real work in GitHub repositories (create issues, comment, propose code changes) with:

- the same agent identity (signed `agent_id` PAT claim),
- the same Cedar engine, policy versions, tests and simulator,
- the same audit trail and Activity page

that already govern KMS calls. The agents should also be managed from the main console on `:4317`, so nobody has to run `npm run start:real` in `examples/github-issues` and open a second console.

---

## 1. Where we are today

There are two separate systems that look alike but share no code.

| | `examples/github-issues` demo | Main console and gateway |
|---|---|---|
| Cedar engine | `@cedar-policy/cedar-wasm` in Node | `cedar-go` in `plugins/pkg/core/authz`, the **only** engine (D-028) |
| Agent identity | Operator picks an agent from a dropdown; local random tokens (`localCredentials`) | Signed `agent_id` claim in the PAT, verified by `plugin-auth`, forwarded as gRPC metadata (D-024) |
| Agents | Hard-coded `developer-agent` / `security-agent` | Per-tenant entity store, Agents page |
| Policy | Static `policy.cedar`, one repo aliased as `designated-test-repo` | Versioned, tested, activated policy sets in OpenBao KV |
| Audit | Local `audit.jsonl` | `plugin-policy` audit ring (+ optional JSONL), Activity page |
| GitHub access | GitHub App; installation token narrowed to one repo + `issues: write` per call | None |

What the demo does well, and what we should keep:

- DENY never calls GitHub, not even the installation-token exchange. This is tested.
- Installation tokens are narrowed per call (`repositories: [name]`, `permissions: {issues: write}`).
- Audit holds metadata only (no titles, bodies, tokens or provider errors). Authorization is recorded **before** the GitHub call, and an audit failure blocks the operation.
- Fixed API endpoints, `redirect: 'error'`, bounded timeouts, no automatic retries.

**Risk with the current plan to embed the demo in the console:** if the demo's Node workflow is moved into `console/server` as it is, we get a second Cedar engine and an identity source the operator picks by hand. Simulate and Access would no longer show what is actually enforced (breaking D-028), and the demo README itself says its identity selector "must not be exposed as a production agent authentication endpoint." The console UI work is still useful. Only the place where enforcement runs needs to move.

---

## 2. Target architecture

GitHub becomes a second enforced service, built the same way as KMS.

```text
 Gemini CLI (sandboxed)                       operator browser
   │ MCP stdio                                     │
   v                                               v
 orbitport MCP server ── agent PAT ──┐     console :4317 (BFF holds operator PAT)
   (kms_* + github_* tools)          │       Agents · Policies · Simulate · Access
                                     v       Activity · Runs (new)
                               ┌──────────┐         │
                               │ gateway  │<────────┘ policy.*, runs.* (new)
                               └────┬─────┘
             kms.* ─────────────────┼──────────────── github.* (new)
                v                                     v
          plugin-kms                            plugin-github (new)
        guard → authz.Evaluate                guard → authz.Evaluate ──DENY──> audit, zero GitHub calls
                v                                     │ALLOW
             OpenBao                                  v
                                      App JWT → installation token (1 repo, min perms) → api.github.com
                                      (App private key read from OpenBao / KMS key-store)
```

### 2.1 Schema and policy (`plugins/pkg/core/authz/schema.cedarschema`)

New entities:

```cedar
entity Org { tenant: String };
entity Repository in [Org] {
  tenant: String,
  owner: String,
  name: String,
  visibility: String,
} tags String;
```

New actions, grouped like the KMS ones so policies can name a group or an exact action:

| Group | Actions | GitHub permission minted |
|---|---|---|
| `github.read` | `github.contents.Read`, `github.issue.List`, `github.issue.Get` | `contents: read`, `issues: read` |
| `github.write` | `github.issue.Create`, `github.issue.Comment`, `github.pr.Propose` | `issues: write`, or `contents: write` + `pull_requests: write` |
| `github.admin` | `github.pr.Merge`, `github.issue.Close` | usually forbidden for agents |

Example tenant policy:

```cedar
@id("triage.issues")
permit (
  principal in Role::"triage",
  action in [Action::"github.issue.Create", Action::"github.issue.Comment"],
  resource in Org::"4-Orbit"
) when { resource.hasTag("agents") && resource.getTag("agents") == "allowed" };

@id("no-agent-merges")
forbid (principal is Agent, action == Action::"github.pr.Merge", resource);
```

Rules to keep:

- Repository attributes and tags come from GitHub, through the App installation. Callers never supply them. This follows D-017 for keys.
- The tenant fence and `platform.owner` keep working unchanged, because every resource carries `tenant`.
- Fail closed: an unknown repo, an unknown action, a repo the installation doesn't cover, or a GitHub metadata lookup failure all mean DENY with zero write calls.
- Extend `defaults/4orbit/{policy.cedar,entities.json,tests.json}` with GitHub cases so the default set ships with tests.

### 2.2 Enforcement: `plugin-github`

- A Go plugin modeled on `plugin-kms`. Every exported RPC is `guard(...)` around an `*Impl`, calling `authz.Evaluate` with the agent principal from gRPC metadata.
- On ALLOW it signs an App JWT, requests an installation token scoped to **one repository** and the **minimum permissions for that action**, makes one GitHub call, and throws the token away.
- Port the demo's guarantees and tests: DENY means zero GitHub calls (including the token exchange), audit-before-call, no retries, metadata-only audit.
- Gateway: add a `github.*` allowlist and route in `gateway/src/services/` alongside `kms.rs`/`policy.rs`, plus `ORBITPORT_GITHUB_PLUGIN` in `plugins.rs`.
- Relation to `gateway/src/agent_delegation.rs`: TODO.md already lists "Wire the delegated-credential store into an operation route that also calls `authz.Evaluate`", and its tests use `github:create-issue`. We need to choose one of two options:
  - (a) agent PAT → Cedar → plugin call (simpler, recommended)
  - (b) agent PAT → Cedar → delegated credential (≤ 900 s, process-local) → operation

  Option (b) only pays off if the external call happens outside the gateway.

### 2.3 Where KMS fits

The GitHub App private key is the most sensitive secret in this design. Options, best first:

1. **Non-exportable signing key.** Import the App's RSA key into OpenBao Transit (BYOK import) and sign the App JWT with Transit (`RS256` = RSA PKCS#1 v1.5 + SHA-256). The key can then never be read back out. *Blocker:* GitHub generates the key, so we need key import, and our KMS plugin does **not** expose it today (no import path in `plugins/pkg/plugin/kms`). We would add it as a platform-only operation that agents can't call.
2. **Key-store secret.** Store the PEM through the KMS key-store / OpenBao KV. Only `plugin-github` reads it with its own service identity, and agents get no Cedar permission for that path.
3. Keep using a file path like the demo does. That's fine locally, but not the end state.

KMS also provides credential issuance (`policy.IssueAgentToken` → patissuer) and the shared audit pipeline. Commits created through the API by a GitHub App are signed by GitHub, so signing commits with KMS keys is optional and not needed.

### 2.4 The Gemini agent

- **Tools:** add `github_*` tools to the MCP server (`crates/mcp-core/src/tools.rs`), or ship a second binary. The tools call gateway JSON-RPC with the agent's own PAT, exactly like the KMS tools.
- **Client:** Gemini CLI registers the MCP server under `mcpServers` in its settings, with the PAT read from a file.
- **No other way to reach GitHub.** This is the most important rule. If Gemini can reach GitHub some other way (a `gh` login, a PEM on disk, git credentials, an unrestricted shell with network access), Cedar doesn't matter. Run Gemini in a container or Gemini CLI's sandbox, turn off or restrict the built-in shell and web tools (use the CLI's tool include/exclude settings), and don't mount any GitHub credentials.
- **Writing code:** don't give the agent a git push token. An installation token lasts about an hour, can't be shortened, and `contents: write` can push to any branch, `main` included. Instead:
  - Reads go through `github.contents.Read`. A clone with a short-lived read-only token is acceptable if we need a full working tree.
  - Writes go through `github.pr.Propose { repo, baseBranch, files | patch, title, body }`. The plugin creates `agent/<agent-id>/<request-id>`, commits through the Git Data API (blobs → tree → commit → ref), and opens a PR.
  - Keep branch protection on default branches as a second, independent layer.

### 2.5 Managing agents from the console

Most of this extends existing pages:

| Page | Change |
|---|---|
| Agents | Unchanged identity model. Optionally show which repos each agent can reach |
| Policies / Tests / Versions | GitHub actions and `Repository` resources in the plain-English rule builder and test cases |
| Simulate | Choose a repository as the resource, using the explain-why-denied flow from `feat/why-denied` |
| Access | Add a repo axis (agents × GitHub actions × repos), filled from the installation's repo list |
| Activity | GitHub events in the same feed, with a link from `requestId` to the created issue/PR |

New:

- **Runs:** start a run (agent, repo, task prompt, time limit), see its status and logs, stop it. A runner service, separate from the BFF and not loopback-exposed to agents, starts a container with Gemini CLI, the MCP server and a freshly minted agent PAT.
- **Stop needs care:** agent PATs can't currently be revoked locally (`accountnoop` doesn't check `jti`; see TODO.md). Stopping a run means killing the container. If needed, follow up with a policy change, which takes effect within the KMS/GitHub plugin's 5 s policy cache.
- **Approvals (later):** a pending-approval queue for actions marked as needing a human (see §3).

---

## 3. Autonomy under Cedar

Agents can run in a loop on their own. Cedar decides every single action. What Cedar can't do on its own:

| Need | Cedar alone? | Approach |
|---|---|---|
| "Only these agents, these actions, these repos" | Yes | Tenant policy |
| "Only during the demo window" | Yes | `context.currentTime` |
| "At most N issues per hour" | No (no counting) | Quotas in `plugin-github`, shown in the console |
| "Ask a human first" | No | Simplest: allow `pr.Propose`, forbid `pr.Merge`, so a human merging is the approval. Later: a `PENDING` result plus a console approval queue |
| "Only `agent/*` branches", "never touch `.github/workflows/`" | Not with today's context | Trusted context computed by the plugin (`context.branch`, `context.paths`), or new `Branch`/`Path` resources. **This changes the documented "currentTime is the only context" decision and needs an explicit new D-0xx.** |

---

## 4. Many repositories, one App

You don't need an App per repository. One GitHub App per org (and one App can be installed on several orgs), with two layers:

1. **The outer limit (GitHub):** install the App on the org with "Only select repositories". Nothing outside that set is reachable, whatever Cedar says.
2. **Per-agent access (Cedar):** policies name repos directly, use `resource in Org::"…"`, or use repo tags. Each call mints a token narrowed to the one repo it touches.

The console fills in the repo list from `GET /installation/repositories`, so newly selected repos show up in Access and Simulate without code changes.

**Tags from GitHub:** custom properties or topics (for example `agents=allowed`) could become Cedar tags. Anyone with repo admin rights could then grant agents access to that repo by setting the property. Decide on purpose whether that is acceptable, or keep the allowlist in Cedar only.

**Practical step:** the live test repo is `laurenc06/orbitport-issue-test`, under a personal account. Create a test repo under the 4-Orbit org (or a throwaway test org), and have an org owner install the App there with only that repo selected.

---

## 5. Open questions and risks

1. **Prompt injection.** Issue bodies, PR comments and repository files are untrusted input to Gemini. Write policies as if the agent is already compromised. Limiting the damage is the main thing this project provides.
2. **Who mints tokens for long runs?** Agent PATs last 60 s to 24 h. A runner that refreshes them needs the operator PAT or a narrower minting capability. That makes the runner as privileged as the console, so treat it that way (loopback/cluster-only, mode-600 secrets, method allowlist).
3. **Attribution.** Everything appears as `<app>[bot]`. Put the agent ID and Orbitport `requestId` into issue/PR bodies or commit trailers, and record the GitHub object number in the audit outcome.
4. **Audit schema.** KMS events use `kmsCalled`, `kmsOperation` and `kmsResult`. Either generalize these to `providerCalled`, `providerOperation` and `providerResult`, or add GitHub-specific fields. Either way, update the e2e redaction checks.
5. **Rate limits and spam.** GitHub applies primary and secondary (content-creation) rate limits per installation. A runaway loop will hit them, or flood the repo before that. Plugin quotas should trip first.
6. **Retries and duplicates.** The demo offers no exactly-once guarantee. An agent that retries after a timeout creates duplicates. Add an idempotency key (for example a hidden marker containing the `requestId` that is searched for before creating).
7. **Event-driven agents.** Use cases like "triage every new issue" need webhooks, but the console binds loopback only. The options are polling, or a separately deployed webhook receiver with signature verification.
8. **Gemini specifics.** Gemini CLI or the Gemini API with our own tool loop, which model, who pays for the API key, and which built-in tools stay enabled.
9. **Upstream scope.** This is a fork of SpaceComputer's gateway for orbital services. Whether GitHub belongs in the core gateway as a plugin or stays an example/extension affects how mergeable the work is. *A question has been drafted for the sponsors.*
10. **Contract.** The demo's `contract.schema.json` v1 is still marked "proposed". Agree on the request/response/audit shape before two teams implement it twice.

---

## 6. Phased plan

| Phase | Work | Done when |
|---|---|---|
| 0. Agree | This doc, the request/audit contract, sponsor scope answer, org test repo + org-installed App | Team sign-off |
| 1. Enforced issue creation | Schema + defaults + tests for `Repository`/`github.issue.Create`; `plugin-github` with only that RPC; gateway route; App key in OpenBao; console Simulate/Access/Activity get repo resources | e2e: agent PAT ALLOW creates one real issue; DENY makes zero GitHub calls; Simulate matches enforcement |
| 2. Gemini by hand | MCP `github_*` tools; Gemini CLI in a container with an agent PAT and no other GitHub credentials | Gemini creates and comments on issues; a denied action appears in Activity with an explanation |
| 3. Code changes | `github.contents.Read`, `github.pr.Propose`; branch protection; forbid merge; decide on trusted branch/path context | Gemini opens a PR from `agent/<id>/…`; can't push to `main` |
| 4. Console run manager | Runner service, Runs page, start/stop/logs, token refresh, quotas, approval queue | An operator starts and stops an autonomous run from the console |
| 5. Multiple repos | Installation repo listing, org-level policies, optional tag mapping | A new repo selected in the App becomes governable with no code changes |

## Related

- [`README.md`](README.md): architecture, authorization model, decisions D-023 to D-033
- [`../../TODO.md`](../../TODO.md): delegated-credential wiring, agent PAT revocation, require-`agent_id` setting
- `examples/github-issues/`: the demo whose guarantees phase 1 carries over

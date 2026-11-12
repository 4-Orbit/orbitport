# 4Orbit on Orbitport: architecture, authorization model, decisions

4Orbit (UCSB CMPSC 189A capstone) is an authorization layer that lets AI agents use SpaceComputer KMS capabilities based on who the agent is and what it wants, with Cedar making every decision. Its first prototype (`4-Orbit/4orbit`, `prototype-1/` and `web/`) was a TypeScript gate running *in front of* Orbitport: it shared one PAT, took agent IDs on the caller's word, and could be bypassed by anyone holding that PAT.

This fork moves that layer **into** Orbitport. Running it is covered in [`DEPLOY.md`](../../DEPLOY.md), and the remaining work in [`TODO.md`](../../TODO.md).

---

## 1. Architecture

```text
 agent (kms-mcp / curl)           operator browser
   │ agent PAT: signed agent_id     │
   v                                v
┌──────────┐ ValidateToken  ┌─────────────┐   ┌──────────────────────────────┐
│ gateway  │──────────────> │ plugin-auth │   │ console :4317 (loopback)     │
│ (Rust)   │<─ client_id,   └─────────────┘   │ React SPA + Node BFF         │
│          │   agent_id, jti                  │ holds the operator PAT       │
│          │<─────────────────────────────────│ allowlisted policy.* methods │
│          │ Hold → kms_tenant                └──────────────────────────────┘
│          │──> plugin-account(noop)
│          │
│          │ kms.* + gRPC metadata            ┌───────────────────────────────┐
│          │ x-orbitport-agent-id ──────────> │ plugin-kms                    │
│          │ x-orbitport-jti-hash             │  guard(): authz.Evaluate ─DENY┼─> audit
│          │                                  │      │ALLOW                   │
│          │                                  │      v                        │
│          │                                  │  *Impl handler → OpenBao      │
│          │                                  └──────┬────────────────────────┘
│          │ policy.*                               │ GetActive (5 s cache), RecordAudit
│          │───────────────────────────────> ┌──────v───────────────┐
│          │ policy.IssueAgentToken:         │ plugin-policy        │── KV v2 ──> OpenBao
│          │  approve here, mint at ──┐      │ store · validate ·   │   orbitport-policy/
└──────────┘                          │      │ simulate · tests ·   │
                                      v      │ audit ring           │
                              plugin-patissuer└──────────────────────┘
```

**One engine.** `plugins/pkg/core/authz` (built on `cedar-go`) is the only Cedar code. The KMS plugin calls it to enforce, and the policy plugin calls it to validate, simulate, build the matrix and diff, run tests, and authorize policy administration. The playground can't disagree with the KMS.

| Piece | Where | Notes |
|---|---|---|
| Cedar engine, schema, platform policy, 4Orbit defaults | `plugins/pkg/core/authz/` | `schema.cedarschema`, `platform.cedar` and `defaults/4orbit/{policy.cedar,entities.json,tests.json}` are embedded |
| Enforcement | `plugins/pkg/plugin/kms/{agent_authz,guarded}.go` | Every exported KMS RPC is a `guard(...)` around the original handler, now named `*Impl` |
| Policy store and playground API | `plugins/pkg/plugin/policy/` | OpenBao KV v2 (`orbitport-policy`), or in memory when `ORBITPORT_POLICY_OPENBAO_PROXY_URL` is unset |
| Agent identity | `patissuer` (`agent_id` claim), `auth` (verifies it), `gateway/src/caller.rs` (forwards it) | `authnoop` accepts the bearer `agent:<id>` for local tests |
| Gateway methods | `gateway/src/services/policy.rs` | `policy.*` allowlist, `policy.ListKeys` (KMS plugin), `policy.IssueAgentToken` (policy plugin approves, patissuer mints) |
| Seed | `plugins/cmd/fourorbit-seed/` | Operator PAT, demo keys, template v1 with its tests, agent PATs |
| Console | `console/` | Port of 4Orbit GUI v1 plus the playground |

---

## 2. Authorization model

### Entities

| Type | Built from | Attributes |
|---|---|---|
| `Account::"<tenant>"` | A PAT without `agent_id`; the tenant comes from Hold | `tenant` |
| `Agent::"<agent_id>"` in `Role` | A PAT's signed `agent_id`; roles come from the tenant's entity store | `tenant` |
| `Role::"<id>"` | The tenant's entity store | — |
| `Key::"<alias>"` | KMS key metadata. Cedar sees the alias (D-017), never `tenant_…` backend names | `tenant`, `scheme`, `keySpec`, `keyUsage`; the key's `Tags` as Cedar entity tags |
| `KeyStoreKey`, `KeyStoreNamespace` | Key-store name or prefix | `tenant`, `name` or `prefix` |
| `KeyNamespace::"keys"` | `kms.ListKeys` | `tenant` |
| `PolicySet::"active"` | `policy.*` methods | `tenant` |

A tenant's entity store may declare only `Role` and `Agent` entities, with no attributes, and agents may only have `Role` parents. Keys always come from the KMS, so a policy author can't invent key attributes.

### Actions

Actions are the RPC method names, grouped under 4Orbit's vocabulary (this replaces D-013's `use → encrypt` table):

| Group | Actions |
|---|---|
| `use` | `kms.Encrypt`, `kms.Decrypt`, `kms.Sign`, `kms.GenerateDataKey`, `kms.Encapsulate`, `kms.Decapsulate` |
| `rotate` | `kms.RotateKey` |
| `read` | `kms.GetKeyMetadata`, `kms.GetPublicKey`, `kms.ListKeys` |
| `admin` | `kms.CreateKey` |
| `keystore` | `kms_keystore.Put`, `Get`, `List`, `Delete` |
| `policy` | `policy.Read`, `policy.Write`, `policy.Activate`, `policy.Simulate`, `policy.IssueAgentToken` |

A policy can name an exact action (`action == Action::"kms.Encrypt"`) or a group (`action in Action::"use"`). The 4Orbit template uses exact actions to keep Prototype 1's semantics, in which `use` meant only encrypt.

### Context

`context.currentTime` (Unix seconds, a Long) is set from the enforcing plugin's clock and is the **only** context. There's no caller-supplied context at all, so spoofing it isn't possible. The simulator may override the time, and its results are labeled SIMULATED TIME.

### Platform policy (`plugins/pkg/core/authz/platform.cedar`, not editable)

| `@id` | Effect |
|---|---|
| `platform.owner` | permit `principal is Account` on everything in its own tenant. Account PATs keep today's behavior. |
| `platform.tenant-fence` | forbid anything that crosses tenants, whatever a tenant policy says |
| `platform.agents-never-administer-policy` | forbid agents every `policy` action |

Policy administration (`policy.*`) is authorized against the platform policy **only**, so a tenant policy can't lock the account out of fixing its own policies, and it can't let an agent in.

### Tenant policies

- Every policy needs `@id("...")` (1–128 characters of `A-Za-z0-9._:-`). The `platform.` prefix is reserved and duplicates are rejected. Determining policies are reported by `@id`. This replaces D-016's positional `policy0…`.
- Policies are validated strictly against the schema with cedar-go's validator. Problems carry line and column.
- They're evaluated together with the platform policy, and every `forbid` wins.

### Fail closed

Every one of these yields DENY, and the KMS backend is never called:

- an unknown action;
- a missing tenant;
- a malformed agent ID or resource;
- a resource type that doesn't match the action;
- any Cedar evaluation error;
- an active bundle that doesn't compile;
- a policy plugin that can't be reached with no cached bundle (agents only; account principals fall back to the platform policy);
- multiple `x-orbitport-agent-id` values.

A missing or foreign key is evaluated with empty attributes, so an unauthorized agent gets "denied by policy" rather than "not found".

### Audit

There's one event per decision: from the KMS plugin for every KMS RPC, and from the policy plugin for policy-admin attempts and writes. The fields are `ts`, `requestId`, `tenant`, `principal`, `action`, `resource`, `decision`, `determiningPolicies`, `authzErrors` (only the `AUTHORIZATION_ERROR` marker), `policyVersion`, `mode`, `kmsCalled`, `kmsOperation`, `kmsResult` (status and gRPC code only) and `jtiHash`. Events never contain plaintext, ciphertext, tokens, raw backend errors or Cedar diagnostics; the e2e suite checks this. The KMS plugin ships events in 250 ms batches from a bounded queue, logging locally if the policy plugin is unreachable. The policy plugin keeps the newest N events per tenant, and can also append JSONL (`ORBITPORT_POLICY_AUDIT_DIR`).

### Enforcement modes

`ORBITPORT_KMS_AUTHZ_MODE=enforce` (the default) blocks on DENY. `shadow` evaluates and audits every decision but never blocks, which lets you roll policies out to an existing deployment. Events carry the mode.

---

## 3. Decisions (continuing 4Orbit's D-001 to D-022)

| ID | Decision | Supersedes |
|---|---|---|
| D-023 | Cedar enforcement runs in `plugin-kms` using `cedar-go`, behind the gateway. The TypeScript gate is retired. | D-011, and resolves D-021 |
| D-024 | Agent identity is a signed `agent_id` PAT claim, carried from the gateway to plugins as gRPC metadata. Metadata was chosen over a new field in every KMS proto message: there's one place to set it, and HTTP headers are never copied into plugin calls. | D-014 |
| D-025 | Cedar actions are RPC method names, grouped as `use`, `rotate`, `read`, `admin`, `keystore` and `policy`. | D-013 |
| D-026 | Tenant policies require `@id`. | D-016 |
| D-027 | The console is a privileged admin tool. Its BFF holds the operator PAT, binds loopback only, checks the Host header and allowlists methods. | D-018, D-020 |
| D-028 | The playground uses the enforcement engine (via `plugin-policy`), never a second Cedar runtime. | — |
| D-029 | Policy sets are immutable versions in OpenBao KV v2, stored as one JSON-encoded field (OpenBao rejects documents with too many strings). Activation moves a pointer and requires the stored test suite to pass, unless forced. | — |
| D-030 | A PAT without `agent_id` keeps owner permissions (`platform.owner`), so existing customers and e2e suites are unaffected. | — |
| D-031 | Policy administration is authorized against the platform policy only. | — |
| D-032 | The existing key-store Cedar authorizer (`ORBITPORT_KMS_KEY_STORE_CEDAR_POLICY_PATH`) stays as a second, operator-level layer after the agent check, so its behavior and tests are unchanged. | — |
| D-033 | Local images build on public `gcr.io/distroless/*-debian13:nonroot` runtimes through a `RUNTIME_IMAGE` build argument. Upstream defaults still point at `dhi.io`. | — |

---

## 4. Threat model changes

**Closed:**
- *Bypassing Cedar with the PAT.* There's no path to the KMS that skips the KMS plugin's guard.
- *Shared PAT and tenant across agents.* Each agent has its own PAT.
- *Self-asserted agent ID* on the real auth path. The ID is a signed claim; forging or tampering with it gets a 401, which the e2e checks.
- *Long-lived agent credentials.* Agent PATs last 60 s to 24 h, enforced by patissuer.
- *Policy tampering by an agent* (`platform.agents-never-administer-policy`).

**New or remaining:**
- **The operator PAT sits in the console's BFF**, giving full owner rights. Mitigations: loopback bind, Host check, method allowlist, mode-600 file, a 12 h lifetime, and redaction in error paths.
- **An account PAT given to an agent** skips agent policies by design (D-030). Never give an agent an account PAT. A tenant setting that requires `agent_id` for KMS use is listed in TODO.md.
- **Revocation of agent PATs** is expiry-only locally (`accountnoop` doesn't check `jti`). On the real dashboard path, Hold checks `jti`, but agent PATs minted through `policy.IssueAgentToken` have no dashboard row yet (open question 2).
- **Audit is best-effort and in memory.** Events can be dropped if the queue overflows, or lost on restart unless `ORBITPORT_POLICY_AUDIT_DIR` is set.
- **Trusted clock.** Time-limited grants trust the KMS pod's clock.
- **`authnoop`'s `agent:<id>` convention** exists only in the development plugin, which already accepts every token. The real auth plugin rejects it (the e2e checks this).
- **The policy plugin's `GetActive` and `RecordAudit`** are internal gRPC with no authentication, like every other plugin. They must never be published outside the cluster. Patissuer's mint RPC has the same property, and the seed relies on it.

---

## 5. Relation to the delegated-credential store

`gateway/src/agent_delegation.rs` (PR #1) issues opaque, process-local credentials scoped to one `(account, agent, action, resource)` for external-service actions such as `github:create-issue`. It is unchanged. Agent PATs are the identity used for KMS calls; delegated credentials narrow a single external action further. Wiring a delegated-credential operation route through `authz.Evaluate` is listed in TODO.md.

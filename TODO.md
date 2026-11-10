# TODO: 4Orbit on Orbitport

This is the work plan for moving the 4Orbit agent-authorization layer into this Orbitport fork (`4-Orbit/orbitport`, branch `ucsb-capstone`) and adding a **policy playground** to a new operator console. [`DEPLOY.md`](DEPLOY.md) describes how to run the result.

Sources compared: `4-Orbit/4orbit@f2de01d` (Prototype 1, GUI v1, docs) and this repo at `8669055`.

---

## 1. Where things stand

### What 4Orbit has (external gate, TypeScript)

| Piece | Location in 4orbit | What it does |
|---|---|---|
| Cedar gate | `prototype-1/src/cedar.ts` | `@cedar-policy/cedar-wasm`. Fails closed. Sets `context.currentTime` from a trusted clock and overwrites any value the caller sent. |
| Enforcement point | `prototype-1/src/gateway.ts` | Cedar runs first. Only an ALLOW reaches the KMS adapter. Logical action maps to a KMS op through a fixed table (`use→encrypt`, `rotate→rotateKey`). Logical key maps to a KMS key ID. Every request is audited. |
| Policy model | `prototype-1/policies/` | `policy.cedar` (6 permits, one of them time-limited), `schema.cedarschema`, `entities.json` (3 roles, 3 agents, 3 keys). |
| Audit | `prototype-1/src/audit.ts` | JSONL with metadata only: no plaintext, ciphertext, tokens, or raw SDK errors. |
| KMS adapters | `prototype-1/src/kms/` | Mock adapter, plus a real one through `@spacecomputer-io/orbitport-sdk-ts` that uses a single shared PAT. |
| Operator console | `web/` | Vite + React client and a small Node server. Read-only Activity and Access views, plus mock-only test requests. |
| Tests | `prototype-1/test/`, `web/test/` | 560-case permission matrix, US5 expiry boundaries, audit redaction, fail-closed behavior. |
| Docs | `docs/` | Authorization model, threat model, decision log D-001 to D-022, local-stack setup. |

### What Orbitport already has that we can build on

- **Cedar inside the KMS plugin** (`plugins/pkg/plugin/kms/key_store_authorizer.go`, `cedar-go v1.8.0`). It only covers `kms_keystore.*`, and the only rule it checks is `principal.owner == resource.owner`. The principal is the *tenant*, not an agent.
- **PAT minting with expiry** (`plugin-patissuer`), **real PAT verification** (`plugin-auth` plus the `local-pat.compose.yaml` overlay), and a JWKS endpoint (`plugin-jwks`).
- **Per-tenant key namespacing** (`tenant.go`). Key IDs are `kms:<alias>`, and the backend key is `tenant_<hash>_<alias>`.
- **Key metadata with tags**, persisted in KV v2. Policies can use the tags as resource attributes.
- **Local OpenBao** (Transit, KV v2) in `dev.docker-compose.yaml`, behind `openbao-proxy`.
- **`kms-mcp`**, the local MCP server agents use. It authenticates with a PAT.

### The gaps this merge closes (from 4orbit `docs/architecture/threat-model.md`)

| 4Orbit open issue | How the merge closes it |
|---|---|
| Anyone holding the PAT can skip Cedar | Cedar moves into the KMS plugin, behind the gateway. No path to the KMS bypasses it. |
| Every agent shares one PAT and one tenant | Each agent gets its own PAT carrying a signed `agent_id` claim. |
| Agent ID is self-asserted (D-014) | The agent ID comes from the verified PAT, never from the request body. |
| No short-lived credentials | Agent PATs get short TTLs, measured in minutes or hours instead of days. |
| Policy IDs are positional (D-016) | Policies get stable `@id("...")` annotations. The playground needs this. |

---

## 2. Target architecture

```text
 agent (kms-mcp / curl)          operator browser
   │ agent PAT (agent_id claim)     │
   v                                v
┌─────────┐  ValidateToken   ┌───────────┐    ┌──────────────────────────┐
│ gateway │ ───────────────> │plugin-auth│    │ console (127.0.0.1:4317) │
│ (Rust)  │ <─ client_id,    └───────────┘    │ React SPA + Node BFF     │
│         │    agent_id, jti                  │ holds the operator PAT   │
│         │ <──────────────────────────────── │ calls policy.* / kms.*   │
│         │  Hold → kms_tenant                └──────────────────────────┘
│         │ ──> plugin-account(noop)
│         │
│         │  kms.* (+ principal)       ┌────────────────────────────────┐
│         │ ─────────────────────────> │ plugin-kms                     │
│         │                            │  authz.Evaluate() ─DENY─> audit│
│         │                            │      │ALLOW                    │
│         │                            │      v                         │
│         │                            │  provider → openbao-proxy      │
│         │                            └──────┬─────────────────────────┘
│         │  policy.*                         │ GetActivePolicySet (cached)
│         │ ─────────────────────────> ┌──────v───────────────┐
└─────────┘                            │ plugin-policy  (NEW) │── KV v2 ──> OpenBao
                                       │ store / validate /   │  orbitport-policy/
                                       │ simulate / audit     │
                                       └──────────────────────┘
```

Design rules. Each one carries a 4Orbit decision forward or replaces one:

1. **Cedar decides at the KMS boundary.** The engine is `cedar-go`, as mentors directed (D-021). The TypeScript gate is retired.
2. **One engine for enforcement and simulation.** The playground's simulator calls the same Go package (`plugins/pkg/core/authz`) as the KMS plugin, never cedar-wasm. Otherwise "the playground said ALLOW" and "the KMS said DENY" can drift apart.
3. **Fail closed** on every failure: parse errors, evaluation errors, missing policy, an unreachable policy plugin, or a missing principal. This is 4Orbit's existing semantics.
4. **Trusted context only.** `context.currentTime` comes from the KMS plugin's clock. Caller-supplied context is never merged over trusted fields. Only the *simulator* may override time, and it labels the result as simulated.
5. **Logical key = alias** (carries D-017 forward). Cedar sees `Key::"dev-key"`, never `tenant_…` or OpenBao names.
6. **Tenancy still comes from Hold.** Policies are stored and evaluated per tenant, and one tenant can never read or simulate another tenant's policy set.
7. **Backward compatible.** A PAT without `agent_id` keeps today's behavior: the owner can do everything in their tenant. Default-deny applies to agent principals. The existing e2e suites must keep passing.

---

## 3. Transfer inventory

### Port (rewrite into Orbitport)

| From 4orbit | To orbitport | Notes |
|---|---|---|
| `prototype-1/policies/policy.cedar` | `policies/4orbit/policy.cedar` | Rewrite against the new schema (§4.1). Add `@id` to every policy and keep the US5 `when { context.currentTime < 1800000000 }`. |
| `prototype-1/policies/schema.cedarschema` | `plugins/pkg/core/authz/schema.cedarschema` (embedded) | Expand to the real KMS actions with action groups (§4.1). |
| `prototype-1/policies/entities.json` | `policies/4orbit/entities.json` | Same 3 roles and 3 agents. Keys are **not** listed here: they come from KMS metadata at evaluation time. |
| `src/cedar.ts` (`authorize`) | `plugins/pkg/core/authz/authz.go` | Port the fail-closed wrapper, trusted-time injection and diagnostics redaction. Generalize `key_store_authorizer.go` into this package. |
| `src/gateway.ts` (PEP, op table) | `plugins/pkg/plugin/kms/plugin.go` | One `p.authorize(ctx, principal, action, keyRef)` call at the top of **every** RPC handler, before `metadataProvider`/provider calls. The op table is no longer needed because Cedar actions are the RPC names. |
| `src/audit.ts` (event shape, redaction rules) | `plugins/pkg/core/authz/audit.go` and `plugin-policy` audit store | Same fields (`requestId, principal, action, resource, decision, determiningPolicies, kmsCalled, kmsOperation, kmsResult`). Add `tenant`, `jti` (hashed), and `policyVersion`. |
| `src/clock.ts` | `plugins/pkg/core/authz/clock.go` | Inject it so tests can pin time. `kms.Plugin` already has `p.now`. |
| `test/permission-matrix.test.ts` | `plugins/pkg/core/authz/matrix_test.go` | Table-driven: 560 cases across 5 context variants. It also ships as the playground's **default test suite** (§5.4). |
| `test/cedar.test.ts`, `gateway.test.ts` (US5, spoofing, fail-closed) | `authz_test.go`, `kms/plugin_authz_test.go` | Check that a DENY means the provider is never invoked. Use a fake provider that counts calls. |
| Audit-redaction tests | `authz/audit_test.go` | No plaintext, ciphertext, PAT, raw OpenBao error, or caller context in audit events. |
| `web/src/*` (Activity, Access matrix, detail panel, badges, styles) | `console/src/` | Reuse the components. Replace the data source (JSONL file) with gateway RPC. |
| `web/server/*` | `console/server/` | Becomes a BFF that proxies to the gateway. Keep the `127.0.0.1` bind, the Host-header check, and the static server. Drop `test-request.ts` (the simulator replaces it). |
| `web/test/*` | `console/test/` | `boundary.test.ts` changes meaning: the console now holds a PAT (§6, D-018 superseded). |
| `docs/architecture/authorization-model.md` | `docs/4orbit/authorization-model.md` | Update to the merged model. |
| `docs/architecture/threat-model.md` | `docs/4orbit/threat-model.md` | Close the gaps listed in §1 and add the new threats from §8. |
| `docs/decisions/decision-log.md` | `docs/4orbit/decisions.md` | Keep D-001 to D-022 and mark the superseded ones (D-011, D-013, D-014, D-016, D-018, D-020). Add D-023 onward from this file. |
| Vision, requirements, success criteria | `docs/4orbit/` | Copy as-is. |

### Do not port

| Item | Why |
|---|---|
| `src/kms/orbitport.ts`, `@spacecomputer-io/orbitport-sdk-ts` | The authorization layer now lives inside Orbitport, so it doesn't need an SDK client to reach itself. |
| `src/kms/mock.ts` | The simulator never calls a KMS, and the local stack runs real OpenBao. |
| `src/cli.ts`, `scripts/setup-key.ts` | Replaced by `scripts/4orbit/seed.sh` and `examples/kms/rpc.sh`. |
| `@cedar-policy/cedar-wasm` | One engine (rule 2). It could come back later only for client-side syntax highlighting, never for decisions. |
| `audit.jsonl`, `.env`, `.agent-demo-token` | Local runtime state and secrets. **Never copy them.** |
| `sc-docs/` | Mirrors upstream SpaceComputer docs. This repo is the upstream. |
| `prototype-1/` as a whole | Archive it in 4orbit with a README pointer here. |

---

## 4. Backend changes

### 4.1 Cedar model (`plugins/pkg/core/authz`)

- [ ] New schema that keeps 4Orbit's vocabulary as **action groups**:

  ```cedar
  entity Role;
  entity Account { tenant: String };
  entity Agent in [Role] { tenant: String };
  entity Key { tenant: String, scheme: String, keySpec: String, keyUsage: String } tags String;
  entity PolicySet { tenant: String };

  type Ctx = { currentTime: Long };

  action "use", "rotate", "read", "admin", "policy";             // groups
  action "kms.Encrypt", "kms.Decrypt", "kms.Sign", "kms.GenerateDataKey",
         "kms.Encapsulate", "kms.Decapsulate"   in [Action::"use"]
    appliesTo { principal: [Account, Agent], resource: Key, context: Ctx };
  action "kms.RotateKey"                         in [Action::"rotate"]  appliesTo { ... };
  action "kms.GetKeyMetadata", "kms.GetPublicKey" in [Action::"read"]   appliesTo { ... };
  action "kms.CreateKey"                          in [Action::"admin"]  appliesTo { ... };
  action "policy.Get", "policy.Put", "policy.Activate", "policy.Simulate"
                                                  in [Action::"policy"] appliesTo { principal: [Account, Agent], resource: PolicySet, context: Ctx };
  // kms_keystore.* actions keep their current names, resource types KeyStoreKey / KeyStoreNamespace
  ```

  With this schema, 4Orbit's `action == Action::"use"` becomes `action in Action::"use"`.
- [ ] **Platform policy** (`plugins/pkg/core/authz/platform.cedar`, embedded, tenants can't edit it):
  - `@id("platform.owner")` permits `principal is Account` on everything where `principal.tenant == resource.tenant`. This keeps today's behavior and folds in `key_store_default.cedar`.
  - `@id("platform.tenant-fence")` forbids any principal whose `tenant != resource.tenant`.
  - `@id("platform.agents-never-edit-policy")` forbids `principal is Agent` on `Action::"policy.Put"` and `Action::"policy.Activate"`.
- [ ] **Tenant policy** (from `plugin-policy`) is evaluated together with the platform set. Every `forbid` wins, which is how Cedar works.
- [ ] Resource attributes come from KMS key metadata: `scheme`, `keySpec`, `keyUsage`, and the key's `Tags` as Cedar entity tags, so a policy can say `resource.hasTag("env") && resource.getTag("env") == "prod"`.
- [ ] `CreateKey` has no existing key to look up. Evaluate it against a synthetic `Key` built from the request (alias, spec, tags).
- [ ] Policy IDs: require `@id` on tenant policies (validation error without it) and report `determiningPolicies` by `@id`. This replaces positional `policy0..N` (D-016).
- [ ] `Evaluate(req) → {decision, determiningPolicies, errorsRedacted}`. Errors go to logs. Audit records only `AUTHORIZATION_ERROR`, as in 4Orbit.

### 4.2 Agent identity in the PAT

- [ ] `proto/plugins/patissuer.proto`: add `string agent_id = 5;` to `IssueTokenRequest`. Validate it against `^[a-z0-9][a-z0-9_-]{0,63}$`, the same regex as 4Orbit's `auditUid`.
- [ ] `patissuer/plugin.go`: stamp an `agent_id` claim. Add `ORBITPORT_PATISSUER_MIN_TTL_SECS` and allow TTLs under a day for agent tokens. Today the ceiling is in days and there's no floor.
- [ ] `proto/plugins/auth.proto`: add `string agent_id = 5;` to `TokenValidationResponse`. Fill it **only** from a verified PAT. `authnoop` must return it empty, or read it from a dev-only `X-Dev-Agent-Id` header guarded by a loud warning. Decide which (§9).
- [ ] `gateway/src/filters.rs`: carry `agent_id` alongside `client_id`/`kms_tenant`.
- [ ] `proto/plugins/kms.proto`: add `Principal principal = N;` to **every** request message, with `message Principal { string tenant = 1; string agent_id = 2; string jti_hash = 3; }`. Regenerate with `make protoc`. Keep `client_id` for namespacing.
- [ ] `gateway/src/services/kms.rs`: populate `principal` in each of the ~15 call sites. A helper on `KmsRpcCall` avoids repeating it 15 times.
- [ ] Revocation: on the real dashboard path, Hold checks the `jti`. `accountnoop` doesn't check it, so document that local revocation is expiry-only.

### 4.3 KMS plugin enforcement (`plugins/pkg/plugin/kms`)

- [ ] Replace `keyStoreAuthorizer` with `authz.Authorizer`, and delete `key_store_authorizer.go` once its tests pass against the new package.
- [ ] Add an authorization call as the **first** step in Encrypt, Decrypt, Sign, Encapsulate, Decapsulate, CreateKey, GetKeyMetadata, GetPublicKey, GenerateDataKey, RotateKey and the four KeyStore RPCs. To load resource attributes it has to read metadata, but it must not touch a provider until it gets an ALLOW.
- [ ] A DENY returns `codes.PermissionDenied` with the fixed message `"request denied by policy"`. The gateway already maps this to a JSON-RPC error. Check that it also triggers `Release` so a denied call isn't charged.
- [ ] Emit one audit event per decision through `authz.AuditSink`. It should be async, best-effort, and bounded, falling back to a structured `audit` logger on stdout if the policy plugin can't be reached. An audit failure must never turn a DENY into an ALLOW.
- [ ] Policy cache: fetch the active tenant policy set from `plugin-policy` with a TTL (`ORBITPORT_KMS_POLICY_CACHE_TTL_SECS`, default 5) and refetch when the version changes. If the policy plugin is down and nothing is cached, agent principals are denied and Account principals fall back to the platform policy alone.
- [ ] New env vars: `ORBITPORT_KMS_POLICY_PLUGIN`, `ORBITPORT_KMS_POLICY_CACHE_TTL_SECS`, `ORBITPORT_KMS_AUTHZ_MODE=enforce|shadow`. Shadow mode evaluates and audits but doesn't block, which helps roll out to an existing deployment. It defaults to `enforce`.

### 4.4 New `plugin-policy` (Go, `plugins/pkg/plugin/policy`)

- [ ] Register `policy` in `plugins/cmd/plugin` (the dispatcher). Port 50009, metrics on 9000 (host port 9009).
- [ ] `proto/plugins/policy.proto`:
  - `GetActive(tenant) → {version, policies, entities}`
  - `ListVersions(tenant)`, `GetVersion(tenant, v)`
  - `Validate(policies, entities) → {ok, errors[{policyId, line, col, msg}], warnings}`, using the embedded schema with strict validation
  - `PutDraft(tenant, policies, entities, message) → draftVersion`
  - `Activate(tenant, version)`. Runs the attached test suite first and refuses if any case fails, unless `force=true` and the caller is an Account.
  - `Simulate(tenant, version|draft, requests[]) → decisions[]`, where each request is `{principal, action, resource, resourceAttrs?, context?, timeOverride?}`
  - `Matrix(tenant, version|draft)`: every agent × action × known key. This is the Access view.
  - `Diff(tenant, vA, vB)`: the matrix cells whose decision changed
  - `Get/PutTests(tenant)`: saved `{name, request, expect}` cases
  - `RecordAudit(event)` and `ListAudit(tenant, filter, cursor)`
- [ ] Storage: an OpenBao KV v2 mount `orbitport-policy` at path `tenants/<tenant_ns>/{active,versions/<n>,tests,agents}`. KV v2 version metadata provides history and rollback. Add the mount to `docker/openbao/bootstrap.sh`, and add `orbitport-policy` to `openbao-proxy.conf` if the proxy restricts paths.
- [ ] Audit storage: a bounded ring buffer per tenant, plus append-only JSONL on a volume (`/var/lib/orbitport/audit/<tenant>.jsonl`). Leave a real datastore for later (§9).
- [ ] Seed data: when a tenant has no policy set, `GetActive` returns an empty tenant set. Owners keep working through `platform.owner` and agents are denied. The seed script loads the 4Orbit default set.

### 4.5 Gateway (`gateway/src`)

- [ ] JSON-RPC methods `policy.Validate`, `policy.Simulate`, `policy.Matrix`, `policy.Diff`, `policy.ListVersions`, `policy.GetVersion`, `policy.PutDraft`, `policy.Activate`, `policy.GetTests`, `policy.PutTests`, `policy.ListAudit`, `policy.ListAgents`, `policy.PutAgent`, `policy.IssueAgentToken`. Add them to `RpcCall` in `services/jrpc.rs`, plus a new `services/policy.rs` and `ORBITPORT_POLICY_PLUGIN` in `plugins.rs`.
- [ ] Authorization of `policy.*`: the gateway sends these through `plugin-policy`, which runs `authz.Evaluate` with a `PolicySet` resource. Policy administration is governed by Cedar too, and an agent can't grant itself access (`platform.agents-never-edit-policy`).
- [ ] Hold and credits: `policy.*` still needs a Hold to resolve tenancy. Use operation label `policy.<Method>` and agree with SpaceComputer that these cost zero (§9).
- [ ] `policy.IssueAgentToken(agent_id, ttl)`: Account principal only. The gateway calls `patissuer.IssueToken` with `agent_id`. On the real dashboard path, the PAT row (`jti`) must be created by the dashboard, so this is local and dev only for now (§9).
- [ ] Update `swagger.yaml` and `crates/kms-api` if the public types move there.
- [ ] Optional: CORS isn't needed, because the console BFF proxies server to server.

### 4.6 `kms-mcp` and examples

- [ ] No protocol change: an agent just runs `kms-mcp` with its own agent PAT (`ORBITPORT_PAT_FILE=.4orbit/tokens/developer-agent.pat`).
- [ ] Map a DENY to a clear MCP tool error ("denied by policy <id>" is not available to the caller. Return only "denied by policy" and keep the ids in the audit).
- [ ] `examples/kms/ai-agents/`: add a `4orbit-roles` demo with three agents and the same allowed and denied scenarios as `npm run demo`.

### 4.7 Deploy tooling (what DEPLOY.md relies on)

- [ ] `4orbit.compose.yaml` overlay: `plugin-policy`, `console`, `fourorbit-seed` (one-shot), the new env vars on `plugin-kms` and `gateway`, and an audit volume. It stacks on `dev.docker-compose.yaml` and `local-pat.compose.yaml`.
- [ ] `.4orbit.env.example`, covering the variables in DEPLOY.md §4.
- [ ] `policies/4orbit/{policy.cedar,entities.json,tests.json}`: the default demo organization.
- [ ] `scripts/4orbit/seed.sh` (idempotent: keys, policy v1, tests, activate, operator and agent PATs into `.4orbit/tokens/`, mode 600) and `scripts/4orbit/rpc.sh <token-name> <method> <params>`. The seed script mints through `plugin-patissuer` gRPC on the compose network, so it needs no Auth0.
- [ ] Makefile targets: `4orbit`, `4orbit-up`, `4orbit-seed`, `4orbit-ps`, `4orbit-stop`, `4orbit-down`. The existing targets call `docker-compose` (v1). Switch them to `$(COMPOSE) ?= docker compose`.
- [ ] Add `.4orbit/` and `.4orbit.env` to `.gitignore`.
- [ ] Check that `plugin-auth` (real mode, from `local-pat.compose.yaml`) starts without reaching Auth0 when only PATs are used. If it doesn't, add a dev setting so it can.

---

## 5. Frontend: console and policy playground (`console/`)

Stack: Vite and React 19, carried over from `4orbit/web` (D-019). Add **CodeMirror 6** for the editor and write a small Cedar language mode. The console has a Node BFF and binds `127.0.0.1:4317`.

### 5.1 Shell and auth
- [ ] The BFF reads the operator (Account) PAT from `ORBITPORT_CONSOLE_PAT_FILE` and never sends it to the browser. Every browser call goes to `/api/rpc`, and the BFF forwards it to `ORBITPORT_URL/api/v1/rpc` with an **allowlist** of methods: `policy.*`, plus read-only `kms.GetKeyMetadata`, `kms.GetCapabilities` and a key-list call (§9: Orbitport has no `kms.ListKeys` yet).
- [ ] Keep 4Orbit's Host-header loopback check and the `127.0.0.1`-only bind.
- [ ] A header badge shows the tenant, gateway URL, active policy version, and `enforce` or `shadow` mode.

### 5.2 Policy editor
- [ ] A CodeMirror editor for the tenant policy text, with the platform policy shown read-only beside it.
- [ ] Debounced live `policy.Validate`, with inline errors and warnings at line and column.
- [ ] Snippets: "role may use key", "time-limited grant", "forbid prod for role", "tag-based grant".
- [ ] Every policy needs `@id`. Offer a quick fix that inserts one.

### 5.3 Entities editor
- [ ] Agents table: id, roles, description, and created time. Add, remove, and change role membership.
- [ ] A Roles list.
- [ ] Keys are read-only, from KMS: alias, scheme, spec, usage, tags. Keys are created in the KMS, not in the playground.

### 5.4 Simulator and tests
- [ ] Single request: principal, action (grouped by `use`/`rotate`/`read`/`admin`), resource, and optional context. **Time travel** lets you pick a simulated `currentTime`, and the result shows a "SIMULATED TIME" badge. Output: decision, determining `@id`s, and errors.
- [ ] **Access matrix**: port `AccessView.tsx`. Agents × actions × keys, with each cell colored and clicking a cell explaining the decision.
- [ ] **Draft vs. active diff**: the matrix shows only changed cells ("deploying this grants deployment-agent kms.Sign on prod-key").
- [ ] **Test suite**: saved cases with an expected decision, and run-all with pass/fail. It ships preloaded with the 4Orbit permission matrix. Activate is blocked while any case fails.
- [ ] **Replay**: from an Activity row, load the real request into the simulator against the draft ("would my change have blocked this?").

### 5.5 Versions
- [ ] A list of versions with author (tenant or `jti` hash), time, and message.
- [ ] A text diff between any two versions, plus the matrix diff.
- [ ] Activate (runs the tests) and Roll back (activates an earlier version).
- [ ] Export and import the policy set as a `.cedar` and `.json` bundle. Dev OpenBao is in-memory, so this is how you keep your work.

### 5.6 Activity
- [ ] Port `ActivityTable`, `RequestDetailPanel` and `SummaryStrip`, and swap the source to `policy.ListAudit` with polling (`usePolling.ts`).
- [ ] Filters: agent, decision, key, and policy version. "Mock" and "real" badges become "enforce" and "shadow".

### 5.7 Agents and tokens
- [ ] Mint a short-lived agent PAT with a TTL picker (default 1 h). Show the token once with a copy button and a ready-to-paste `kms-mcp` config snippet. Never store or display it again.

### 5.8 Console tests
- [ ] Port `web/test/*`.
- [ ] New tests: the BFF rejects methods outside the allowlist, the PAT never appears in any response body, and a non-loopback Host gets a 403.
- [ ] Playwright smoke against the compose stack: edit, validate, simulate, activate, enforced DENY, roll back.

---

## 6. Decisions to record (D-023 onward)

| ID | Decision | Supersedes |
|---|---|---|
| D-023 | Cedar enforcement moves into `plugin-kms` using `cedar-go`. The TS gate is retired. | D-011, D-021 (resolved) |
| D-024 | Agent identity is a signed `agent_id` PAT claim, forwarded by the gateway as `Principal`. | D-014 |
| D-025 | Cedar actions are the RPC method names, grouped under 4Orbit's `use`/`rotate`/`read`/`admin`. | D-013 |
| D-026 | Policies need `@id`. Positional IDs aren't used. | D-016 |
| D-027 | The console is a privileged admin tool. It holds the operator PAT in its BFF, still loopback-only. | D-018, D-020 |
| D-028 | The playground simulates with the enforcement engine through `plugin-policy`, never a second Cedar runtime. | none |
| D-029 | Policy sets are versioned in OpenBao KV v2, and activation requires the test suite to pass. | none |
| D-030 | A PAT without `agent_id` keeps today's owner permissions (`platform.owner`). | none |

---

## 7. Tests and CI

- [ ] `make test` covers the new Go packages (`authz`, `policy`) and the Rust changes.
- [ ] Go: port the permission matrix, add a case that a DENY makes zero provider calls for every RPC, test the platform fence (cross-tenant DENY even with a tenant `permit`), and test that agents can't call `policy.Put`.
- [ ] Gateway e2e: a new profile `gateway/tests/e2e_agents.rs`, run with `make E2E_PROFILE=agents e2e` against the 4Orbit overlay, using real PATs from the seed step.
- [ ] Existing `happy` and `offline` e2e must still pass on the plain dev stack. They use `authnoop` and no `agent_id`, so they hit `platform.owner`.
- [ ] `.github/workflows/console.yml` runs typecheck, tests and build for `console/`.
- [ ] `e2e.yml` adds a job with the 4Orbit overlay and the `agents` profile.

---

## 8. Threat-model updates

- [ ] **Closed:** PAT bypass of Cedar, shared PAT, and self-asserted agent ID (for verified PATs only, not under `authnoop`).
- [ ] **New: the operator PAT in the console BFF.** A leak gives full owner rights. Mitigation: loopback bind, file permission 600, and a short TTL.
- [ ] **New: an Account PAT handed to an agent** skips agent policies by design. Document "never give an agent an Account PAT", and consider a tenant setting that requires `agent_id` for KMS use.
- [ ] **New: policy tampering through `policy.*`.** Covered by the platform forbid and the test gate. Every Activate is audited.
- [ ] **New: availability of the policy plugin.** Fail closed for agents (rule 3).
- [ ] **New: the audit sink is best-effort**, so an event can be dropped under load. Revisit before production.
- [ ] **Unchanged: trusted clock.** It now means the KMS pod's clock.

---

## 9. Open questions (mentors and SpaceComputer)

1. Does SpaceComputer's planned KMS-side Cedar (mentioned in D-021) match §4.1? If an upstream design exists, align with it before writing code.
2. Agent PATs in production: should the dashboard own agent registration and the `jti` rows? `policy.IssueAgentToken` is a dev-only shortcut until then.
3. Credit pricing for `policy.*` and for DENIED KMS calls. Our proposal: free for both.
4. `authnoop` and `agent_id`: should it return an empty value (agents untestable on the plain dev stack), or honor a dev header?
5. A `kms.ListKeys` RPC so the playground can list keys. Today keys can only be looked up by ID.
6. Where audit should live long term: OpenBao audit device, a dashboard DB, or an external log pipeline.
7. Can we get access to the private `openbao-eth-plugin`, `openbao-pqc-plugin` and `openbao-threshold-plugin` repos, so `kms.Sign` (Ethereum) and PQC can be policy-tested?

---

## 10. Suggested order

| Milestone | Contents | Done when |
|---|---|---|
| M1: engine | §4.1 `authz` package, permission-matrix port, platform policy | `go test ./pkg/core/authz/...` is green, with 560 matrix cases passing |
| M2: identity | §4.2 PAT `agent_id` through auth, gateway and kms proto | An e2e test shows the `agent_id` reaching the KMS plugin from a verified PAT |
| M3: enforce | §4.3 every KMS RPC gated, using a file-loaded tenant policy for now | Developer encrypt on `dev-key` is ALLOWED, developer rotate is DENIED, and the provider is never called on a DENY |
| M4: policy plugin | §4.4, §4.5 store, validate, simulate, versions, audit | `curl policy.Simulate` matches the live KMS decision for every matrix cell |
| M5: console | §5.1, §5.6, §5.3 (port GUI v1 onto the RPC data source) | Activity and Access views work against the stack |
| M6: playground | §5.2, §5.4, §5.5, §5.7 | The Playwright smoke test (§5.8) passes |
| M7: docs and CI | §6, §7, §8, DEPLOY.md verified on a clean machine | A teammate follows DEPLOY.md on a fresh clone without help |

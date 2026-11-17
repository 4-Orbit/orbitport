# Plugin: `policy` (4Orbit)

A per-tenant, versioned Cedar policy store for agent authorization. It feeds the KMS plugin the active bundle, records decision audit, and serves the `policy.*` JSON-RPC methods behind the console's policy playground. Every decision uses `pkg/core/authz`, the same engine the KMS plugin enforces with.

Design and threat model: [`docs/4orbit/README.md`](../../../../docs/4orbit/README.md).

## gRPC (`proto/plugins/policy.proto`)

| RPC | Caller | Purpose |
|---|---|---|
| `Call(method, kms_tenant, agent_id, jti_hash, params_json)` | gateway | One allowlisted `policy.*` method. The gateway sets tenancy (from Hold) and the agent id (from the verified PAT). |
| `GetActive(kms_tenant)` | KMS plugin | The active bundle (`exists=false` when there's none). |
| `RecordAudit(events_json[])` | KMS plugin | Decision events, best effort. |

## `policy.*` methods

| Method | Cedar action | Params | Result |
|---|---|---|---|
| `policy.GetSchema` | `policy.Read` | — | schema text, platform policy, actions with their groups |
| `policy.GetActive` | `policy.Read` | — | the active version and activation record |
| `policy.ListVersions` | `policy.Read` | `{cursor?, limit? (≤100)}` | `{versions, nextCursor}`, newest first; pass `nextCursor` back for older ones |
| `policy.GetVersion` | `policy.Read` | `{version}` | one version |
| `policy.GetTemplate` | `policy.Read` | `{template: "4orbit"}` | the template's policies, entities and tests, without saving anything |
| `policy.GetTests` | `policy.Read` | — | the saved test suite |
| `policy.ListAudit` | `policy.Read` | `{cursor?, limit? (≤200), agentId?, decision?, action?, resource?, jtiHash?}` | `{events, nextCursor, summary}`, newest first; filters apply before paging |
| `policy.Validate` | `policy.Simulate` | `{policies, entities}` | `{ok, problems[], summary}` |
| `policy.Simulate` | `policy.Simulate` | `{requests[], source?, at?, explain?}` | decisions; `at` sets a simulated time; with `explain: true`, each DENY (the first 50) carries an `explanation` like `policy.Explain`'s |
| `policy.Explain` | `policy.Simulate` | `{agentId?, action, resource, source?, at?}` | `{source, version, at, simulatedTime, explanation}`: why the request is denied (`kind`: blocked, expired, notYet, conditionFalse, closest, noRule, unknownAgent, noPolicy, errored, invalidRequest), with the matching forbids or the closest permits and what each is missing. Computed by `authz.Explain` with the enforcement engine |
| `policy.Matrix` | `policy.Simulate` | `{source?, keys? (≤5000), actions?, includeAccount?, at?, agents?, onlyAllowed?, keySearch?, keyOffset?, keyLimit? (≤100), agentOffset?, agentLimit? (≤50), summary?}` | one page of agents × keys × actions with `totalKeys`/`totalPrincipals`; with `summary: true`, per-agent counts over every key instead of cells |
| `policy.Diff` | `policy.Simulate` | `{from?, to?, keys?, actions?}` | the cells whose decision changed |
| `policy.RunTests` | `policy.Simulate` | `{source?, tests?}` | pass/fail report |
| `policy.SaveDraft` | `policy.Write` | `{policies, entities, message, allowDuplicate?}` | `{version, duplicate}`; an identical existing version (preferring the active one) is returned instead of a copy unless `allowDuplicate` |
| `policy.PutTests` | `policy.Write` | `{tests[]}` | count |
| `policy.LoadTemplate` | `policy.Write` | `{template: "4orbit"}` | saves the 4Orbit organization as a version and installs its 98-case suite |
| `policy.Activate` | `policy.Activate` | `{version, force?}` | `{activated, tests}`; refused while any test fails unless `force` |
| `policy.IssueAgentToken` | `policy.IssueAgentToken` | `{agentId, ttlSeconds}` | the approval; the gateway then mints the PAT through patissuer |

`source` is `{version: N}`, `{draft: {policies, entities}}`, or omitted (the active version). Unknown params are rejected. These methods are authorized against the **platform policy only**: account principals are allowed and agents never are.

The gateway also serves `policy.ListKeys {cursor?, limit? (≤200)}` → `{keys, nextCursor, truncated}`, which goes to the KMS plugin's internal `ListKeys` RPC rather than to this plugin. Keys are listed in key-id order; the cursor is the last key id of the previous page.

**Paging rules:** every list says whether more exists (`nextCursor` or totals), and nothing is dropped silently. Cursors are opaque strings; a malformed one is rejected with `invalid_argument`.

## Storage

OpenBao KV v2 at `<mount>/data/tenants/<sha256(tenant)[:16]>/`:

| Path | Content |
|---|---|
| `meta` | `{latest}`, updated with check-and-set so concurrent saves get distinct versions |
| `versions/<n>` | an immutable version, written with `cas=0` and stored as one JSON-encoded field |
| `active` | `{version, activatedAt, activatedBy}` |
| `tests` | the test suite, stored as one JSON-encoded field |
| `hashes/<sha256>` | `{version}`: content index for the duplicate check (policy text + entities, order-independent); newest version wins |
| `hashindex` | `{upTo}`: how far the index is complete; versions saved before the index existed are back-filled on first lookup |

Audit cursors are per-tenant sequence numbers, so a cursor stays valid while the in-memory ring drops its oldest events.

Configuration is listed in [`CONTEXT.md`](../../../../CONTEXT.md#plugin-policy).

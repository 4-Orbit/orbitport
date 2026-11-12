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
| `policy.ListVersions` / `policy.GetVersion` | `policy.Read` | `{version}` | version list (newest first) / one version |
| `policy.GetTests` | `policy.Read` | — | the saved test suite |
| `policy.ListAudit` | `policy.Read` | `{limit, agentId, decision, action, resource}` | events (newest first) and a summary |
| `policy.Validate` | `policy.Simulate` | `{policies, entities}` | `{ok, problems[], summary}` |
| `policy.Simulate` | `policy.Simulate` | `{requests[], source?, at?}` | decisions; `at` sets a simulated time |
| `policy.Matrix` | `policy.Simulate` | `{source?, keys?, actions?, includeAccount?, at?}` | agents × keys × actions |
| `policy.Diff` | `policy.Simulate` | `{from?, to?, keys?, actions?}` | the cells whose decision changed |
| `policy.RunTests` | `policy.Simulate` | `{source?, tests?}` | pass/fail report |
| `policy.SaveDraft` | `policy.Write` | `{policies, entities, message}` | the new version number (bundle must validate) |
| `policy.PutTests` | `policy.Write` | `{tests[]}` | count |
| `policy.LoadTemplate` | `policy.Write` | `{template: "4orbit"}` | saves the 4Orbit organization as a version and installs its 98-case suite |
| `policy.Activate` | `policy.Activate` | `{version, force?}` | `{activated, tests}`; refused while any test fails unless `force` |
| `policy.IssueAgentToken` | `policy.IssueAgentToken` | `{agentId, ttlSeconds}` | the approval; the gateway then mints the PAT through patissuer |

`source` is `{version: N}`, `{draft: {policies, entities}}`, or omitted (the active version). Unknown params are rejected. These methods are authorized against the **platform policy only**: account principals are allowed and agents never are.

The gateway also serves `policy.ListKeys`, which goes to the KMS plugin's internal `ListKeys` RPC rather than to this plugin.

## Storage

OpenBao KV v2 at `<mount>/data/tenants/<sha256(tenant)[:16]>/`:

| Path | Content |
|---|---|
| `meta` | `{latest}`, updated with check-and-set so concurrent saves get distinct versions |
| `versions/<n>` | an immutable version, written with `cas=0` and stored as one JSON-encoded field |
| `active` | `{version, activatedAt, activatedBy}` |
| `tests` | the test suite, stored as one JSON-encoded field |

Configuration is listed in [`CONTEXT.md`](../../../../CONTEXT.md#plugin-policy).

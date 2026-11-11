# UCSB capstone: delegated agent credential contract

This is a process-local development implementation. The upstream agent
identity and policy interfaces still need to be connected.

## Grant shape

`gateway::agent_delegation::AgentScope` contains four exact-match fields:

| Field | Source | Example |
| --- | --- | --- |
| `accountId` | Trusted issuer/account context | `test-account` |
| `agentId` | Trusted issuer/agent context | `developer-agent` |
| `action` | One permitted operation | `github:create-issue` |
| `resource` | One logical target | `4-Orbit/test-repo` |

When `ORBITPORT_AGENT_DELEGATION_ENABLED=true`, the gateway mounts
`POST /internal/agent/credentials` on the internal listener. The route requires
an allowlisted Auth0 M2M service token with `agent:delegate` scope through
Orbitport's existing `ValidateServiceToken` path. It accepts:

```json
{
  "accountId": "test-account",
  "agentId": "developer-agent",
  "action": "github:create-issue",
  "resource": "4-Orbit/test-repo",
  "ttlSeconds": 60
}
```

On success it returns `201` with `token` and `expiresAt`, and
`Cache-Control: no-store`. The trusted issuer calls
`AgentCredentialStore::issue(scope, ttl_seconds)` through this route.
The route is disabled by default. In the local dev compose stack, set
`ORBITPORT_AGENT_DELEGATION_ENABLED=true` before starting the gateway; the
internal listener is bound to `127.0.0.1:8090` on the host. That stack uses
`authnoop`, which accepts any service token, so its credentials and outcomes
are development evidence only. Production must use the real auth plugin with
an allowlisted M2M client carrying `agent:delegate`.

To verify the code without Docker, run from the repository root:

```sh
cargo test -p gateway agent_delegation::tests --lib --locked
cargo test -p gateway --test agent_delegation_route --locked
```

With the dev compose stack running and the feature enabled, a local issuance
smoke test is:

```sh
curl -fsS http://127.0.0.1:8090/internal/agent/credentials \
  -H 'Authorization: Bearer dev-only-service-token' \
  -H 'Content-Type: application/json' \
  -d '{"accountId":"test-account","agentId":"developer-agent","action":"github:create-issue","resource":"4-Orbit/test-repo","ttlSeconds":60}' \
  | jq '{tokenLength:(.token|length),expiresAt}'
```

The expected token length is 64. To exercise the issued credential on the
public gateway listener, call the read-only preview endpoint before expiry:

```sh
curl -fsS http://127.0.0.1:8080/api/v1/agent/requests/preview \
  -H "Authorization: Bearer $AGENT_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"action":"github:create-issue","resource":"4-Orbit/test-repo"}'
```

Set `AGENT_TOKEN` to the `token` returned by issuance. The response confirms
the stored account, agent, action, and resource and reports
`policyEvaluated:false` and `operationPerformed:false`. An invalid, expired,
or out-of-scope credential returns `401`. This endpoint does not invoke Cedar,
GitHub, or KMS; the real action route must still enforce policy and audit.
The lifetime must be 1–900 seconds. The returned credential is an opaque,
random bearer token; only its SHA-256 digest and the grant are stored. The raw
token must be returned once over a protected channel and kept out of logs and
browser state. Restart invalidates all outstanding credentials.

An operation handler calls `authenticate(token, action, resource)`. It gets the
stored account and agent identity only if the token is valid, in scope, and
unexpired. The agent request must not supply or override `accountId` or
`agentId`. If an independently verified account and agent identity is
available, use `validate(token, &expected_scope)` as an additional binding.

The operation must still pass SpaceComputer policy enforcement after credential
validation. An issued credential is a scope limit, not a Cedar ALLOW decision.
The handler must record the resulting request and decision through the agreed
audit interface. Credential rejection and policy denial must make no GitHub or
KMS call.

`gateway::agent_request_auth::with_agent_request_auth(store.clone())` is the
gateway filter for the next agent-facing operation route. It accepts a bearer
credential and JSON with `action`, `resource`, and optional operation `input`.
It rejects top-level `accountId` and `agentId` fields and gives the handler an
`AuthenticatedAgentRequest` whose account and agent come from the stored grant.
The read-only preview endpoint mounts this filter on the public listener when
delegation is enabled. The GitHub operation will also attach it to its endpoint,
run Cedar/SpaceComputer policy enforcement, and then call GitHub only on ALLOW.
The filter returns `401` for missing, invalid,
expired, or out-of-scope credentials and `503` if the credential store's
trusted clock or lock is unavailable.

## Integration boundary

The GitHub operation and frontend can use this contract now. The pending
upstream contract must determine who may issue credentials, how verified agent
and account identity reaches the gateway, and which policy/audit APIs the
handler calls. Do not mount `issue()` on a public route or treat the existing
customer PAT as proof of an agent identity. A stolen bearer token can be used
within its scope until expiry or local revocation; the current store has no
distributed state or proof of possession.

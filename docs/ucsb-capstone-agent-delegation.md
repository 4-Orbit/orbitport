# UCSB capstone: delegated agent credential contract

This is the first gateway-side piece of the UCSB capstone branch. It is a
process-local development implementation, not a production issuer or an
Orbitport agent endpoint. The upstream agent identity and policy interfaces
still need to be connected.

## Grant shape

`gateway::agent_delegation::AgentScope` contains four exact-match fields:

| Field | Source | Example |
| --- | --- | --- |
| `accountId` | Trusted issuer/account context | `test-account` |
| `agentId` | Trusted issuer/agent context | `developer-agent` |
| `action` | One permitted operation | `github:create-issue` |
| `resource` | One logical target | `4-Orbit/test-repo` |

The trusted issuer calls `AgentCredentialStore::issue(scope, ttl_seconds)`.
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

## Integration boundary

The GitHub operation and frontend can use this contract now. The pending
upstream contract must determine who may issue credentials, how verified agent
and account identity reaches the gateway, and which policy/audit APIs the
handler calls. Do not mount `issue()` on a public route or treat the existing
customer PAT as proof of an agent identity. A stolen bearer token can be used
within its scope until expiry or local revocation; the current store has no
distributed state or proof of possession.

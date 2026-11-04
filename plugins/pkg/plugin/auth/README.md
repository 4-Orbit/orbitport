# Orbitport Plugin / Auth

Fail-closed JWT validation plugin used by the gateway to authenticate incoming
requests.

## Overview

Implements the `AuthPlugin` gRPC service (`proto/plugins/auth.proto`). Public
requests use `ValidateToken(token)`, which accepts only personal access tokens
(PATs) from the configured PAT issuer and answers `Unauthenticated` for
anything else, Auth0 tokens included. Without PAT config it refuses every token. Gateway-internal capability routes use
`ValidateServiceToken(token, required_scopes)`, which accepts only allowlisted
Auth0 M2M clients (`<client_id>@clients`) carrying `gty=client-credentials`,
an expiry, and every required scope.

Service tokens are validated against an Auth0 tenant using the
`auth0/go-jwt-middleware` validator with RS256 and a JWKS caching provider
(5 min cache, 1 min allowed clock skew).

The plugin refuses to start if `ORBITPORT_AUTH0_DOMAIN` or
`ORBITPORT_AUTH0_AUDIENCE` is missing — this is deliberate so a misconfigured
deployment cannot silently run without authentication. For local development,
use the `authnoop` plugin instead.

Set `ORBITPORT_AUTH_SERVICE_CLIENT_IDS` to the comma-separated M2M client IDs
allowed to use internal capabilities. An empty value authorizes no clients.

Configuration: see [CONTEXT.md → Plugin: `auth`](../../../../CONTEXT.md#plugin-auth).

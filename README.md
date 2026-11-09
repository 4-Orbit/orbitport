# SpaceComputer | Orbitport

![spacecomputer logo](https://raw.githubusercontent.com/spacecomputer-io/media-kit/refs/heads/main/SpaceComputer/logo/SpaceComputer_banner.png)

![Plugins](https://github.com/spacecomputer-io/orbitport/actions/workflows/plugins.yml/badge.svg?branch=main)
![Gateway](https://github.com/spacecomputer-io/orbitport/actions/workflows/gateway.yml/badge.svg?branch=main)
![E2E](https://github.com/spacecomputer-io/orbitport/actions/workflows/e2e.yml/badge.svg?branch=main)
![Build & Push Image](https://github.com/spacecomputer-io/orbitport/actions/workflows/build_push.yml/badge.svg)

## What is Orbitport?

Orbitport is a unified gateway to space-based orbital services operated by SpaceComputer. It gives web2 and web3 applications a single, secure entry point to services served from multiple providers and satellites — today that means `cTRNG` (cosmic True Random Number Generation) backed by the Aptos Orbital satellites, with more services on the roadmap. This repository ships a local Docker setup (see [Running locally](#running-locally)).

## Services

- **cTRNG** — cosmic true random numbers, served by the `masterseed` plugin from a rolling pool of satellite-harvested entropy.
- **Randomness Beacon** — a background service that pins a continuously updated beacon record to IPFS and republishes it under a stable IPNS name. Public registry: [`beacons.yaml`](beacons.yaml).
- **KMS** — multi-tenant Key Management Service backed by OpenBao. Encrypt/decrypt with Transit (`AES_256_GCM96`), sign with Transit (ECDSA, Ed25519, RSA), Ethereum (secp256k1, including EIP-191), use PQC ML-DSA / ML-KEM, and store/retrieve arbitrary JSON secrets through the KMS key-store. See the [`kms`](plugins/pkg/plugin/kms/README.md) plugin. Try it with the runnable use cases in [`examples/kms`](examples/kms/).
- **spaceTEE** — Space Trusted Execution Environment. Planned.

## Architecture

```
                  ┌──────────┐
    HTTP/JSON ──▶ │ gateway  │ ──▶ plugin-auth        (AuthPlugin)
    JSON-RPC      │  (Rust)  │ ──▶ plugin-masterseed  (MasterSeedPlugin)
                  └──────────┘          │
                                        ▼
                                   plugin-aptos-orbital (RandomnessPlugin)
                                        │
                                        ▼
                                   api.aptosorbital.com (satellites)

                  ┌──────────────┐
                  │ plugin-beacon│ ──▶ plugin-ipfs ──▶ IPFS / IPNS
                  │ (background) │ ──▶ plugin-aptos-orbital
                  └──────────────┘ ──▶ plugin-masterseed
```

For a deeper walk-through (gRPC wiring, plugin internals, env-var reference, protobuf workflow, test profiles), see [`CONTEXT.md`](CONTEXT.md). A flat repo map is in [`llms.txt`](llms.txt).

## Running locally

The fast path uses the dev compose stack, which swaps in the `authnoop` plugin and the Aptos Orbital mocker so no external credentials are required.

```bash
git clone https://github.com/spacecomputer-io/orbitport.git
cd orbitport
cp .example.env .env    # defaults are fine for dev
make devenv-up          # builds images, starts dev compose stack
curl http://localhost:8080/healthz
```

Smoke-test a cTRNG request once the stack is up:

```bash
curl -X POST http://localhost:8080/api/v1/rpc \
  -H "Authorization: Bearer dev" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"ctrng.Get","params":{"chunks":3}}'
```

Teardown:

```bash
make devenv-down
```

## API

The full HTTP and JSON-RPC reference lives in [`swagger.yaml`](swagger.yaml).

Customer requests require a PAT. Auth0 service tokens are accepted only on
internal service routes such as PAT issuance, not the customer API.

Example request:

```bash
curl -X POST http://localhost:8080/api/v1/rpc \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"ctrng.Get","params":{"chunks":2}}'
```

## Local MCP Server

Agents can use KMS through the local `kms-mcp` stdio executable, which calls the existing
gateway JSON-RPC API with your PAT. It adds no public MCP endpoint; manual API
calls remain available with the same PAT authentication. Build with `make mcp-build`, installation,
harness configuration, opt-in tools and release verification are documented in
[`mcp/README.md`](mcp/README.md). See [client setup](mcp/CLIENT_SETUP.md) for
file-based PAT configuration for Claude Desktop, Codex desktop, Claude Code
and Codex CLI, plus manual terminal testing.

## Configuration

All env vars are prefixed `ORBITPORT_`. The full list, including defaults, is the source-controlled [`.example.env`](.example.env); per-knob descriptions live in [`CONTEXT.md`](CONTEXT.md#configuration). For local dev, the defaults in `.example.env` are sufficient.

## Testing

```bash
make test                       # unit tests (Rust + Go)
make lint                       # clippy + golangci-lint
make e2e                        # happy-path e2e against dev compose
make E2E_PROFILE=offline e2e    # fallback path (Aptos unreachable)
```

See [`CONTEXT.md`](CONTEXT.md#testing) for the full e2e matrix.

## Links

* [SpaceComputer docs](https://docs.spacecomputer.io)
* [Orbitport user guide](https://docs.spacecomputer.io/using-orbitport/user-guide)
* [Orbitport dev/internal docs](docs/README.md)
* [Public beacons list](beacons.yaml)

## Contributing

We welcome contributions to Orbitport! Please see our [contributing guidelines](CONTRIBUTING.md) for more information on how to get involved.

## License

Orbitport is licensed under the Apache License 2.0. See the [LICENSE](LICENSE) file for more information.

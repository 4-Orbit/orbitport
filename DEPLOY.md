# DEPLOY: Orbitport + 4Orbit on your own machine

This runs the merged stack locally: the Orbitport gateway and plugins, local OpenBao, per-agent Cedar enforcement in the KMS plugin, the policy plugin, and the operator console with the policy playground. Every command below was run on an Apple Silicon Mac (macOS, Docker Desktop, Compose v2) on 2026-11-10.

Everything here is **development only**: OpenBao runs in dev mode with the public root token `root`, the account plugin is a noop that maps every token to one tenant (`noop-tenant`), and OpenBao keeps its data in memory. Don't expose these ports to an untrusted network.

What changed and why is in [`TODO.md`](TODO.md) and [`docs/4orbit/`](docs/4orbit/README.md).

---

## 0. What you get

| Service | Host address | Purpose |
|---|---|---|
| `gateway` | `http://127.0.0.1:8080` | Public JSON-RPC API (`/api/v1/rpc`, including the new `policy.*` methods) and `/healthz` |
| `gateway` internal | `http://127.0.0.1:8090` | PAT and agent-credential issuance, loopback only |
| `plugin-jwks` | `http://127.0.0.1:8091/.well-known/jwks.json` | PAT public keys |
| `openbao-proxy` | `http://127.0.0.1:8200` | OpenBao: Transit, KV v2, and the new `orbitport-policy` mount |
| `plugin-policy` | gRPC `plugin-policy:50009` (internal); metrics on `:9009` | Versioned policy store, validation, simulation, test suites, decision audit |
| `console` | `http://127.0.0.1:4317` | Operator console and policy playground |

The seed step loads the 4Orbit demo organization:

| Agent | Role | Allowed (everything else is denied) |
|---|---|---|
| `developer-agent` | `developer` | `kms.Encrypt` on `demo-key` until 2027-01-15T08:00:00Z, and `kms.Encrypt` on `dev-key` |
| `security-agent` | `security` | `kms.RotateKey` on `demo-key`, `dev-key` and `prod-key` |
| `deployment-agent` | `deployment` | `kms.Encrypt` on `prod-key` |

A token without an `agent_id` (an account-level PAT, such as the operator's) keeps today's Orbitport behavior: full control of its own tenant (`platform.owner`).

---

## 1. Prerequisites

| Tool | Version | Needed for | Check |
|---|---|---|---|
| Docker Desktop (or Engine) with Compose v2 | recent | everything | `docker info && docker compose version` |
| GNU Make | any | everything | `make --version` |
| Git, `curl`, `jq` | any | everything | `jq --version` |
| Node.js | 22.12 or newer | console development and tests only (the console also runs in Docker) | `node -v` |
| Go | 1.26 or newer | native Go tests (`make test`, `make 4orbit-test`) | `go version` |
| Rust (stable) with `rustfmt` and `clippy` | 1.85 or newer | native Rust tests and lint | `cargo --version` |
| `protoc` + `protoc-gen-go` v1.36.12 + `protoc-gen-go-grpc` v1.6.2 | | only if you edit `proto/` | `protoc --version` |
| `golangci-lint` | v2 | only for `make lint` | `golangci-lint version` |

On macOS with Homebrew:

```sh
brew install go protobuf jq golangci-lint
rustup component add rustfmt clippy
go install google.golang.org/protobuf/cmd/protoc-gen-go@v1.36.12
go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@v1.6.2
```

Give Docker Desktop at least **6 GB of memory**. The first build takes 10–20 minutes; later builds use the cache.

> **Hardened base images.** Upstream Dockerfiles use `dhi.io/static` runtime images, which need a Docker Hardened Images login (`docker login dhi.io`). Without one, `make devenv-up` fails with `401 Unauthorized`. The `4orbit-*` targets build with the public `gcr.io/distroless/*-debian13:nonroot` images instead. To use the hardened images, pass `FOURORBIT_PLUGIN_RUNTIME=dhi.io/static:20250419-debian13 FOURORBIT_GATEWAY_RUNTIME=dhi.io/static:20250419-glibc`.

---

## 2. Clone

```sh
mkdir -p ~/cs189 && cd ~/cs189
git clone https://github.com/4-Orbit/orbitport.git
cd orbitport
git checkout 4orbit-migration      # or the branch this work was merged into
```

Optional: the private OpenBao plugin repos enable Ethereum, PQC and threshold signing. They must be siblings of `orbitport/`:

```sh
cd ~/cs189
git clone https://github.com/spacecomputer-io/openbao-eth-plugin.git
git clone https://github.com/spacecomputer-io/openbao-pqc-plugin.git
git clone https://github.com/spacecomputer-io/openbao-threshold-plugin.git
```

Without them, the plugin builders exit cleanly, OpenBao skips those mounts, and Docker creates empty `../openbao-*-plugin` folders as mount points. Transit (AES, ECDSA, Ed25519, RSA) and every 4Orbit flow still work. Two upstream e2e tests need the missing plugins and fail without them (see §9).

---

## 3. Configure

```sh
cd ~/cs189/orbitport
cp .4orbit.env.example .4orbit.env      # optional; defaults match this file
```

| Variable | Default | Meaning |
|---|---|---|
| `ORBITPORT_KMS_AUTHZ_MODE` | `enforce` | `shadow` evaluates and audits every decision but never blocks |
| `ORBITPORT_KMS_POLICY_CACHE_TTL_SECS` | `5` | How long until an activated version is enforced |
| `ORBITPORT_PATISSUER_MIN_TTL_SECS` | `60` | Shortest agent-token lifetime |
| `ORBITPORT_PATISSUER_AGENT_MAX_TTL_SECS` | `86400` | Longest agent-token lifetime |
| `FOURORBIT_AGENT_TOKEN_TTL` | `3600` | Agent-token lifetime used by the seed step |
| `FOURORBIT_OPERATOR_TOKEN_TTL` | `43200` | Operator-token lifetime used by the seed step |
| `ORBITPORT_POLICY_AUDIT_RING` | `2000` | Decisions kept in memory per tenant |
| `ORBITPORT_CONSOLE_PORT` | `4317` | Console port (bound to `127.0.0.1` only) |
| `FOURORBIT_RESEED` | `false` | When `true`, the next `make 4orbit-seed` reloads the template as a new version |

---

## 4. Build and start

```sh
make 4orbit-up
```

This builds `op-plugin`, `op-mocker`, `op-fourorbit-seed`, `op-gateway` and `op-console` with the public runtime images. It then starts:

```sh
docker compose --env-file .dev.env --env-file .4orbit.env \
  -f dev.docker-compose.yaml -f local-pat.compose.yaml -f 4orbit.compose.yaml up -d --no-build
```

`local-pat.compose.yaml` replaces `authnoop` with the real auth plugin, so every token is a verified PAT and agent identity comes only from its signed `agent_id` claim. Once the gateway is healthy, `fourorbit-seed` runs automatically.

Check:

```sh
make 4orbit-ps                                   # everything Up (healthy) or Exited (0)
docker logs fourorbit-seed                       # ends with "seed complete"
curl -fsS http://127.0.0.1:8080/healthz          # {"status":"ok"}
curl -fsS http://127.0.0.1:4317/api/health       # {"gateway":"ok",...,"tokenPresent":true}
ls .4orbit/tokens                                # operator.pat + one .pat per agent
```

`plugin-beacon` can show `unhealthy` for a minute while IPFS starts. This is normal and unrelated to 4Orbit.

---

## 5. What the seed did

`make 4orbit-seed` re-runs it. It's idempotent: on a stack that's already seeded, it only refreshes tokens. In order, it:

1. mints an **operator PAT** (account-level, 12 h) directly from `plugin-patissuer` over the compose network, writing `.4orbit/tokens/operator.pat`;
2. creates Transit AES keys `demo-key`, `dev-key` and `prod-key`, tagged `env=demo|dev|prod`;
3. if the tenant has no active policy, saves the 4Orbit template as **version 1** together with its **98-case test suite** (the 4Orbit permission matrix plus the US5 expiry boundary), then activates it, which only succeeds if every case passes;
4. mints a 1-hour **agent PAT** for every registered agent, writing `.4orbit/tokens/<agent>.pat`.

The token folder is mode 700 and the files are mode 600. Don't print them during a screen share.

---

## 6. Try it from the command line

`scripts/4orbit/rpc.sh <token-name> <method> '<params>'` calls the gateway with a seeded token:

```sh
R=scripts/4orbit/rpc.sh

# ALLOW: the developer may encrypt with dev-key
$R developer-agent kms.Encrypt '{"KeyId":"kms:dev-key","Plaintext":"aGVsbG8="}' | jq .result.KeyId

# DENY: the developer may not rotate. The KMS backend is never called.
$R developer-agent kms.RotateKey '{"KeyId":"kms:dev-key"}' | jq .error.message
# "... request denied by policy"

# ALLOW: security may rotate prod
$R security-agent kms.RotateKey '{"KeyId":"kms:prod-key"}' | jq .result.KeyMetadata.PrimaryVersion

# DENY: agents can never administer policy (platform.agents-never-administer-policy)
$R security-agent policy.Activate '{"version":1}' | jq .error.message

# The operator's account PAT keeps full owner rights
$R operator kms.RotateKey '{"KeyId":"kms:dev-key"}' | jq .result.KeyMetadata.KeyId

# The audit trail
$R operator policy.ListAudit '{"limit":5}' | jq '.result.events[] | {principal,action,resource,decision,determiningPolicies,kmsCalled}'

# The playground API: time travel past the US5 expiry
$R operator policy.Simulate '{"at":1800000000,"requests":[{"agentId":"developer-agent","action":"kms.Encrypt","resource":{"type":"Key","id":"demo-key"}}]}' | jq '.result.results[0].decision'
# "DENY"
```

To run all 47 end-to-end checks (enforcement, forged and tampered tokens, audit, playground API, the test gate, live activation and rollback, and agent tokens):

```sh
make 4orbit-e2e          # ends with "passed: 47  failed: 0"
```

---

## 7. The console and policy playground

Open **http://127.0.0.1:4317**. Use `127.0.0.1` or `localhost`; any other Host header gets a 403. The console's server reads `.4orbit/tokens/operator.pat` on every call and never sends it to the browser.

| Tab | What it does |
|---|---|
| **Activity** | Every KMS decision and policy-admin attempt (polls every 3 s), with filters by agent, decision, action and key. Click a row for the determining policies, whether the KMS was called, enforce or shadow mode, and the policy version. **Replay in simulator** sends that request to the Simulate tab. |
| **Access** | Agents × keys × KMS actions for the active version, the editor draft or any saved version, at the current time or a simulated one. Click a cell to see why. |
| **Policies** | A Cedar editor with highlighting and server-side validation as you type (the same engine as enforcement, with errors placed at their line). Also: an agents-and-roles editor, snippets, **What changes vs active?** (the decision diff), **Save as new version**, and the read-only platform policy. |
| **Simulate** | Ask Cedar about any principal, action, resource, key tags, source and time. Results show a SIMULATED TIME badge when you time-travel. **Save as test case** adds the result to the test suite. |
| **Tests** | The tenant's saved expectations. Run them against the draft, the active version or any saved version; add or remove cases and save the suite. |
| **Versions** | The version list, a decision diff and text diff against the active version, **Activate** (refused while any test fails, showing which cases fail, with an explicit *Activate anyway* step), **Roll back**, and **Open in editor**. |
| **Agents** | Registered agents and their roles. **Mint token** issues a short-lived agent PAT, shown once, with a ready-to-paste `kms-mcp` config. |

A five-minute walkthrough:

1. **Access**: the matrix matches the table in §0.
2. **Policies → Insert snippet → Single agent may rotate a key**, then change it to `Agent::"developer-agent"` and `Key::"dev-key"`. The badge turns VALID. Click **What changes vs active?** and exactly one cell flips to ALLOW.
3. **Save as new version** with a message.
4. **Versions → Activate**: refused, because the 4Orbit suite expects the developer's rotate on `dev-key` to be DENY. Read the failing case, then either use **Activate anyway…** or update the case on **Tests** and activate.
5. Within about 5 s, `scripts/4orbit/rpc.sh developer-agent kms.RotateKey '{"KeyId":"kms:dev-key"}'` succeeds. **Activity** names your new policy and version.
6. **Versions → Roll back to this** on v1. The same call is denied again.
7. **Simulate**: `developer-agent`, `kms.Encrypt`, `demo-key`, time `2027-01-16 00:00:00` gives DENY with a SIMULATED TIME badge.

For console development with hot reload against the running stack:

```sh
cd console
npm ci
npm run dev        # http://127.0.0.1:5173, proxying /api to the console server on :4317
```

Stop the `console` container first (`docker stop console`) so port 4317 is free. The dev server reads `../.4orbit/tokens/operator.pat` and talks to `http://127.0.0.1:8080` by default (`ORBITPORT_URL` and `ORBITPORT_CONSOLE_PAT_FILE` override these).

---

## 8. A real agent through MCP

```sh
make mcp-build
install -m 755 target/release/kms-mcp ~/.local/bin/kms-mcp
```

Point your MCP client (Claude Code, Claude Desktop, Codex) at the launcher with an **agent** token, never the operator's:

```json
{
  "mcpServers": {
    "kms-developer-agent": {
      "command": "/ABSOLUTE/PATH/orbitport/mcp/scripts/kms-mcp-from-file.sh",
      "env": {
        "ORBITPORT_URL": "http://127.0.0.1:8080",
        "ORBITPORT_PAT_FILE": "/ABSOLUTE/PATH/orbitport/.4orbit/tokens/developer-agent.pat"
      }
    }
  }
}
```

Ask the agent to encrypt with `kms:dev-key` (allowed) and then to rotate it (denied). Both show up on **Activity**. Seeded agent tokens last 1 hour; refresh them with `make 4orbit-seed` or mint one on **Agents**.

---

## 9. Tests

| What | Command | Needs the stack? | Result on 2026-11-10 |
|---|---|---|---|
| All Go and Rust unit tests | `make test` | no | pass |
| 4Orbit unit tests (Go engine, KMS, policy, auth, patissuer; Rust gateway; console) | `make 4orbit-test` | no | pass |
| Lint | `make lint` (`golangci-lint` + `clippy -D warnings`) | no | 0 issues |
| Console typecheck and build | `cd console && npm run typecheck && npm run build` | no | pass |
| 4Orbit end-to-end | `make 4orbit-e2e` | 4Orbit stack | 47/47 |
| Original gateway e2e | `make devenv && make e2e-all` | plain dev stack (`authnoop`) | all pass except `kms_ethereum_create_key_and_sign` and `threshold_coordinate_dkg`, which need the private OpenBao plugins (§2) |
| Original beacon e2e | `make go-e2e` | plain dev stack | pass |

The original e2e suites authenticate with the literal `test_access_token`, which only `authnoop` accepts. Run them on the plain dev stack, not the 4Orbit overlay:

```sh
make 4orbit-down
make devenv           # starts the plain dev stack from the images make 4orbit-up built
make e2e-all
make go-e2e
make devenv-down
make 4orbit           # back to the 4Orbit stack (then make 4orbit-seed)
```

`make devenv-up` rebuilds with the hardened `dhi.io` base images. Use `make devenv` (no rebuild) unless you have a `dhi.io` login.

On the plain dev stack, `authnoop` treats the bearer `agent:<id>` as that agent. With no policy plugin there, every agent is denied and account tokens behave as before:

```sh
scripts/4orbit/rpc.sh dev:agent:developer-agent kms.GetKeyMetadata '{"KeyId":"kms:x"}'   # denied by policy
scripts/4orbit/rpc.sh dev:test_access_token     kms.GetCapabilities                      # works
```

---

## 10. Day-to-day

| Task | Command |
|---|---|
| Start from existing images | `make 4orbit` |
| Rebuild everything and start | `make 4orbit-up` |
| Refresh tokens (or seed a fresh stack) | `make 4orbit-seed` |
| Follow logs | `make 4orbit-logs` |
| Status | `make 4orbit-ps` |
| Stop, keeping containers | `make 4orbit-stop` |
| Remove containers | `make 4orbit-down` |

**Persistence:** dev OpenBao keeps everything in memory. `make 4orbit-down`, and often a Docker Desktop restart, wipes keys, key metadata and **every policy version and test suite**. Afterwards, `make 4orbit` brings the stack back and the seed runs again automatically. To keep your own policies, copy them out of the Policies tab or fetch them with `scripts/4orbit/rpc.sh operator policy.GetVersion '{"version":N}'` before you tear down. The decision audit lives in `plugin-policy`'s memory (the newest 2000 events per tenant) and resets when that container restarts.

---

## 11. Troubleshooting

| Symptom | Cause and fix |
|---|---|
| `failed to fetch anonymous token ... dhi.io ... 401 Unauthorized` | You ran `make devenv-up` or `make docker-build` without a DHI login. Use `make 4orbit-up`, or `make docker-build PLUGIN_RUNTIME_IMAGE=gcr.io/distroless/static-debian13:nonroot GATEWAY_RUNTIME_IMAGE=gcr.io/distroless/cc-debian13:nonroot`. |
| Every call returns HTTP 401 | Your token expired (agent tokens last 1 h, the operator token 12 h), or OpenBao was reset and its signing key changed. Run `make 4orbit-seed`. The old dev bearer `test_access_token` never works on this stack. |
| The console shows "Operator token missing" or "operator token rejected" | Run `make 4orbit-seed`. The console re-reads the file, so there's no need to restart it. |
| Every agent call is denied, even allowed ones | No active policy (OpenBao was reset), so run `make 4orbit-seed`. Or `plugin-policy` is down and agents fail closed: check `docker logs plugin-policy`. |
| A newly activated policy isn't enforced yet | Wait `ORBITPORT_KMS_POLICY_CACHE_TTL_SECS` (5 s). The console header shows the active version. |
| Activate is refused | A test case fails. The Versions tab lists which; fix the policy or the case, or force it deliberately. |
| `policy.* ... policy plugin not configured` | The gateway was started without the overlay. Use `make 4orbit`, not `make devenv`. |
| `kms.Sign` with an Ethereum key, or PQC or threshold calls, fail with "no handler for route" | The private OpenBao plugins aren't checked out (§2). |
| The console returns 403 | Wrong Host. Browse to `http://127.0.0.1:4317`; over SSH, use `ssh -L 4317:127.0.0.1:4317 host`. |
| A port is in use (8080, 8200, 4317, 9009…) | Stop the other process, or change the host port in `4orbit.compose.yaml`. |
| Linux: the seed or console can't write or read `.4orbit/tokens` | Both run as your host UID and GID (the Makefile passes `id -u` and `id -g`). Don't run `make` with `sudo`, and remove a `.4orbit/` owned by root. |
| Builds are very slow or run out of memory on a Mac | Raise Docker Desktop memory to 6 GB or more. |

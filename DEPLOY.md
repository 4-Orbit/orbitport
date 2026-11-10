# DEPLOY: Orbitport + 4Orbit on your own machine

This guide runs the merged stack on one machine: the Orbitport gateway and plugins, local OpenBao, per-agent Cedar enforcement in the KMS plugin, the new `plugin-policy`, and the operator console with the policy playground.

> **Status.** This describes the **target** setup defined in [`TODO.md`](TODO.md). Steps 1–3 work on this branch today. Steps marked **(M*n*)** need the TODO milestone with that number. Until those land, see [Before the merge lands](#before-the-merge-lands) at the end.

Everything here is **development only**: OpenBao runs in dev mode with root token `root`, the account plugin is a noop, and data lives in memory. Don't expose any of these ports to an untrusted network.

---

## 0. What you'll end up with

| Service | Host address | Purpose |
|---|---|---|
| `gateway` | `http://127.0.0.1:8080` | Public JSON-RPC API (`/api/v1/rpc`), `/healthz` |
| `gateway` internal | `http://127.0.0.1:8090` | PAT issuance (loopback only) |
| `plugin-jwks` | `http://127.0.0.1:8091/.well-known/jwks.json` | PAT public keys |
| `openbao-proxy` | `http://127.0.0.1:8200` | OpenBao (Transit, KV v2, `orbitport-policy`) |
| `plugin-policy` | gRPC `plugin-policy:50009` (internal), metrics `:9009` | Policy store, validation, simulation, audit **(M4)** |
| `console` | `http://127.0.0.1:4317` | Operator console and policy playground **(M5/M6)** |

The default 4Orbit demo organization, which the seed step loads:

| Agent | Role | Allowed |
|---|---|---|
| `developer-agent` | `developer` | `use` on `demo-key` (until 2027-01-15T08:00:00Z), `use` on `dev-key` |
| `security-agent` | `security` | `rotate` on `demo-key`, `dev-key`, `prod-key` |
| `deployment-agent` | `deployment` | `use` on `prod-key` |

Anything else is denied by default.

---

## 1. Prerequisites

| Tool | Version | Check |
|---|---|---|
| Docker Desktop (or Engine) + Compose v2 | recent | `docker info && docker compose version` |
| Make | any | `make --version` |
| Git | any | `git --version` |
| Node.js | **22.12+** (console dev and tests only; the console also runs in Docker) | `node -v` |
| `curl`, `jq` | any | `jq --version` |
| Go 1.26+ and Rust 1.85+ | **only** for native `make test` / `make e2e` | `go version`, `cargo --version` |

Docker builds supply Go and Rust inside containers, so you can run the stack without either installed on the host.

**Apple Silicon:** the stack builds natively for linux/arm64, which was verified on an M-series Mac (see 4orbit `docs/local-stack-setup.md`). Give Docker Desktop at least **6 GB RAM** and **20 GB disk**. The first build takes 10–20 minutes.

---

## 2. Clone

Use one parent folder. The compose file looks for the optional OpenBao plugin repos as siblings of `orbitport/`.

```sh
mkdir -p ~/cs189 && cd ~/cs189
git clone -b ucsb-capstone https://github.com/4-Orbit/orbitport.git

# Optional (private, need SpaceComputer access). Enable Ethereum, PQC and threshold signing.
# If they are missing the builders exit cleanly and bootstrap skips those mounts;
# Transit (AES, ECDSA, Ed25519, RSA) still works, and so does every 4Orbit demo.
git clone https://github.com/spacecomputer-io/openbao-eth-plugin.git
git clone https://github.com/spacecomputer-io/openbao-pqc-plugin.git
git clone https://github.com/spacecomputer-io/openbao-threshold-plugin.git
```

Use your normal GitHub authentication. Never put a token in a clone URL.

---

## 3. Start the base Orbitport dev stack (works today)

Do this once first, so you know the base stack is healthy before you add the overlays.

```sh
cd ~/cs189/orbitport
make devenv-up            # docker-build + dev.docker-compose.yaml up -d
docker compose -f dev.docker-compose.yaml ps
curl -fsS http://127.0.0.1:8080/healthz          # {"status":"ok"}
curl -fsS http://127.0.0.1:8200/v1/sys/health | jq .sealed   # false
```

`make devenv-up` calls `docker-compose`. If you only have the v2 plugin (`docker compose`), either `brew install docker-compose` or run the equivalent command yourself:

```sh
make docker-build
OPMOCK_PROFILE=happy docker compose --env-file .dev.env -f dev.docker-compose.yaml up -d
```

The beacon can report `unhealthy` for a minute while IPFS starts. That's normal.

Smoke-test the KMS. `authnoop` accepts any bearer token on this base stack:

```sh
curl -fsS http://127.0.0.1:8080/api/v1/rpc -H 'Content-Type: application/json' \
  -H 'Authorization: Bearer test_access_token' \
  -d '{"jsonrpc":"2.0","id":1,"method":"kms.GetCapabilities","params":{}}' | jq '.result | keys'
```

Stop it before you continue: `make devenv-down`.

---

## 4. Configure the 4Orbit overlay

```sh
cp .4orbit.env.example .4orbit.env     # (M3) template ships with the overlay
chmod 600 .4orbit.env
```

The defaults work locally. The settings that matter:

| Variable | Default | Meaning |
|---|---|---|
| `ORBITPORT_KMS_AUTHZ_MODE` | `enforce` | `shadow` audits decisions but doesn't block |
| `ORBITPORT_KMS_POLICY_CACHE_TTL_SECS` | `5` | How fast an activated policy takes effect |
| `ORBITPORT_PATISSUER_MIN_TTL_SECS` | `60` | Shortest agent-token lifetime |
| `FOURORBIT_AGENT_TOKEN_TTL` | `3600` | TTL the seed script uses for agent PATs |
| `ORBITPORT_CONSOLE_PORT` | `4317` | Console port (always bound to `127.0.0.1`) |

The overlay `4orbit.compose.yaml` **(M3–M6)** stacks on top of `dev.docker-compose.yaml` and `local-pat.compose.yaml`. It:

- switches `plugin-auth` to the real PAT verifier (from `local-pat.compose.yaml`);
- adds `ORBITPORT_KMS_POLICY_PLUGIN=http://plugin-policy:50009` to `plugin-kms` and the gateway;
- adds the `plugin-policy`, `fourorbit-seed` (one-shot) and `console` services;
- adds the `orbitport-policy` KV v2 mount to OpenBao bootstrap and a volume for audit JSONL.

---

## 5. Build and start the merged stack **(M3–M6)**

```sh
make 4orbit-up
```

which runs:

```sh
make docker-build
OPMOCK_PROFILE=happy docker compose --env-file .dev.env --env-file .4orbit.env \
  -f dev.docker-compose.yaml -f local-pat.compose.yaml -f 4orbit.compose.yaml up -d --build
```

Check health:

```sh
make 4orbit-ps                                     # every service healthy or exited(0)
curl -fsS http://127.0.0.1:8080/healthz
curl -fsS http://127.0.0.1:8091/.well-known/jwks.json | jq '.keys | length'   # >= 1
docker exec plugin-policy /app healthcheck && echo policy ok
docker exec plugin-kms    /app healthcheck && echo kms ok
curl -fsS http://127.0.0.1:4317/ -o /dev/null && echo console ok
```

---

## 6. Seed the demo organization **(M4)**

`fourorbit-seed` runs automatically on `make 4orbit-up`. To re-run it, for example after an OpenBao reset:

```sh
make 4orbit-seed
```

It is idempotent. Running inside the compose network, it:

1. mints an **operator (Account) PAT** through `plugin-patissuer`. There's no `agent_id` and the TTL is 12 h. It's written to `.4orbit/tokens/operator.pat`;
2. creates the Transit AES keys `demo-key`, `dev-key` and `prod-key` (tagged `env=demo|dev|prod`) and skips any that already exist;
3. registers the three agents and roles, and loads `policies/4orbit/policy.cedar` and `entities.json` as **version 1**, together with the default test suite (the 4Orbit permission matrix);
4. activates version 1, which only works if the suite passes;
5. mints one **agent PAT** per agent (`agent_id` claim, `FOURORBIT_AGENT_TOKEN_TTL`) into `.4orbit/tokens/<agent>.pat`.

`.4orbit/` is git-ignored and the token files are `chmod 600`. Don't `cat` them while screen-sharing.

---

## 7. Verify enforcement from the command line **(M3)**

Use the small wrapper (it reads a token file and calls `/api/v1/rpc`):

```sh
alias rpc='scripts/4orbit/rpc.sh'      # usage: rpc <agent|operator> <method> '<params-json>'

# ALLOW: developer may use dev-key
rpc developer-agent kms.Encrypt '{"KeyId":"kms:dev-key","Plaintext":"aGVsbG8="}' | jq '.result.KeyId'
# "kms:dev-key"

# DENY: developer may not rotate. The KMS provider is never called.
rpc developer-agent kms.RotateKey '{"KeyId":"kms:dev-key"}' | jq '.error.message'
# "request denied by policy"

# DENY: developer may not touch prod
rpc developer-agent kms.Encrypt '{"KeyId":"kms:prod-key","Plaintext":"aGVsbG8="}' | jq '.error.message'

# ALLOW: security may rotate prod
rpc security-agent kms.RotateKey '{"KeyId":"kms:prod-key"}' | jq '.result.KeyMetadata.PrimaryVersion'

# DENY: an agent can never change policy (platform.agents-never-edit-policy)
rpc security-agent policy.Activate '{"Version":1}' | jq '.error.message'

# Audit: the last five decisions
rpc operator policy.ListAudit '{"Limit":5}' | jq '.result.Events[] | {principal, action, resource, decision, determiningPolicies, kmsCalled}'
```

What to expect: every DENY has `kmsCalled: false`, and every ALLOW names its `@id` policy, such as `developer-use-dev-key`. A token that's tampered with or expired gets an HTTP 401 from the gateway before Cedar runs.

---

## 8. Use the console and policy playground **(M5/M6)**

Open **http://127.0.0.1:4317**. Use `127.0.0.1` or `localhost`, because other hostnames get a 403. The BFF reads `.4orbit/tokens/operator.pat` and the browser never sees it.

A five-minute walkthrough:

1. **Activity.** The requests from step 7 are listed with ALLOW and DENY badges. Click a row for its determining policy and whether the KMS was called.
2. **Access.** The matrix of agents × actions × keys for the active version. It should match the table in §0.
3. **Policies → New draft.** Add:
   ```cedar
   @id("deployment-sign-prod")
   permit (principal in Role::"deployment", action == Action::"kms.Sign", resource == Key::"prod-key");
   ```
   Validation runs as you type. Without an `@id` you get an error and a quick fix.
4. **Diff.** The draft-vs-active matrix highlights the cells your draft changes.
5. **Simulate.** Pick `developer-agent`, `kms.Encrypt`, `demo-key`, then set the simulated time to `2027-01-16`. You get DENY with a "SIMULATED TIME" badge, which is the US5 expiry.
6. **Tests → Run all.** The 4Orbit matrix should still pass. Add a case: `deployment-agent kms.Sign prod-key → ALLOW`.
7. **Activate.** You get version 2. Within `ORBITPORT_KMS_POLICY_CACHE_TTL_SECS`, the KMS enforces it. Check with `rpc deployment-agent kms.Sign …` (this needs a signing key; see the next point).
8. **Versions → Roll back** to v1. Enforcement reverts.
9. **Agents → Mint token.** Pick an agent and a TTL, then copy the token and the `kms-mcp` snippet. The token is shown only once.
10. **Export.** Download the policy bundle, because dev OpenBao loses it on `down`.

For console development with hot reload, against the running stack:

```sh
cd console
npm ci
ORBITPORT_URL=http://127.0.0.1:8080 ORBITPORT_CONSOLE_PAT_FILE=../.4orbit/tokens/operator.pat npm run dev   # http://127.0.0.1:5173
```

---

## 9. Run a real agent through MCP **(M3)**

```sh
make mcp-build                                    # builds target/release/kms-mcp
install -m 755 target/release/kms-mcp ~/.local/bin/kms-mcp
```

Point your MCP client (Claude Code, Claude Desktop, Codex) at the launcher with an **agent** PAT. Don't use the operator PAT here:

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

Ask the agent to encrypt with `kms:dev-key` (allowed), then to rotate it (denied). Both show up in **Activity**. More client examples are in [`mcp/CLIENT_SETUP.md`](mcp/CLIENT_SETUP.md).

---

## 10. Tests

```sh
make test                        # Go + Rust unit tests, incl. authz permission matrix (M1)
make lint
(cd console && npm ci && npm test && npm run typecheck)                 # (M5)

# e2e against the merged stack (it must be up)
make E2E_PROFILE=agents e2e-lazy                                        # (M3)
(cd console && npx playwright test)                                     # (M6)

# Regression: the original suites still pass on the plain dev stack
make 4orbit-down && make devenv-up && make e2e-all && make go-e2e
```

---

## 11. Day-to-day operation

| Task | Command |
|---|---|
| Start (existing images) | `make 4orbit` |
| Rebuild after code changes | `make 4orbit-up` |
| Logs | `docker compose -f dev.docker-compose.yaml -f local-pat.compose.yaml -f 4orbit.compose.yaml logs --tail 100 -f gateway plugin-kms plugin-policy` |
| Stop, keep containers | `make 4orbit-stop` |
| Tear down | `make 4orbit-down` |
| Refresh expired agent tokens | `make 4orbit-seed` (only re-mints, keeps keys and policies) |
| Move the audit log aside | `docker exec plugin-policy sh -c 'mv /var/lib/orbitport/audit/*.jsonl /var/lib/orbitport/audit/archive/'` |

**Persistence warning:** OpenBao dev mode keeps everything **in memory**. `down` (and often a Docker Desktop restart) wipes keys, KV metadata **and every policy version**. After a reset, run `make 4orbit-seed` and re-import your exported bundle from the console. Never use `down -v` unless you mean to delete the IPFS and plugin-build volumes as well.

---

## 12. Troubleshooting

| Symptom | Cause and fix |
|---|---|
| `make: docker-compose: command not found` | Install `docker-compose`, or use the `docker compose` commands shown in §3 and §5. |
| OpenBao plugin builders fail | The sibling repos are present but broken. Remove them or `git pull` them. When they're absent, builders skip. |
| `401` on every call after the overlay | Real PAT verification is on, so `test_access_token` no longer works. Use the files in `.4orbit/tokens/`. Tokens expired? Run `make 4orbit-seed`. |
| Legacy e2e fails on the overlay | Expected: it uses `authnoop` tokens. Run it on the plain dev stack (§10). |
| Every agent call is DENY, even allowed ones | No active policy (OpenBao was reset), so run `make 4orbit-seed`. Or `plugin-policy` is down (`docker logs plugin-policy`), and agents fail closed. |
| A policy change isn't enforced | Wait for `ORBITPORT_KMS_POLICY_CACHE_TTL_SECS`. Check the console header shows the new active version. |
| Activate refused | A test case failed. Open **Tests** to see which. |
| Console shows `403` | Wrong host. Browse to `http://127.0.0.1:4317`. Over SSH, use `ssh -L 4317:127.0.0.1:4317 host`. |
| Console says "operator token missing" | `.4orbit/tokens/operator.pat` doesn't exist. Run `make 4orbit-seed`. |
| `Alias already exists` from `kms.CreateKey` | Creation isn't idempotent. Use the existing `kms:<alias>`. |
| `kms.CreateKey` returns HTTP 400 | Include `"Tags": []` even when it's empty. |
| Port in use (8080, 8200, 4317 …) | Stop the other process, or change the host port in `4orbit.compose.yaml`. |
| Builds are very slow or OOM on a Mac | Raise Docker Desktop memory to 6 GB or more. |

---

## Before the merge lands

Until M3 is done, the closest working setup is the 4Orbit external gate pointed at this local stack (verified October 16, 2026):

```sh
# Terminal 1: base Orbitport stack (section 3)
cd ~/cs189/orbitport && make devenv-up

# Create a local key once
curl -fsS http://127.0.0.1:8080/api/v1/rpc -H 'Content-Type: application/json' \
  -H 'Authorization: Bearer test_access_token' \
  -d '{"jsonrpc":"2.0","id":1,"method":"kms.CreateKey","params":{"Description":"4orbit demo","Scheme":"TRANSIT","KeySpec":"AES_256_GCM96","KeyUsage":"ENCRYPT_DECRYPT","Alias":"demo-key","Tags":[]}}'

# Terminal 2: 4Orbit Prototype 1 against localhost
cd ~/cs189/4orbit/prototype-1 && npm ci
ORBITPORT_API_URL=http://127.0.0.1:8080 ORBITPORT_ACCESS_TOKEN=test_access_token \
ORBITPORT_DEMO_KEY_ID=kms:demo-key npm run demo:real

# Terminal 3: the GUI v1 console (read-only, mock test requests)
cd ~/cs189/4orbit/web && npm ci && npm start     # http://127.0.0.1:4317
```

This setup has the limits that motivate the merge: Cedar runs outside Orbitport, so the shared token bypasses it, and agent IDs are self-asserted.

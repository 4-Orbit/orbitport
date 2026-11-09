# Orbitport KMS examples

Short, runnable use cases for the Orbitport KMS API, grouped by role. Each one is a bash script that calls the public JSON-RPC API with your token and checks the results with standard tools such as `openssl`. The AI agent demo goes through the local MCP server instead.

## Before you start

You need `bash`, `curl`, `jq` and `openssl`. Some demos need OpenSSL 3 (for Ed25519 keys and prehashed verification); macOS ships LibreSSL, so install it with `brew install openssl@3` and put it first in your `PATH`. The Web3 demo uses [Foundry](https://getfoundry.sh) `cast` when it is installed. The AI agent demo needs Foundry (`cast` and `anvil`) and `kms-mcp`; see its README.

1. Sign up on the [dashboard](https://accounts.spacecomputer.io) and create an API token.
2. Copy `examples/.env.example` to `examples/.env` and set `ORBITPORT_PAT` to your token. `.env` is gitignored.
3. From `examples/kms/`, create the demo keys once:

   ```bash
   ./setup.sh
   ```

4. List the demos and run one, or run them all:

   ```bash
   ./demo.sh
   ./demo.sh signed-webhooks
   ./demo.sh --all
   ```

   `--all` runs every demo in order and keeps going if one fails. It ends with `All 23 demos passed`, or with how many passed and which failed, and then exits with status 1.

Each demo writes its files to `.work/<demo>/` so you can inspect them after the run. Set `DEMO_PAUSE=1` in `.env` to wait for Enter between steps.

For a one-off call, use `rpc.sh`:

```bash
./rpc.sh kms.GetKeyMetadata '{"KeyId":"examples-sign-p256"}'
./rpc.sh kms.GetCapabilities
```

## Run on Linux

The scripts also run on Linux. To try them in a container, run this from `examples/kms/`:

```bash
docker run --rm -it -v "$(dirname "$PWD")":/examples -w /examples/kms ubuntu:24.04 bash -c 'apt-get update -qq && apt-get install -y -qq curl jq openssl ca-certificates >/dev/null && ./demo.sh --all'
```

It mounts `examples/`, including `.env`, installs the tools and runs every demo. The container has no Foundry or `kms-mcp`, so the AI agent demo fails there; run it on your machine. If the demo keys do not exist yet, run the same command with `./setup.sh` in place of `./demo.sh --all` first. On a Linux host the container writes `.work/` as root, so remove it afterwards with `sudo rm -rf .work`.

## Demos

Each `run.sh` shows its JSON-RPC requests and `openssl` checks in full, so you can copy them into your own code. `lib/common.sh` only holds the config, output, the `rpc` call, encoding and the local envelope crypto.

### Dev

| Demo | What it shows |
| --- | --- |
| [pii-encryption](dev/pii-encryption/) | Encrypt sensitive columns before they reach the database |
| [signed-webhooks](dev/signed-webhooks/) | Sign each webhook; a changed byte or replayed timestamp is rejected |
| [kms-jwt](dev/kms-jwt/) | Mint ES256 JWTs with no key file on disk |
| [license-keys](dev/license-keys/) | Sign licenses once, verify them offline in the app |
| [signed-download-links](dev/signed-download-links/) | Expiring download links checked with only the public key |
| [large-file-encryption](dev/large-file-encryption/) | Envelope encryption: a 100 MB file never travels to the KMS |
| [web3-signing](dev/web3-signing/) | EIP-191 signing with an Ethereum key that stays in the KMS |

### DevOps

| Demo | What it shows |
| --- | --- |
| [release-signing](devops/release-signing/) | CI signs artifacts without ever holding the key |
| [image-sbom-signing](devops/image-sbom-signing/) | Sign the image digest and SBOM, check both before deploy |
| [ci-secrets](devops/ci-secrets/) | CI fetches credentials at runtime instead of `.env` files |
| [secrets-per-environment](devops/secrets-per-environment/) | Same secret names under `dev/` and `prod/` prefixes |
| [encrypted-config](devops/encrypted-config/) | Commit encrypted values files, decrypt at deploy time |
| [encrypted-backups](devops/encrypted-backups/) | Encrypt database dumps before upload, then restore |

### SRE

| Demo | What it shows |
| --- | --- |
| [rotation-drill](sre/rotation-drill/) | Rotate live keys; old ciphertext and signatures keep working |
| [incident-response](sre/incident-response/) | Revoke a leaked token and rotate; the key never left the KMS |
| [tamper-evident-logs](sre/tamper-evident-logs/) | Sign daily log digests; an edited line fails the audit |
| [signed-config](sre/signed-config/) | Services load only config and flags that verify |
| [usage-metering](sre/usage-metering/) | Per-operation request counts and credits in the dashboard |
| [preflight-checks](sre/preflight-checks/) | Check KMS capabilities before rolling out |

### Cloud security

| Demo | What it shows |
| --- | --- |
| [non-exportable-keys](cloud-security/non-exportable-keys/) | A KMS key signs but is never readable; a stored secret comes back in full |
| [crypto-shredding](cloud-security/crypto-shredding/) | Erase a user's data by deleting their data key |
| [verify-without-trust](cloud-security/verify-without-trust/) | Verify signatures with plain `openssl`, no SDK |

### AI agents

| Demo | What it shows |
| --- | --- |
| [agent-payments](ai-agents/agent-payments/) | An agent pays from a wallet whose key stays in the KMS, through the MCP server |

## Keys and credits

`setup.sh` creates seven keys in your account, all prefixed `examples-`. Running it again keeps the keys that already exist:

| Alias | Type | Used by |
| --- | --- | --- |
| `examples-encrypt` | AES-256-GCM | encryption and data key demos |
| `examples-sign-p256` | ECDSA P-256 | most signing demos |
| `examples-sign-ed25519` | Ed25519 | license keys, download links, non-exportable keys |
| `examples-eth` | Ethereum secp256k1 | Web3 signing |
| `examples-rotation-sign` | ECDSA P-256 | rotation drill, incident response |
| `examples-rotation-encrypt` | AES-256-GCM | rotation drill |
| `examples-agent-wallet` | Ethereum secp256k1 | AI agent payments |

The API has no call to delete keys yet, so these seven keys stay in your account.

The key-store demos also leave entries with fake values: `examples/ci/db` and `examples/{dev,prod}/{db,payments}`. The next run creates them again. To delete them:

```bash
for n in examples/ci/db examples/dev/db examples/dev/payments examples/prod/db examples/prod/payments; do ./rpc.sh kms_keystore.Delete "{\"Name\":\"$n\"}"; done
```

Most calls use credits from your account. Creating and rotating keys cost more than other operations; the dashboard lists the price per operation. The rotation drill and incident response demos rotate a key on every run. At current prices, the first `./setup.sh` costs about 77 credits and each `./demo.sh --all` about 107.

## Troubleshooting

| Message | What to do |
| --- | --- |
| `401 Unauthorized: check ORBITPORT_PAT` | The token is wrong, expired or revoked. Create a new one in the dashboard and update `.env` |
| `402 out of credits` | Add credits in the dashboard, then run the demo again |
| `429 rate limited` | Wait a few seconds and run again |
| `did you run ./setup.sh?` | The demo keys are missing. Run `./setup.sh` |
| `OpenSSL 3 is required` | Install OpenSSL 3 and put it first in your `PATH` (see Before you start) |
| `'kms-mcp' is required for this demo` | Install Foundry and `kms-mcp`, or set `KMS_MCP_BIN` in `.env` to the full path (see the agent-payments README) |
| `port 18545 is already in use` | Stop the process using that port, often an earlier `anvil`, and run again |

## Configuration

| Variable | Default | Purpose |
| --- | --- | --- |
| `ORBITPORT_PAT` | (required) | API token from the dashboard |
| `ORBITPORT_URL` | `https://op.spacecomputer.io` | Gateway base URL |
| `ORBITPORT_DASHBOARD_URL` | `https://accounts.spacecomputer.io` | Dashboard link shown by some demos |
| `KMS_MCP_BIN` | `kms-mcp` | MCP server executable for the AI agent demo, a name on `PATH` or a full path |
| `DEMO_PAUSE` | `0` | `1` waits for Enter between steps |

All settings are read from `examples/.env` only. Variables with the same names in your shell are ignored.

The token is sent through a curl header file, so it never appears in the process list. The AI agent demo passes it to `kms-mcp` in its environment, the way an MCP client does, never as an argument.

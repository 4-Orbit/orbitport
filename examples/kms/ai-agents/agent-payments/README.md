# AI agent payments

An AI agent pays from an Ethereum wallet without ever holding its private key. The key stays in the KMS. The agent connects through the MCP server with a revocable API token, builds each payment and asks the KMS to sign it. If the agent is hacked, the attacker gets the token, not the key, and revoking the token ends their access.

```bash
./run.sh
```

The script plays the agent: it talks to `kms-mcp` over stdio, the same way an MCP client does, so it runs without an LLM. Payments go to a local test chain that the demo starts and stops, so no faucet or test funds are needed.

MCP tools: `tools/list`, `kms_get_key_metadata` (address) and `kms_sign` (`ETHEREUM_SECP256K1`, `DIGEST`) on `examples-agent-wallet`. Token revocation happens in the dashboard; the last step uses an invalid token to show what the agent sees afterwards.

## What you need

- [Foundry](https://getfoundry.sh) for `cast` and `anvil`.
- `kms-mcp`, the local MCP server. Follow the [install steps](../../../../mcp/README.md#install), and set `KMS_MCP_BIN` in `examples/.env` if it is not on your `PATH`.
- The `examples-agent-wallet` key. If you ran `./setup.sh` before this demo existed, run it again; it keeps the keys you already have.
- Port 18545 free for the local chain.

## How the payment is signed

1. The agent lists the payment fields (EIP-1559: chain id, nonce, fees, gas, recipient, amount).
2. It encodes them and hashes the result with keccak-256. That 32-byte hash is what a wallet signs.
3. It sends only the hash to `kms_sign` and gets back `r`, `s` and the recovery id `v`.
4. It attaches the signature and sends the raw transaction. The chain recovers the sender from the signature, so a confirmed payment from the wallet address proves the KMS key signed it.

## What a stolen token can do

Until you revoke it, the token can ask the KMS to sign anything with any key in its account, so an attacker could spend what the wallet holds during that window. It can never read or export the key, and it stops working the moment you revoke it. Every signature also shows up in your credit history.

- Give the agent its own account, so its token reaches only its wallet.
- Keep a small balance in the agent wallet.
- Use a short token lifetime.

## Use it with a real agent

Register `kms-mcp` in your MCP client with the same token, as described in [mcp/CLIENT_SETUP.md](../../../../mcp/CLIENT_SETUP.md). The agent then sees the same tools this script uses. To send payments it also needs a way to build and broadcast transactions, such as shell access to `cast`.

#!/usr/bin/env bash
# AI agent payments: the agent pays from a wallet whose key stays in the KMS, through the MCP server.

source "$(dirname "${BASH_SOURCE[0]}")/../../lib/common.sh"
init_demo agent-payments

for bin in "$KMS_MCP_BIN" cast anvil; do
  command -v "$bin" >/dev/null 2>&1 ||
    die "'$bin' is required for this demo. Install Foundry (cast, anvil) and kms-mcp, see the demo README"
done
export FOUNDRY_DISABLE_NIGHTLY_WARNING=1

CHAIN_PORT=18545
CHAIN_RPC="http://127.0.0.1:$CHAIN_PORT"
MERCHANT="0x000000000000000000000000000000000000bEEF"
AMOUNT_ETH="0.01"

# minimal big-endian hex for an RLP field: no leading zero bytes, zero is empty
rlp_hex() {
  local h="${1#0x}"
  h="${h#"${h%%[!0]*}"}"
  if ((${#h} % 2)); then h="0$h"; fi
  echo "0x$h"
}
rlp_int() { rlp_hex "$(cast to-hex "$1")"; }

title "AI agent payments (key in the KMS, agent over MCP)"

step "The agent connects to the KMS through the MCP server"
tools=$(mcp_tools)
info "$(echo "$tools" | jq 'length') tools: $(echo "$tools" | jq -r 'join(", ")')"
ok "none of them can read or export a private key"
info "The agent's only credential is the API token in .env."

step "The wallet key lives in the KMS"
meta=$(mcp_call kms_get_key_metadata "$(jq -nc --arg k "$KEY_AGENT_WALLET" '{KeyId:$k}')")
wallet=$(echo "$meta" | jq -r '.KeyMetadata.Address')
ok "wallet $wallet"
info "The agent knows the address. The private key never leaves the KMS."

step "Start a local test chain and fund the wallet"
if cast chain-id --rpc-url "$CHAIN_RPC" >/dev/null 2>&1; then
  die "port $CHAIN_PORT is already in use; stop that process and run again"
fi
anvil --port "$CHAIN_PORT" >anvil.log 2>&1 &
anvil_pid=$!
trap 'kill "$anvil_pid" 2>/dev/null || true' EXIT
for _ in $(seq 1 50); do
  cast chain-id --rpc-url "$CHAIN_RPC" >/dev/null 2>&1 && break
  sleep 0.1
done
chain_id=$(cast chain-id --rpc-url "$CHAIN_RPC" 2>/dev/null) || die "anvil did not start, see $WORK_DIR/anvil.log"
cast rpc anvil_setBalance "$wallet" "$(cast to-hex "$(cast to-wei 1)")" --rpc-url "$CHAIN_RPC" >/dev/null
ok "chain $chain_id on port $CHAIN_PORT, wallet balance $(cast balance "$wallet" --ether --rpc-url "$CHAIN_RPC") ETH"
info "Test money on a throwaway chain. Funding it needs no private key."

step "The agent builds a payment of $AMOUNT_ETH ETH to a merchant"
nonce=$(cast nonce "$wallet" --rpc-url "$CHAIN_RPC")
base_fee=$(cast base-fee --rpc-url "$CHAIN_RPC")
tip=1000000000
max_fee=$((base_fee * 2 + tip))
# EIP-1559 fields: chain id, nonce, tip, max fee, gas, to, value, data, access list
fields=$(jq -nc --arg c "$(rlp_int "$chain_id")" --arg n "$(rlp_int "$nonce")" --arg t "$(rlp_int "$tip")" \
  --arg m "$(rlp_int "$max_fee")" --arg g "$(rlp_int 21000)" --arg to "$MERCHANT" \
  --arg v "$(rlp_int "$(cast to-wei "$AMOUNT_ETH")")" '[$c, $n, $t, $m, $g, $to, $v, "0x", []]')
echo "$fields" | jq . >payment.json
show <payment.json
unsigned="0x02$(cast to-rlp "$fields" | cut -c3-)"
sighash=$(cast keccak "$unsigned")
info "hash to sign (keccak-256 of the type 2 transaction): $sighash"

step "The agent asks the KMS to sign the hash"
sig=$(mcp_call kms_sign "$(jq -nc --arg k "$KEY_AGENT_WALLET" --arg m "$sighash" \
  '{KeyId:$k, Message:$m, SigningAlgorithm:"ETHEREUM_SECP256K1", MessageType:"DIGEST"}')" | jq -r '.Signature')
echo "$sig" >signature.txt
ok "signature ${sig:0:20}...${sig: -8}"
info "Only the 32-byte hash went to the KMS. The reply is r, s and the recovery id v."

step "The agent sends the signed payment"
s="${sig#0x}"
v=$((16#${s:128:2}))
y_parity=$((v >= 27 ? v - 27 : v))
signed_fields=$(echo "$fields" | jq -c --arg y "$(rlp_int "$y_parity")" --arg r "$(rlp_hex "${s:0:64}")" \
  --arg s "$(rlp_hex "${s:64:64}")" '. + [$y, $r, $s]')
raw="0x02$(cast to-rlp "$signed_fields" | cut -c3-)"
echo "$raw" >payment.signed.txt
tx=$(cast publish "$raw" --rpc-url "$CHAIN_RPC" | jq -r '.transactionHash')
receipt=$(cast receipt "$tx" --rpc-url "$CHAIN_RPC" --json)
from=$(echo "$receipt" | jq -r '.from')
[[ "$(echo "$receipt" | jq -r '.status')" == "0x1" ]] || die "the chain rejected the payment, see $WORK_DIR"
[[ "$(echo "$from" | tr 'A-F' 'a-f')" == "$(echo "$wallet" | tr 'A-F' 'a-f')" ]] ||
  die "the payment was sent from $from, not from the KMS wallet"
ok "confirmed: ${tx:0:18}... sent from the KMS wallet"
balance=$(cast balance "$wallet" --ether --rpc-url "$CHAIN_RPC")
info "wallet $balance ETH, merchant $(cast balance "$MERCHANT" --ether --rpc-url "$CHAIN_RPC") ETH"
info "The chain recovered the sender from the signature, so only the KMS key could have signed it."

step "The agent is hacked, and you revoke its token"
note "What the attacker gets: the token, not the key. It works only until you revoke it."
info "Revoke the agent's token in the dashboard: $ORBITPORT_DASHBOARD_URL"
info "Here an invalid token stands in for the revoked one, so your real token keeps working."
if out=$(ORBITPORT_PAT="revoked-agent-token" mcp_try kms_sign "$(jq -nc --arg k "$KEY_AGENT_WALLET" --arg m "$sighash" \
  '{KeyId:$k, Message:$m, SigningAlgorithm:"ETHEREUM_SECP256K1", MessageType:"DIGEST"}')"); then
  die "the KMS signed with an invalid token"
fi
bad "refused: $out"
[[ "$(cast balance "$wallet" --ether --rpc-url "$CHAIN_RPC")" == "$balance" ]] || die "the wallet balance changed"
ok "wallet balance unchanged: $balance ETH"
note "Give the agent its own account, a small balance and a short token lifetime."

done_banner

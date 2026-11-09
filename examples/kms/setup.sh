#!/usr/bin/env bash
# Creates the demo keys once. Safe to run again: existing keys are kept.

source "$(dirname "${BASH_SOURCE[0]}")/lib/common.sh"

require_tools curl jq openssl
require_pat

title "Orbitport KMS examples: setup"
info "Gateway: $ORBITPORT_URL"

# alias scheme key-spec key-usage description
KEYS=(
  "$KEY_ENCRYPT TRANSIT AES_256_GCM96 ENCRYPT_DECRYPT field and envelope encryption"
  "$KEY_SIGN TRANSIT ECDSA_P256 SIGN_VERIFY ECDSA P-256 signing"
  "$KEY_SIGN_ED25519 TRANSIT ED25519 SIGN_VERIFY Ed25519 signing"
  "$KEY_ETH ETHEREUM ECC_SECG_P256K1 SIGN_VERIFY Ethereum signing"
  "$KEY_ROTATION_SIGN TRANSIT ECDSA_P256 SIGN_VERIFY rotation demos (signing)"
  "$KEY_ROTATION_ENCRYPT TRANSIT AES_256_GCM96 ENCRYPT_DECRYPT rotation demos (encryption)"
  "$KEY_AGENT_WALLET ETHEREUM ECC_SECG_P256K1 SIGN_VERIFY AI agent wallet"
)

for entry in "${KEYS[@]}"; do
  read -r alias scheme spec usage desc <<<"$entry"
  step "$alias ($scheme $spec)"
  if out=$(rpc_try kms.GetKeyMetadata "$(jq -nc --arg k "$alias" '{KeyId:$k}')"); then
    ok "already exists"
    continue
  fi
  # a missing key reads as "does not belong"; anything else (401, network) stops here
  [[ "$out" == *"does not belong"* ]] || die "kms.GetKeyMetadata failed: $out"
  rpc kms.CreateKey "$(jq -nc --arg a "$alias" --arg s "$scheme" --arg ks "$spec" --arg u "$usage" --arg d "$desc" \
    '{Alias:$a, Scheme:$s, KeySpec:$ks, KeyUsage:$u, Description:$d, Tags:[{TagKey:"purpose", TagValue:"examples"}]}')" >/dev/null
  ok "created"
done

echo
ok "Keys are ready. Run ./demo.sh to see the demos."

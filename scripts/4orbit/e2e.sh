#!/usr/bin/env bash
# End-to-end checks for the 4Orbit stack (make 4orbit-up && make 4orbit-seed).
#
# Exercises real PAT verification, per-agent Cedar enforcement in the KMS
# plugin, the audit trail, the policy playground API (validate, simulate,
# matrix, diff, tests gate, activate, rollback) and agent-token rules.
# Exits non-zero on the first failed check.
set -uo pipefail

root="$(cd "$(dirname "$0")/../.." && pwd)"
rpc="$root/scripts/4orbit/rpc.sh"
url="${ORBITPORT_URL:-http://127.0.0.1:8080}"
ttl="${ORBITPORT_KMS_POLICY_CACHE_TTL_SECS:-5}"
pass=0
fail=0

ok()   { pass=$((pass + 1)); printf '  \033[32mPASS\033[0m %s\n' "$1"; }
bad()  { fail=$((fail + 1)); printf '  \033[31mFAIL\033[0m %s\n       %s\n' "$1" "$2"; }

# expect <description> <token> <method> <params> <jq-filter that must be true>
expect() {
  local desc="$1" token="$2" method="$3" params="$4" filter="$5" out
  out="$("$rpc" "$token" "$method" "$params" 2>&1)"
  if echo "$out" | jq -e "$filter" >/dev/null 2>&1; then ok "$desc"; else bad "$desc" "$out"; fi
}

allowed() { echo '.result != null and .error == null'; }
denied()  { echo '.error.message | test("denied by policy")'; }

http_status() {
  local token="$1"
  curl -s -o /dev/null -w '%{http_code}' "$url/api/v1/rpc" \
    -H 'Content-Type: application/json' -H "Authorization: Bearer $token" \
    -d '{"jsonrpc":"2.0","id":1,"method":"kms.GetKeyMetadata","params":{"KeyId":"kms:dev-key"}}'
}

for f in operator developer-agent security-agent deployment-agent; do
  [[ -r "$root/.4orbit/tokens/$f.pat" ]] || { echo "missing .4orbit/tokens/$f.pat: run make 4orbit-seed" >&2; exit 1; }
done
curl -fsS "$url/healthz" >/dev/null || { echo "gateway not healthy at $url" >&2; exit 1; }

echo "== Health"
ok "gateway /healthz"
if curl -fsS http://127.0.0.1:8091/.well-known/jwks.json | jq -e '.keys | length >= 1' >/dev/null; then ok "JWKS published"; else bad "JWKS published" "no keys"; fi

echo "== Authentication"
dev_token="$(tr -d '[:space:]' < "$root/.4orbit/tokens/developer-agent.pat")"
# Forge a claim: swap the payload's agent_id but keep the original signature.
b64url_decode() { local s="${1//-/+}"; s="${s//_//}"; while (( ${#s} % 4 )); do s="$s="; done; echo "$s" | base64 -d 2>/dev/null; }
b64url_encode() { base64 | tr -d '=\n' | tr '+/' '-_'; }
IFS=. read -r h p sig <<< "$dev_token"
forged_payload="$(b64url_decode "$p" | jq -c '.agent_id = "security-agent"' | b64url_encode)"
s="$(http_status "$h.$forged_payload.$sig")"; [[ "$s" == 401 ]] && ok "forged agent_id claim rejected (401)" || bad "forged agent_id claim rejected" "HTTP $s"
# Corrupt the signature itself (first character, which carries real bits).
first="${sig:0:1}"; [[ "$first" == "A" ]] && repl=B || repl=A
s="$(http_status "$h.$p.$repl${sig:1}")"; [[ "$s" == 401 ]] && ok "corrupted signature rejected (401)" || bad "corrupted signature rejected" "HTTP $s"
s="$(http_status "agent:developer-agent")"; [[ "$s" == 401 ]] && ok "authnoop dev convention not accepted by real auth (401)" || bad "dev convention rejected" "HTTP $s"
s="$(http_status "test_access_token")"; [[ "$s" == 401 ]] && ok "legacy dev bearer rejected (401)" || bad "legacy bearer rejected" "HTTP $s"

echo "== Enforcement (4Orbit permission matrix, live KMS)"
P='{"KeyId":"kms:dev-key","Plaintext":"aGVsbG8="}'
expect "developer encrypts dev-key (ALLOW)"            developer-agent  kms.Encrypt   "$P" "$(allowed) and .result.KeyId == \"kms:dev-key\""
expect "developer rotates dev-key (DENY)"              developer-agent  kms.RotateKey '{"KeyId":"kms:dev-key"}' "$(denied)"
expect "developer encrypts prod-key (DENY)"            developer-agent  kms.Encrypt   '{"KeyId":"kms:prod-key","Plaintext":"aGVsbG8="}' "$(denied)"
expect "developer reads key metadata (DENY: read not granted)" developer-agent kms.GetKeyMetadata '{"KeyId":"kms:dev-key"}' "$(denied)"
expect "developer encrypts unknown key (DENY, not not-found)" developer-agent kms.Encrypt '{"KeyId":"kms:nope","Plaintext":"aGVsbG8="}' "$(denied)"
expect "security encrypts demo-key (DENY)"             security-agent   kms.Encrypt   '{"KeyId":"kms:demo-key","Plaintext":"aGVsbG8="}' "$(denied)"
expect "security rotates prod-key (ALLOW)"             security-agent   kms.RotateKey '{"KeyId":"kms:prod-key"}' "$(allowed) and .result.KeyMetadata.PrimaryVersion >= 2"
expect "deployment encrypts prod-key (ALLOW)"          deployment-agent kms.Encrypt   '{"KeyId":"kms:prod-key","Plaintext":"aGVsbG8="}' "$(allowed)"
expect "deployment encrypts dev-key (DENY)"            deployment-agent kms.Encrypt   "$P" "$(denied)"
expect "deployment creates a key (DENY: admin)"        deployment-agent kms.CreateKey '{"Description":"x","Scheme":"TRANSIT","KeySpec":"AES_256_GCM96","KeyUsage":"ENCRYPT_DECRYPT","Alias":"agent-made","Tags":[]}' "$(denied)"
blob="$("$rpc" developer-agent kms.Encrypt "$P" | jq -r .result.CiphertextBlob)"
expect "developer decrypts its ciphertext (DENY: decrypt not granted)" developer-agent kms.Decrypt "{\"CiphertextBlob\":\"$blob\"}" "$(denied)"
expect "operator (account PAT) decrypts it (ALLOW: platform.owner)"   operator kms.Decrypt "{\"CiphertextBlob\":\"$blob\"}" "$(allowed) and .result.Plaintext == \"aGVsbG8=\""
expect "operator rotates dev-key (ALLOW: platform.owner)" operator kms.RotateKey '{"KeyId":"kms:dev-key"}' "$(allowed)"

echo "== Policy administration is account-only"
expect "agent cannot read policy"         security-agent  policy.GetActive '{}' "$(denied)"
expect "agent cannot activate a version"  security-agent  policy.Activate '{"version":1}' "$(denied)"
expect "agent cannot mint agent tokens"   developer-agent policy.IssueAgentToken '{"agentId":"security-agent"}' "$(denied)"
expect "agent cannot list keys"           developer-agent policy.ListKeys '{}' "$(denied)"
expect "unknown policy method rejected"   operator policy.DropEverything '{}' '.error != null'

echo "== Audit"
sleep 1
expect "DENY of developer rotate recorded with kmsCalled=false" operator policy.ListAudit '{"agentId":"developer-agent","action":"kms.RotateKey","decision":"DENY","limit":5}' \
  '.result.events | length >= 1 and all(.decision == "DENY" and .kmsCalled == false)'
expect "ALLOW records determining policy and KMS success" operator policy.ListAudit '{"agentId":"developer-agent","decision":"ALLOW","limit":5}' \
  '.result.events[0].determiningPolicies == ["developer-encrypt-dev-key"] and .result.events[0].kmsResult.status == "SUCCESS"'
expect "agent policy-admin attempts are audited" operator policy.ListAudit '{"agentId":"security-agent","action":"policy.Activate","limit":5}' \
  '.result.events[0].determiningPolicies == ["platform.agents-never-administer-policy"]'
expect "audit has no plaintext or ciphertext" operator policy.ListAudit '{"limit":200}' \
  "(tostring | test(\"aGVsbG8=|$blob\") | not)"

echo "== Playground API"
expect "schema and actions" operator policy.GetSchema '{}' '.result.actions | length >= 20'
expect "ListKeys returns the seeded keys with tags" operator policy.ListKeys '{}' \
  '[.result.keys[].alias] | sort == ["demo-key","dev-key","prod-key"]'
expect "Validate flags a policy without @id" operator policy.Validate '{"policies":"permit (principal, action, resource);"}' '.result.ok == false'
expect "Simulate: developer demo-key now (ALLOW)" operator policy.Simulate \
  '{"requests":[{"agentId":"developer-agent","action":"kms.Encrypt","resource":{"type":"Key","id":"demo-key"}}]}' \
  '.result.results[0].decision == "ALLOW" and .result.simulatedTime == false'
expect "Simulate time travel past US5 expiry (DENY)" operator policy.Simulate \
  '{"at":1800000000,"requests":[{"agentId":"developer-agent","action":"kms.Encrypt","resource":{"type":"Key","id":"demo-key"}}]}' \
  '.result.results[0].decision == "DENY" and .result.simulatedTime == true'
expect "Matrix over the active version" operator policy.Matrix '{}' '.result.cells | length == 90'
expect "Stored test suite passes" operator policy.RunTests '{}' '.result.failed == 0 and .result.total == 98'

echo "== Draft -> test gate -> activate -> live enforcement -> rollback"
active="$("$rpc" operator policy.GetActive '{}')"
v1="$(echo "$active" | jq -r .result.version.version)"
policies="$(echo "$active" | jq -r .result.version.policies)"
entities="$(echo "$active" | jq -c .result.version.entities)"
grant=$'\n@id("developer-rotate-dev-key")\npermit (principal in Role::"developer", action == Action::"kms.RotateKey", resource == Key::"dev-key");\n'
draft="$(jq -cn --arg p "$policies$grant" --argjson e "$entities" '{policies:$p, entities:$e}')"
expect "Diff shows exactly the new grant" operator policy.Diff "$(jq -cn --argjson d "$draft" '{to:{draft:$d}}')" \
  '.result.changes | length == 1 and .[0].principal == "developer-agent" and .[0].action == "kms.RotateKey" and .[0].after == "ALLOW"'
saved="$("$rpc" operator policy.SaveDraft "$(jq -cn --argjson d "$draft" '$d + {message:"e2e: let developers rotate dev-key"}')")"
v2="$(echo "$saved" | jq -r .result.version)"
[[ "$v2" =~ ^[0-9]+$ ]] && ok "draft saved as v$v2" || bad "draft saved" "$saved"
expect "activation blocked by the test suite" operator policy.Activate "{\"version\":$v2}" '.result.activated == false and .result.tests.failed == 1'
expect "forced activation" operator policy.Activate "{\"version\":$v2,\"force\":true}" '.result.activated == true and .result.forced == true'
sleep $((ttl + 1))
expect "KMS now lets developer rotate dev-key" developer-agent kms.RotateKey '{"KeyId":"kms:dev-key"}' "$(allowed)"
sleep 1  # audit is shipped in 250 ms batches
expect "audit names the new policy and version" operator policy.ListAudit '{"agentId":"developer-agent","action":"kms.RotateKey","decision":"ALLOW","limit":1}' \
  ".result.events[0].determiningPolicies == [\"developer-rotate-dev-key\"] and .result.events[0].policyVersion == $v2"
expect "rollback to v$v1" operator policy.Activate "{\"version\":$v1}" '.result.activated == true'
sleep $((ttl + 1))
expect "KMS denies developer rotate again" developer-agent kms.RotateKey '{"KeyId":"kms:dev-key"}' "$(denied)"

echo "== Agent tokens"
expect "operator mints a 5-minute developer token" operator policy.IssueAgentToken '{"agentId":"developer-agent","ttlSeconds":300}' \
  '.result.token | length > 100'
expect "unregistered agent refused" operator policy.IssueAgentToken '{"agentId":"ghost-agent"}' '.error.data.reason == "failed_precondition"'
expect "TTL below the floor refused" operator policy.IssueAgentToken '{"agentId":"developer-agent","ttlSeconds":5}' '.error.data.reason == "invalid_argument"'
fresh="$("$rpc" operator policy.IssueAgentToken '{"agentId":"deployment-agent","ttlSeconds":120}' | jq -r .result.token)"
out="$(curl -sS "$url/api/v1/rpc" -H 'Content-Type: application/json' -H "Authorization: Bearer $fresh" \
  -d '{"jsonrpc":"2.0","id":1,"method":"kms.Encrypt","params":{"KeyId":"kms:prod-key","Plaintext":"aGVsbG8="}}')"
echo "$out" | jq -e '.result.KeyId == "kms:prod-key"' >/dev/null && ok "freshly minted deployment token works" || bad "fresh token works" "$out"

echo
echo "passed: $pass  failed: $fail"
[[ $fail -eq 0 ]]

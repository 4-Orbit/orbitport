#!/usr/bin/env bash
# Shared helpers for the KMS examples. Every run.sh sources this file.
#
# Configuration comes only from examples/.env (shared by all examples), never from the shell:
#   ORBITPORT_PAT            personal access token from the dashboard (required)
#   ORBITPORT_URL            gateway base URL (default https://op.spacecomputer.io)
#   ORBITPORT_DASHBOARD_URL  dashboard URL shown by some demos
#   KMS_MCP_BIN              kms-mcp executable for the AI agent demos (default kms-mcp on PATH)
#   DEMO_PAUSE=1             wait for Enter between steps

set -euo pipefail

KMS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
EXAMPLES_DIR="$(dirname "$KMS_DIR")"

# ignore copies in the shell, so a stale token there cannot shadow .env
unset ORBITPORT_PAT ORBITPORT_URL ORBITPORT_DASHBOARD_URL KMS_MCP_BIN DEMO_PAUSE
if [[ -f "$EXAMPLES_DIR/.env" ]]; then
  set -a
  # shellcheck disable=SC1091
  source "$EXAMPLES_DIR/.env"
  set +a
fi

ORBITPORT_URL="${ORBITPORT_URL:-https://op.spacecomputer.io}"
ORBITPORT_DASHBOARD_URL="${ORBITPORT_DASHBOARD_URL:-https://accounts.spacecomputer.io}"
KMS_MCP_BIN="${KMS_MCP_BIN:-kms-mcp}"
RPC_URL="${ORBITPORT_URL%/}/api/v1/rpc"

# demo keys, created once by setup.sh (aliases are scoped to your account)
# shellcheck disable=SC2034
{
  KEY_ENCRYPT="examples-encrypt"
  KEY_SIGN="examples-sign-p256"
  KEY_SIGN_ED25519="examples-sign-ed25519"
  KEY_ETH="examples-eth"
  KEY_ROTATION_SIGN="examples-rotation-sign"
  KEY_ROTATION_ENCRYPT="examples-rotation-encrypt"
  KEY_AGENT_WALLET="examples-agent-wallet"
}

############################################
# Output
############################################

if [[ -t 1 && -z "${NO_COLOR:-}" ]]; then
  C_BOLD=$'\033[1m' C_DIM=$'\033[2m' C_RED=$'\033[31m' C_GREEN=$'\033[32m'
  C_YELLOW=$'\033[33m' C_BLUE=$'\033[34m' C_CYAN=$'\033[36m' C_RESET=$'\033[0m'
else
  C_BOLD="" C_DIM="" C_RED="" C_GREEN="" C_YELLOW="" C_BLUE="" C_CYAN="" C_RESET=""
fi

STEP_NO=0

title() {
  echo
  echo "${C_BOLD}${C_BLUE}== $* ==${C_RESET}"
}

step() {
  STEP_NO=$((STEP_NO + 1))
  pause
  echo
  echo "${C_BOLD}${STEP_NO}. $*${C_RESET}"
}

info() { echo "   $*"; }
ok()   { echo "   ${C_GREEN}✔ $*${C_RESET}"; }
bad()  { echo "   ${C_RED}✘ $*${C_RESET}"; }
note() { echo "   ${C_YELLOW}$*${C_RESET}"; }
die()  { echo "${C_RED}error: $*${C_RESET}" >&2; exit 1; }

# show a file or value in a dimmed block, long lines cut; awk also ends a last line with no newline
show() {
  awk -v d="$C_DIM" -v r="$C_RESET" '{ if (length($0) > 105) $0 = substr($0, 1, 105) "…"; print "     " d $0 r }'
}

pause() {
  if [[ "${DEMO_PAUSE:-0}" == "1" && -t 0 ]]; then
    read -r -p "   ${C_DIM}(Enter to continue)${C_RESET}" _
  fi
}

done_banner() {
  echo
  echo "${C_BOLD}${C_GREEN}Done.${C_RESET} Files are in ${WORK_DIR#"$KMS_DIR"/}"
}

############################################
# Setup checks
############################################

require_tools() {
  local bin
  for bin in "$@"; do
    command -v "$bin" >/dev/null 2>&1 || die "'$bin' is required but not installed"
  done
}

# Ed25519 keys and prehashed verification need OpenSSL 3 (LibreSSL lacks them)
require_openssl3() {
  openssl version | grep -q '^OpenSSL 3' ||
    die "OpenSSL 3 is required (found: $(openssl version)). On macOS: brew install openssl@3"
}

require_pat() {
  [[ -n "${ORBITPORT_PAT:-}" ]] ||
    die "ORBITPORT_PAT is not set. Create a token in the dashboard and put it in examples/.env"
}

# work dir per demo, kept after the run so the files can be inspected
init_demo() {
  local slug="$1"
  require_tools curl jq openssl
  require_pat
  WORK_DIR="$KMS_DIR/.work/$slug"
  rm -rf "$WORK_DIR"
  mkdir -p "$WORK_DIR"
  cd "$WORK_DIR"
}

############################################
# JSON-RPC
############################################

# rpc_try <method> <params-json>: prints the result JSON, or the error message with status 1.
# The token goes through a header file, so it never shows up in the process list.
rpc_try() {
  local method="$1" params="$2" body resp code err
  body=$(jq -nc --arg m "$method" --argjson p "$params" '{jsonrpc:"2.0", id:1, method:$m, params:$p}')
  echo "   ${C_CYAN}→ $method${C_RESET} ${C_DIM}$(echo "$params" | jq -c 'walk(if type == "string" and length > 40 then .[0:37] + "..." else . end)')${C_RESET}" >&2
  resp=$(curl -sS -X POST "$RPC_URL" \
    -H "Content-Type: application/json" \
    -H @<(printf 'Authorization: Bearer %s\n' "$ORBITPORT_PAT") \
    --data-binary @- -w $'\n%{http_code}' <<<"$body") || { echo "cannot reach $RPC_URL"; return 1; }
  code="${resp##*$'\n'}"
  resp="${resp%$'\n'*}"
  case "$code" in
    401) echo "401 Unauthorized: check ORBITPORT_PAT (expired or revoked?)"; return 1 ;;
    402) echo "402 out of credits: add credits in the dashboard ($ORBITPORT_DASHBOARD_URL)"; return 1 ;;
    429) echo "429 rate limited: wait a few seconds and run again"; return 1 ;;
  esac
  if echo "$resp" | jq -e '.result' >/dev/null 2>&1; then
    echo "$resp" | jq -c '.result'
    return 0
  fi
  err=$(echo "$resp" | jq -r '.error.message // empty' 2>/dev/null || true)
  echo "${err:-HTTP $code: $resp}"
  return 1
}

# rpc <method> <params-json>: like rpc_try, but stops the demo on error
rpc() {
  local out
  if out=$(rpc_try "$@"); then
    echo "$out"
    return 0
  fi
  if [[ "$out" == *"does not belong"* || "$out" == *"not found"* ]]; then
    die "$1 failed: $out (did you run ./setup.sh?)"
  fi
  die "$1 failed: $out"
}

############################################
# MCP (AI agent demos)
############################################

# each request starts kms-mcp, initializes and sends one message; the token goes in its
# environment, as an MCP client passes it, never as an argument
mcp_request() {
  local request="$1" init out
  init='{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"kms-examples","version":"1"}}}'
  out=$(printf '%s\n%s\n' "$init" "$request" |
    ORBITPORT_PAT="$ORBITPORT_PAT" ORBITPORT_URL="$ORBITPORT_URL" "$KMS_MCP_BIN") || return 1
  echo "$out" | jq -c 'select(.id == 2)'
}

# mcp_tools: prints the names of the tools the MCP server offers, as a JSON array
mcp_tools() {
  echo "   ${C_CYAN}→ tools/list${C_RESET}" >&2
  mcp_request '{"jsonrpc":"2.0","id":2,"method":"tools/list"}' | jq -c '[.result.tools[].name]'
}

# mcp_try <tool> <arguments-json>: prints the tool result JSON, or the error text with status 1
mcp_try() {
  local tool="$1" args="$2" resp
  echo "   ${C_CYAN}→ $tool${C_RESET} ${C_DIM}$(echo "$args" | jq -c 'walk(if type == "string" and length > 40 then .[0:37] + "..." else . end)')${C_RESET}" >&2
  resp=$(mcp_request "$(jq -nc --arg n "$tool" --argjson a "$args" \
    '{jsonrpc:"2.0", id:2, method:"tools/call", params:{name:$n, arguments:$a}}')") || { echo "cannot run $KMS_MCP_BIN"; return 1; }
  if echo "$resp" | jq -e '.result.isError == false' >/dev/null 2>&1; then
    echo "$resp" | jq -c '.result.structuredContent'
    return 0
  fi
  echo "$resp" | jq -r '.result.content[0].text // .error.message // "no response from the MCP server"'
  return 1
}

# mcp_call <tool> <arguments-json>: like mcp_try, but stops the demo on error
mcp_call() {
  local out
  if out=$(mcp_try "$@"); then
    echo "$out"
    return 0
  fi
  if [[ "$out" == *"does not exist"* ]]; then
    die "$1 failed: $out (did you run ./setup.sh?)"
  fi
  die "$1 failed: $out"
}

############################################
# Encoding
############################################

b64()  { openssl base64 -A; }
b64d() { openssl base64 -d -A; }
b64url()  { openssl base64 -A | tr '+/' '-_' | tr -d '='; }
b64url_d() {
  local s
  s=$(tr -- '-_' '+/')
  case $(( ${#s} % 4 )) in
    2) s="$s==" ;;
    3) s="$s=" ;;
  esac
  printf '%s' "$s" | openssl base64 -d -A
}
hex()  { od -An -v -tx1 | tr -d ' \n'; }
unhex() {
  local h i
  h=$(tr -d ' \n')
  # shellcheck disable=SC2059
  for ((i = 0; i < ${#h}; i += 2)); do printf "\\x${h:i:2}"; done
}
sha256_hex() { openssl dgst -sha256 -r | cut -d' ' -f1; }
sha256_b64() { openssl dgst -sha256 -binary | b64; }

# human date for an epoch, BSD and GNU date
fmt_epoch() { date -u -r "$1" '+%Y-%m-%d %H:%M:%S UTC' 2>/dev/null || date -u -d "@$1" '+%Y-%m-%d %H:%M:%S UTC'; }

############################################
# Signatures and public keys
############################################

# sig_bytes <Signature>: strips the vault:vN: prefix and decodes, writes DER or raw bytes to stdout
sig_bytes() { printf '%s' "${1#vault:v*:}" | b64d; }

# ed25519_pem: GetPublicKey returns Ed25519 keys as 32 raw bytes (base64 on stdin),
# this wraps them in the standard SPKI header and writes a PEM to stdout
ed25519_pem() {
  { printf '302a300506032b6570032100' | unhex; b64d; } | openssl pkey -pubin -inform DER -outform PEM
}

############################################
# Envelope encryption: AES-256-CTR + HMAC-SHA256 under a 64-byte data key
############################################

# envelope_encrypt <GenerateDataKey result> <in> <out>: encrypts locally with the plaintext data key,
# writes <out> (ciphertext) and <out>.json (key id, wrapped key, iv, mac)
envelope_encrypt() {
  local dk="$1" in="$2" out="$3" keyhex enc_key mac_key iv mac
  keyhex=$(echo "$dk" | jq -r '.Plaintext' | b64d | hex)
  enc_key="${keyhex:0:64}" mac_key="${keyhex:64:64}"
  iv=$(openssl rand -hex 16)
  openssl enc -aes-256-ctr -K "$enc_key" -iv "$iv" -in "$in" -out "$out"
  mac=$({ printf '%s' "$iv" | unhex; cat "$out"; } | openssl dgst -sha256 -mac HMAC -macopt "hexkey:$mac_key" -r | cut -d' ' -f1)
  echo "$dk" | jq --arg iv "$iv" --arg mac "$mac" \
    '{key_id:.KeyId, wrapped_key:.CiphertextBlob, iv:$iv, mac:$mac, cipher:"aes-256-ctr+hmac-sha256"}' >"$out.json"
}

# envelope_decrypt <plaintext data key, base64> <in> <out> [header]: checks the MAC, decrypts locally.
# The header defaults to <in>.json.
envelope_decrypt() {
  local in="$2" out="$3" hdr keyhex enc_key mac_key iv mac
  hdr=$(cat "${4:-$in.json}")
  keyhex=$(printf '%s' "$1" | b64d | hex)
  enc_key="${keyhex:0:64}" mac_key="${keyhex:64:64}"
  iv=$(echo "$hdr" | jq -r '.iv')
  mac=$({ printf '%s' "$iv" | unhex; cat "$in"; } | openssl dgst -sha256 -mac HMAC -macopt "hexkey:$mac_key" -r | cut -d' ' -f1)
  if [[ "$mac" != "$(echo "$hdr" | jq -r '.mac')" ]]; then
    return 1
  fi
  openssl enc -d -aes-256-ctr -K "$enc_key" -iv "$iv" -in "$in" -out "$out"
}

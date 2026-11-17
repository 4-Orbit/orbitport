#!/usr/bin/env bash
# Call the local gateway's JSON-RPC API with a seeded token.
#
#   scripts/4orbit/rpc.sh <token> <method> [params-json]
#
# <token> is a name under .4orbit/tokens (operator, developer-agent, ...), or
# dev:<literal> to send a literal bearer on the plain dev stack (authnoop),
# for example dev:agent:developer-agent.
set -euo pipefail

if [[ $# -lt 2 ]]; then
  echo "usage: $0 <operator|AGENT|dev:TOKEN> <method> [params-json]" >&2
  exit 2
fi

root="$(cd "$(dirname "$0")/../.." && pwd)"
name="$1"
method="$2"
params="${3:-}"
if [[ -z "$params" ]]; then
  params='{}'
fi
url="${ORBITPORT_URL:-http://127.0.0.1:8080}"

if [[ "$name" == dev:* ]]; then
  token="${name#dev:}"
else
  file="$root/.4orbit/tokens/$name.pat"
  if [[ ! -r "$file" ]]; then
    echo "no token file $file (run: make 4orbit-seed)" >&2
    exit 1
  fi
  token="$(tr -d '[:space:]' < "$file")"
fi

body=$(jq -cn --arg m "$method" --argjson p "$params" '{jsonrpc:"2.0",id:1,method:$m,params:$p}')
curl -sS "$url/api/v1/rpc" \
  -H 'Content-Type: application/json' \
  -H "Authorization: Bearer $token" \
  -d "$body"
echo

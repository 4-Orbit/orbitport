#!/usr/bin/env bash
# Lists the demos by role and runs one by name, or all of them.
#
#   ./demo.sh          list every demo
#   ./demo.sh <demo>   run a demo, e.g. ./demo.sh signed-webhooks
#   ./demo.sh --all    run every demo, then print a summary
#
# Settings come from examples/.env; DEMO_PAUSE=1 there waits for Enter between steps.

set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROLES=(dev devops sre cloud-security ai-agents)

# first line of the README, without the "# "
summary() { sed -n '1s/^# //p' "$1/README.md"; }

list() {
  local role demo
  for role in "${ROLES[@]}"; do
    echo
    echo "$role"
    for demo in "$DIR/$role"/*/; do
      demo="${demo%/}"
      printf '  %-28s %s\n' "$(basename "$demo")" "$(summary "$demo")"
    done
  done
  echo
  echo "Run one with: ./demo.sh <demo>, or all with: ./demo.sh --all"
}

# runs every demo even if one fails, exits 1 if any failed
run_all() {
  local role demo total=0 passed=0 failed=""
  for role in "${ROLES[@]}"; do
    for demo in "$DIR/$role"/*/; do
      demo="${demo%/}"
      total=$((total + 1))
      if "$demo/run.sh"; then
        passed=$((passed + 1))
      else
        failed="$failed $(basename "$demo")"
      fi
    done
  done
  echo
  if [[ -z "$failed" ]]; then
    echo "All $total demos passed"
    return 0
  fi
  echo "$passed of $total demos passed. Failed:$failed" >&2
  return 1
}

if [[ $# -eq 0 ]]; then
  list
  exit 0
fi

if [[ "$1" == "--all" ]]; then
  run_all
  exit
fi

for role in "${ROLES[@]}"; do
  if [[ -x "$DIR/$role/$1/run.sh" ]]; then
    exec "$DIR/$role/$1/run.sh"
  fi
done

echo "unknown demo: $1" >&2
list >&2
exit 1

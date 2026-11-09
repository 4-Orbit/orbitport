#!/bin/sh
set +x
set -eu

pat_file="${ORBITPORT_PAT_FILE:-${HOME}/.config/spacecomputer-kms/prod.pat}"
binary="${KMS_MCP_BIN:-${HOME}/.local/bin/kms-mcp}"

if [ ! -f "$pat_file" ] || [ ! -r "$pat_file" ]; then
    printf '%s\n' 'PAT file is missing or unreadable; check ORBITPORT_PAT_FILE.' >&2
    exit 1
fi

# Read data, never source the credential file as shell code.
ORBITPORT_PAT="$(cat < "$pat_file" 2>/dev/null)" || {
    printf '%s\n' 'Unable to read the PAT file.' >&2
    exit 1
}
if [ -z "$ORBITPORT_PAT" ]; then
    printf '%s\n' 'PAT file is empty.' >&2
    exit 1
fi

export ORBITPORT_PAT
exec "$binary" "$@"

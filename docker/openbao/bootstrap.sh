#!/bin/sh

set -eu

OPENBAO_ADDR="${OPENBAO_ADDR:-http://openbao:8200}"
OPENBAO_TOKEN="${OPENBAO_TOKEN:-root}"
OPENBAO_PLUGIN_DIR="${OPENBAO_PLUGIN_DIR:-/openbao/plugins}"
OPENBAO_ETH_PLUGIN_NAME="${OPENBAO_ETH_PLUGIN_NAME:-ethereum-secrets-plugin}"
OPENBAO_ETH_MOUNT="${OPENBAO_ETH_MOUNT:-ethereum}"
OPENBAO_PQC_PLUGIN_NAME="${OPENBAO_PQC_PLUGIN_NAME:-openbao-pqc-plugin}"
OPENBAO_PQC_MOUNT="${OPENBAO_PQC_MOUNT:-pqc}"
OPENBAO_THRESHOLD_PLUGIN_NAME="${OPENBAO_THRESHOLD_PLUGIN_NAME:-openbao-threshold-plugin}"
OPENBAO_THRESHOLD_MOUNTS="${OPENBAO_THRESHOLD_MOUNTS:-threshold}"
OPENBAO_TRANSIT_MOUNT="${OPENBAO_TRANSIT_MOUNT:-transit}"
OPENBAO_KV_MOUNT="${OPENBAO_KV_MOUNT:-orbitport-kv}"
OPENBAO_KEY_STORE_MOUNT="${OPENBAO_KEY_STORE_MOUNT:-key-store}"
# 4Orbit policy plugin: versioned per-tenant Cedar policy sets.
OPENBAO_POLICY_MOUNT="${OPENBAO_POLICY_MOUNT:-orbitport-policy}"

export BAO_ADDR="${OPENBAO_ADDR}"
export BAO_TOKEN="${OPENBAO_TOKEN}"

eth_plugin_path="${OPENBAO_PLUGIN_DIR}/${OPENBAO_ETH_PLUGIN_NAME}"
pqc_plugin_path="${OPENBAO_PLUGIN_DIR}/${OPENBAO_PQC_PLUGIN_NAME}"
threshold_plugin_path="${OPENBAO_PLUGIN_DIR}/${OPENBAO_THRESHOLD_PLUGIN_NAME}"

echo "waiting for OpenBao at ${BAO_ADDR}"
until bao status >/dev/null 2>&1; do
    sleep 1
done

enable_mount_if_missing() {
    mount_path="$1"
    mount_type="$2"

    if ! bao secrets list | grep -q "^${mount_path}/"; then
        bao secrets enable -path="${mount_path}" "${mount_type}"
    fi
}

enable_mount_if_missing "${OPENBAO_TRANSIT_MOUNT}" transit
enable_mount_if_missing "${OPENBAO_KV_MOUNT}" kv-v2
enable_mount_if_missing "${OPENBAO_KEY_STORE_MOUNT}" kv-v2
enable_mount_if_missing "${OPENBAO_POLICY_MOUNT}" kv-v2

# PAT signing key (patissuer plugin transit mode). Idempotent: read-or-create.
OPENBAO_PAT_KEY="${OPENBAO_PAT_KEY:-pat-signing}"
if ! bao read "${OPENBAO_TRANSIT_MOUNT}/keys/${OPENBAO_PAT_KEY}" >/dev/null 2>&1; then
    bao write -f "${OPENBAO_TRANSIT_MOUNT}/keys/${OPENBAO_PAT_KEY}" type=ecdsa-p256
    echo "created transit key ${OPENBAO_PAT_KEY} (ecdsa-p256)"
fi

if [ -f "${eth_plugin_path}" ]; then
    plugin_sha="$(sha256sum "${eth_plugin_path}" | cut -d' ' -f1)"
    bao plugin register -sha256="${plugin_sha}" secret "${OPENBAO_ETH_PLUGIN_NAME}"
    enable_mount_if_missing "${OPENBAO_ETH_MOUNT}" "${OPENBAO_ETH_PLUGIN_NAME}"
else
    echo "ethereum plugin binary not found at ${eth_plugin_path}; skipping ethereum mount"
fi

if [ -f "${pqc_plugin_path}" ]; then
    plugin_sha="$(sha256sum "${pqc_plugin_path}" | cut -d' ' -f1)"
    bao plugin register -sha256="${plugin_sha}" secret "${OPENBAO_PQC_PLUGIN_NAME}"
    enable_mount_if_missing "${OPENBAO_PQC_MOUNT}" "${OPENBAO_PQC_PLUGIN_NAME}"
else
    echo "PQC plugin binary not found at ${pqc_plugin_path}; skipping PQC mount"
fi

if [ -f "${threshold_plugin_path}" ]; then
    plugin_sha="$(sha256sum "${threshold_plugin_path}" | cut -d' ' -f1)"
    bao plugin register -sha256="${plugin_sha}" secret "${OPENBAO_THRESHOLD_PLUGIN_NAME}"
    for mount in ${OPENBAO_THRESHOLD_MOUNTS}; do
        enable_mount_if_missing "${mount}" "${OPENBAO_THRESHOLD_PLUGIN_NAME}"
    done
else
    echo "threshold plugin binary not found at ${threshold_plugin_path}; skipping threshold mounts"
fi

echo "OpenBao bootstrap complete"

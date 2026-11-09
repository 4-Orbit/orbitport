# KMS MCP

This Rust executable runs a local MCP server: your agent starts it over
stdio, and each tool call becomes one HTTPS request to the Orbitport
gateway `POST /api/v1/rpc`. KMS and secret storage remain remote. The
gateway owns authentication, tenant resolution, pricing and credit holds.
There is no hosted MCP endpoint.

## Install

Build from the repository root (Rust, a C build toolchain/CMake for TLS, and
`protoc` are required):

```sh
cargo build --locked --release -p kms-mcp
./target/release/kms-mcp --help
```

The release workflow publishes archives for macOS arm64/x64, Linux arm64/x64
and Windows x64 under `mcp-v*` tags. The release tag must match the version in
`mcp/Cargo.toml`. macOS and Linux archives (`kms-mcp-<target>.tar.gz`) contain
the executable and a POSIX file-based PAT launcher, `kms-mcp-from-file.sh`.
The Windows archive (`kms-mcp-x86_64-pc-windows-msvc.zip`) contains only
`kms-mcp.exe`.
Download your platform archive and `SHA256SUMS` from the same GitHub Release.
On Linux, verify with `sha256sum --check --ignore-missing SHA256SUMS`; on macOS,
compare `shasum -a 256 <archive>` with its entry. Verify provenance with:

```sh
gh attestation verify <archive> --repo spacecomputer-io/orbitport
```

Extract the executable to a user-owned location and configure its absolute
path in your harness. The macOS binaries are not signed or notarized. If the
archive was downloaded with a browser, macOS may block the executable; after
verifying it, clear the flag with `xattr -d com.apple.quarantine kms-mcp`.
Downloads with `gh release download` or `curl` are not flagged. Releases are built by CI; the executable is not an
OpenBao server or a replacement for the gateway.

## Configure

Follow [Client Setup](CLIENT_SETUP.md) for file-backed PAT storage and exact
configuration files/commands for Claude Desktop, Codex desktop, Claude Code
CLI and Codex CLI. It also covers manual terminal initialization,
`notifications/initialized`, `tools/list` and a live tool call.

The executable advertises the MCP server name `spacecomputer-kms`. The
optional file-based launcher loads `ORBITPORT_PAT` before starting `kms-mcp`;
the binary itself still reads credentials only from that environment variable.

The URL defaults to production, `https://op.spacecomputer.io`. HTTP is accepted
only for localhost/loopback development. The URL must be a base URL, not a
path ending in `/api/v1/rpc` or `/mcp`. Redirects are never followed.

Use the file-based launcher or your harness's secure environment-variable
mechanism rather than pasting a PAT into prompts or checked-in configuration.
A PAT cannot be provided as a CLI argument. Give agents separate named PATs
where the dashboard permits it, use a short practical lifetime, and revoke them in the
dashboard when access is no longer needed.

## Tools

Tool arguments retain the existing PascalCase JSON-RPC shapes. Call
`tools/list` for generated input/output schemas and `kms_get_capabilities`
for active algorithms. The latter is a gateway tool call, not a free local
protocol query. Current ML-KEM operations remain disabled.

| Tool | JSON-RPC method | Opt-in |
| --- | --- | --- |
| `kms_get_capabilities` | `kms.GetCapabilities` | default |
| `kms_create_key` | `kms.CreateKey` | default |
| `kms_get_key_metadata` | `kms.GetKeyMetadata` | default |
| `kms_get_public_key` | `kms.GetPublicKey` | default |
| `kms_encrypt` | `kms.Encrypt` | default |
| `kms_sign` | `kms.Sign` | default |
| `kms_rotate_key` | `kms.RotateKey` | default |
| `kms_keystore_put` | `kms_keystore.Put` | default |
| `kms_keystore_list` | `kms_keystore.List` | default |
| `kms_decrypt` | `kms.Decrypt` | `decrypt` |
| `kms_generate_data_key` | `kms.GenerateDataKey` | `generate-data-key` |
| `kms_encapsulate` | `kms.Encapsulate` | `encapsulate` (currently disabled) |
| `kms_decapsulate` | `kms.Decapsulate` | `decapsulate` (currently disabled) |
| `kms_keystore_get` | `kms_keystore.Get` | `keystore-get` |
| `kms_keystore_delete` | `kms_keystore.Delete` | `keystore-delete` |

Hidden tools are neither listed nor executable, even if an agent guesses
their names. The allowlist is fixed at startup and cannot be changed through
tool arguments. This protects against prompt injection; it is not a PAT scope.
Someone holding the PAT can still call the gateway directly.

Read-only lookups carry MCP annotations. Put and Delete are marked destructive:
Put overwrites the latest entry; Delete removes all versions. Annotations
are hints, and confirmation behavior depends on the harness.

Key-store secrets must be JSON objects and remain opaque JSON end to end,
preserving large integers and long decimals. Identity fields such as
`ClientId` and `kms_tenant` are refused; tenancy comes from the gateway.

## Protocol And Errors

The server handles legacy initialization (`2025-03-26`, `2025-06-18`,
`2025-11-25`) and modern `2026-07-28` discovery/per-request metadata.
Initialize, discovery, ping, listing and notifications are answered locally
without credits or gateway calls. Notifications produce no response.
Each successful tool invocation uses the same operation tag and price as a
manual call. The process keeps no persistent state or token cache.

Only JSON protocol messages are written to stdout. Diagnostics go to stderr;
raw arguments, responses and credentials are never logged. Input messages,
including the newline, are limited to 65 KiB: the default 64 KiB gateway
body limit plus 1 KiB for MCP framing and metadata. Oversized lines are
discarded through the next newline, reported as a protocol error, and do not
close the session. The gateway's own body limit still applies to forwarded
requests. Gateway responses are limited to 2 MiB.
The HTTP deadline is 30 seconds with a five-second connect timeout.
EOF exits after the active request finishes or times out; Ctrl-C interrupts.

| Failure | Action |
| --- | --- |
| Expired, invalid or revoked PAT | Create a new PAT in the dashboard |
| Insufficient credits | Top up the account |
| Account inactive | Contact your account administrator |
| Rate limit | Try again shortly |
| Backend outage | Try again later |
| Gateway body too large (HTTP 413) | Reduce the request payload to fit the gateway limit |
| Invalid parameters | Correct the parameters using the validation reason, when available |
| KMS resource not found | Check the key ID or key-store entry name |
| KMS permission denied | Check your access to the operation |
| KMS failed precondition | Check whether the resource is in the required state |
| KMS invalid arguments | Correct the operation arguments |
| KMS operation error | Check the resource, permissions and arguments |
| Gateway or local timeout/interrupted response | Check whether the operation completed before retrying |

Requests are never automatically retried, including writes. A gateway timeout
does not establish whether the operation completed. The MCP displays safe,
bounded gateway validation messages and uses fixed messages for known execution
failure reasons, without forwarding raw backend details. Older gateways that
omit a failure reason still get the generic error. Successful tool results
include text and raw structured content; KMS failures use `isError: true`.

Invalid arguments to an available tool also return `isError: true`, with a
field name or path where possible and without echoing submitted values. The
agent can correct the arguments and try again; the rejected call makes no
gateway request. Unknown or hidden tools and malformed MCP requests remain
JSON-RPC protocol errors.

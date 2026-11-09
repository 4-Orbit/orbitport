# KMS MCP Client Setup

This guide configures the local `kms-mcp` executable for Claude Desktop,
Codex desktop, Claude Code CLI and Codex CLI. The examples target macOS.
the launcher also works on Linux with the corresponding home/config paths.
It requires a POSIX shell and is not a native Windows launcher.

The advertised MCP server name is `spacecomputer-kms`. The executable name
is `kms-mcp`. It connects to the existing Orbitport gateway, it does not run
KMS or OpenBao locally and does not use a hosted `/mcp` URL.

## Build And Install

From your Orbitport checkout:

```sh
cargo build --locked --release -p kms-mcp
mkdir -p "$HOME/.local/bin"
install -d -m 700 "$HOME/.config/spacecomputer-kms"
install -m 755 target/release/kms-mcp "$HOME/.local/bin/kms-mcp"
install -m 700 mcp/scripts/kms-mcp-from-file.sh "$HOME/.config/spacecomputer-kms/run-mcp.sh"
```

macOS and Linux release archives contain `kms-mcp` and
`kms-mcp-from-file.sh`; the Windows zip contains only `kms-mcp.exe`.
As an alternative to building, after verifying and
extracting a macOS/Linux archive, run these commands in its extracted directory:

```sh
mkdir -p "$HOME/.local/bin"
install -d -m 700 "$HOME/.config/spacecomputer-kms"
install -m 755 ./kms-mcp "$HOME/.local/bin/kms-mcp"
install -m 700 ./kms-mcp-from-file.sh "$HOME/.config/spacecomputer-kms/run-mcp.sh"
```

Neither installation method requires `sudo`.

## Store The PAT In A File

Create a PAT in the Orbitport dashboard. Create the file without putting
the token in shell history:

```sh
umask 077
touch "$HOME/.config/spacecomputer-kms/prod.pat"
chmod 600 "$HOME/.config/spacecomputer-kms/prod.pat"
nano "$HOME/.config/spacecomputer-kms/prod.pat"
```

The file must contain only the complete PAT on one line, with no quotes,
`Bearer` prefix or `ORBITPORT_PAT=` assignment. A final newline is fine.
Do not put this file in the repository, a cloud-synced directory or a prompt.

The file is plaintext. Directory mode `700` and file mode `600` restrict it
to your user account, but cannot protect it from other processes running as
you. Use a dedicated, revocable PAT with a short practical lifetime. Use
each PAT only with the gateway it was issued for.

The launcher reads the file as data, exports `ORBITPORT_PAT` and replaces
itself with the executable. It does not print the token or evaluate the file
as shell code. Its settings are:

| Setting | Purpose | Value in these examples |
| --- | --- | --- |
| `ORBITPORT_PAT_FILE` | File read by the launcher | `$HOME/.config/spacecomputer-kms/prod.pat` |
| `KMS_MCP_BIN` | Executable launched by the script | `$HOME/.local/bin/kms-mcp` |
| `ORBITPORT_URL` | Gateway base URL read by the executable | `https://op.spacecomputer.io` |

`ORBITPORT_PAT_FILE` and `KMS_MCP_BIN` are launcher settings, not native Rust
CLI options. The binary still reads its credential only from `ORBITPORT_PAT`.
The examples explicitly set both the production PAT file and gateway URL.

## Configuration Files

| Client | User configuration | Optional project configuration |
| --- | --- | --- |
| Claude Desktop on macOS | `~/Library/Application Support/Claude/claude_desktop_config.json` | Not used in this guide |
| Codex desktop | `~/.codex/config.toml` | `.codex/config.toml` in a trusted project |
| Claude Code CLI | `~/.claude.json`, managed by `claude mcp add --scope user` | `.mcp.json` with `--scope project` |
| Codex CLI | `~/.codex/config.toml`, shared with Codex desktop | `.codex/config.toml` in a trusted project |

Use user-level configuration for personal PAT connections. Preserve unrelated
configuration entries. Replace `/Users/YOU` in the examples with your actual
absolute home path, JSON and TOML commands do not automatically expand `~`.
For a custom `CODEX_HOME`, the user config is `$CODEX_HOME/config.toml`.

The setup examples expose the nine default tools without any opt-ins. See
[Optional Tool Opt-Ins](#optional-tool-opt-ins) if your harness needs a
tool outside the default set.

## Claude Desktop

Open Claude Desktop's developer settings and choose **Edit Config**, or edit
`~/Library/Application Support/Claude/claude_desktop_config.json`. Merge this
entry into its existing `mcpServers` object:

```json
{
  "mcpServers": {
    "spacecomputer-kms": {
      "command": "/bin/sh",
      "args": ["/Users/YOU/.config/spacecomputer-kms/run-mcp.sh"],
      "env": {
        "ORBITPORT_PAT_FILE": "/Users/YOU/.config/spacecomputer-kms/prod.pat",
        "KMS_MCP_BIN": "/Users/YOU/.local/bin/kms-mcp",
        "ORBITPORT_URL": "https://op.spacecomputer.io"
      }
    }
  }
}
```

Fully quit Claude Desktop and reopen it. The app starts the launcher and
performs MCP initialization and discovery automatically. A terminal export
is not required. This is a local stdio server, not a remote connector URL.
See the [official local-server setup](https://modelcontextprotocol.io/docs/develop/connect-local-servers).

## Codex Desktop

Add this table to `~/.codex/config.toml`. If your app exposes an MCP settings
panel, it can also create a STDIO entry with the same command, arguments and
environment settings:

```toml
[mcp_servers.spacecomputer-kms]
command = "/bin/sh"
args = ["/Users/YOU/.config/spacecomputer-kms/run-mcp.sh"]

[mcp_servers.spacecomputer-kms.env]
ORBITPORT_PAT_FILE = "/Users/YOU/.config/spacecomputer-kms/prod.pat"
KMS_MCP_BIN = "/Users/YOU/.local/bin/kms-mcp"
ORBITPORT_URL = "https://op.spacecomputer.io"
```

Restart the desktop app or its MCP connection. No `env_vars` forwarding of a
terminal PAT is needed: the launcher reads the file each time it starts.
The desktop client and CLI share this configuration, do not add a duplicate
server under another name. See the [official OpenAI MCP configuration](https://learn.chatgpt.com/docs/extend/mcp).

## Claude Code CLI

Register a user-scoped stdio server. The CLI writes the connection to
`~/.claude.json`, it is not stored in `.claude/settings.json`:

```sh
claude mcp add --transport stdio --scope user \
  --env ORBITPORT_URL=https://op.spacecomputer.io \
  --env "ORBITPORT_PAT_FILE=$HOME/.config/spacecomputer-kms/prod.pat" \
  --env "KMS_MCP_BIN=$HOME/.local/bin/kms-mcp" \
  spacecomputer-kms -- /bin/sh "$HOME/.config/spacecomputer-kms/run-mcp.sh"

claude mcp get spacecomputer-kms
claude
```

Inside Claude Code, use `/mcp` to check the connection. A new session loads
the registration and performs initialization/discovery automatically. If a
server with that name already exists, update or remove that entry rather
than creating duplicates.

If the team intentionally wants project configuration, use `--scope project`
instead: the CLI writes `.mcp.json` in the project root. Keep only paths and
non-secret settings there, never the PAT. See the [official Claude Code MCP
configuration and scope reference](https://code.claude.com/docs/en/mcp).

## Codex CLI

If you configured Codex desktop above, it is already registered. Start
`codex` and inspect `/mcp`, no second registration is needed.

Alternatively, register it from the terminal instead of editing TOML:

```sh
codex mcp add spacecomputer-kms \
  --env ORBITPORT_URL=https://op.spacecomputer.io \
  --env "ORBITPORT_PAT_FILE=$HOME/.config/spacecomputer-kms/prod.pat" \
  --env "KMS_MCP_BIN=$HOME/.local/bin/kms-mcp" \
  -- /bin/sh "$HOME/.config/spacecomputer-kms/run-mcp.sh"

codex mcp list
codex
```

This writes the user-level `~/.codex/config.toml` entry and also applies to
Codex desktop. The environment contains file paths and a gateway URL, not
the PAT. See the [official OpenAI MCP CLI instructions](https://learn.chatgpt.com/docs/extend/mcp).

## Verify A Harness Connection

All four clients launch the local process themselves, do not also start a
terminal instance for them. Initialization and `tools/list` are handled by
the client. First confirm that discovery shows the nine default tools.

A non-mutating live check is:

> Use spacecomputer-kms's kms_get_capabilities tool and summarize the supported algorithms. Do not create or modify anything.

That is an actual KMS tool call, so it requires a valid PAT, an active account
and credits. It uses the same billing path as manual JSON-RPC. Tool discovery
alone is local and does not verify the PAT or contact the gateway.

## Run Manually In A Terminal

Start one local instance with the same file-backed launcher:

```sh
ORBITPORT_URL=https://op.spacecomputer.io \
ORBITPORT_PAT_FILE="$HOME/.config/spacecomputer-kms/prod.pat" \
KMS_MCP_BIN="$HOME/.local/bin/kms-mcp" \
/bin/sh "$HOME/.config/spacecomputer-kms/run-mcp.sh"
```

It waits silently for newline-delimited JSON on stdin, it does not open an
HTTP port. Enter each request below on one line in that same terminal and
wait for each response before continuing. You are acting as the harness.

### Initialize

```json
{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"terminal-test","version":"1.0"}}}
```

The response agrees a protocol version and includes
`serverInfo.name: "spacecomputer-kms"` and the server's tool capability.
Then signal that initialization is complete:

```json
{"jsonrpc":"2.0","method":"notifications/initialized"}
```

No response to this notification is expected. These are protocol steps, not
user authentication. See the [MCP initialization lifecycle](https://modelcontextprotocol.io/specification/2025-11-25/basic/lifecycle).

### List Tools

```json
{"jsonrpc":"2.0","id":2,"method":"tools/list"}
```

The response contains the nine default tools, descriptions, input/output schemas and
annotations. Hidden tools remain uncallable even if their names are guessed.
Initialization and listing make no gateway requests and consume no credits.

### Make A Live Tool Call

```json
{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"kms_get_capabilities","arguments":{}}}
```

This call reaches the production gateway, which checks the PAT, account and credits.
It does not create or modify keys, but follows normal KMS billing. A tool
failure appears as `isError: true`. Use Ctrl-C to stop the process and return
to your shell. Do not paste response JSON back as request arguments.

## Optional Tool Opt-Ins

Enable only the tools your harness needs. To expose key-store Get, append
`--allow keystore-get` after the launcher script path. In a harness `args`
array, add the flag and its value as separate entries, for example:

```toml
args = ["/Users/YOU/.config/spacecomputer-kms/run-mcp.sh", "--allow", "keystore-get"]
```

Use a comma-separated value to enable more than one option. Restart the MCP
connection or harness after changing the arguments.

| Opt-in | What it exposes |
| --- | --- |
| `decrypt` | Decrypts ciphertext and returns plaintext. |
| `generate-data-key` | Returns both a plaintext data key and its encrypted copy. |
| `keystore-get` | Returns the stored JSON secret to the harness. |
| `keystore-delete` | Permanently deletes a key-store entry and all its versions. |
| `encapsulate` | Exposes the key-agreement tool; execution is currently disabled. |
| `decapsulate` | Exposes the shared-key recovery tool; execution is currently disabled. |

These are **local tool exposure controls, not PAT scopes**. A holder of the
PAT can still call the gateway directly. The default tool set is restricted,
not read-only: it includes operations that can create keys or write entries.
Opting in to a tool that returns secrets can expose them to the harness.

## Credential And Configuration Changes

After replacing a PAT file, restart the MCP connection or its harness. A
running process retains the PAT loaded at startup, it does not reread the
file for each call. Revocation is still enforced by the gateway/account
backend on subsequent operations.

Reinstall the binary after rebuilding it if you use the installed path
above. Update old harness commands to point at `kms-mcp` or the launcher.
The launcher defaults to a user-installed binary, not your checkout's
`target/release` directory. Do not log the PAT, enable shell tracing while
loading it, or add banners to stdout: stdout is reserved for MCP messages.

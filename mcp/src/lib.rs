//! Local stdio adapter. The gateway remains the authentication and KMS boundary.
pub mod client;
pub mod types;

use kms_mcp_core::{Dispatch, ToolPolicy, dispatch, protocol_error};
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncWrite, AsyncWriteExt};

// Leave 1 KiB for MCP framing and metadata above the default gateway body limit.
pub const MAX_MESSAGE_BYTES: usize = 64 * 1024 + 1024;

enum InputMessage {
    Line(Vec<u8>),
    Oversized,
}

// Read with fill_buf rather than read_line so an untrusted oversized line
// cannot grow an unbounded allocation before its length is checked.
async fn read_message<R: AsyncBufRead + Unpin>(
    input: &mut R,
) -> std::io::Result<Option<InputMessage>> {
    let mut line = Some(Vec::new());
    loop {
        let buf = input.fill_buf().await?;
        if buf.is_empty() {
            break;
        }
        let count = buf
            .iter()
            .position(|b| *b == b'\n')
            .map_or(buf.len(), |n| n + 1);
        let ended = buf[count - 1] == b'\n';
        if let Some(bytes) = &mut line {
            if count > MAX_MESSAGE_BYTES - bytes.len() {
                // Drop the prefix and consume without buffering until the newline.
                line = None;
            } else {
                bytes.extend_from_slice(&buf[..count]);
            }
        }
        input.consume(count);
        if ended {
            break;
        }
    }
    Ok(match line {
        Some(line) if line.is_empty() => None,
        Some(line) => Some(InputMessage::Line(line)),
        None => Some(InputMessage::Oversized),
    })
}

pub async fn serve<R, W>(
    mut input: R,
    mut output: W,
    client: client::GatewayClient,
    policy: ToolPolicy,
) -> std::io::Result<()>
where
    R: AsyncBufRead + Unpin,
    W: AsyncWrite + Unpin,
{
    while let Some(message) = read_message(&mut input).await? {
        let response = match message {
            InputMessage::Oversized => {
                protocol_error(None, -32000, "MCP message exceeds size limit")
            }
            InputMessage::Line(line) => {
                if line.iter().all(u8::is_ascii_whitespace) {
                    continue;
                }
                match std::str::from_utf8(&line) {
                    Err(_) => protocol_error(None, -32700, "Parse error"),
                    Ok(line) => match dispatch(line, &policy) {
                        Dispatch::Reply(reply) => reply,
                        Dispatch::Notification => continue,
                        Dispatch::Call(pending) => match client.execute(&pending.call).await {
                            Ok(result) => pending.success(result),
                            Err(error) => pending.failure(error.to_string()),
                        },
                    },
                }
            }
        };
        output.write_all(response.as_bytes()).await?;
        output.write_all(b"\n").await?;
        output.flush().await?;
    }
    Ok(())
}

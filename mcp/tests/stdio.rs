use kms_mcp::{MAX_MESSAGE_BYTES, client::GatewayClient, types::McpError};
use kms_mcp_core::ToolPolicy;
use serde_json::{Value, json};
use std::{
    io::{BufRead, BufReader, Read, Write},
    net::{TcpListener, TcpStream},
    process::{Command, Stdio},
    sync::{Arc, Mutex},
    thread,
    time::{Duration, Instant},
};

struct Fixture {
    url: String,
    requests: Arc<Mutex<Vec<String>>>,
    worker: Option<thread::JoinHandle<()>>,
}

impl Fixture {
    fn new(status: u16, body: &str) -> Self {
        Self::delayed(status, body, Duration::ZERO)
    }

    fn delayed(status: u16, body: &str, delay: Duration) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let requests = Arc::new(Mutex::new(Vec::new()));
        let captured = requests.clone();
        let body = body.to_string();
        let worker = thread::spawn(move || {
            let until = Instant::now() + Duration::from_secs(3);
            while Instant::now() < until {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        let request = read_request(&stream);
                        let request_body = request.split("\r\n\r\n").nth(1).unwrap();
                        let id =
                            serde_json::from_str::<Value>(request_body).unwrap()["id"].to_string();
                        captured.lock().unwrap().push(request);
                        thread::sleep(delay);
                        let body = body.replace("__ID__", &id);
                        let reply = format!(
                            "HTTP/1.1 {status} Test\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\nLocation: http://127.0.0.1:1/stolen\r\n\r\n{body}",
                            body.len()
                        );
                        let _ = stream.write_all(reply.as_bytes());
                        return;
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5))
                    }
                    Err(e) => panic!("{e}"),
                }
            }
        });
        Self {
            url,
            requests,
            worker: Some(worker),
        }
    }

    fn finish(mut self) -> Vec<String> {
        self.worker.take().unwrap().join().unwrap();
        Arc::try_unwrap(self.requests)
            .unwrap()
            .into_inner()
            .unwrap()
    }
}

fn read_request(stream: &TcpStream) -> String {
    stream.set_nonblocking(false).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let mut reader = BufReader::new(stream);
    let mut headers = String::new();
    let mut length = 0;
    loop {
        let mut line = String::new();
        reader.read_line(&mut line).unwrap();
        if line.to_ascii_lowercase().starts_with("content-length:") {
            length = line.split(':').nth(1).unwrap().trim().parse().unwrap();
        }
        headers.push_str(&line);
        if line == "\r\n" {
            break;
        }
    }
    let mut body = vec![0; length];
    reader.read_exact(&mut body).unwrap();
    headers + &String::from_utf8(body).unwrap()
}

fn subprocess(input: &str, url: &str, allow: &str) -> std::process::Output {
    let mut process = Command::new(env!("CARGO_BIN_EXE_kms-mcp"))
        .env("ORBITPORT_PAT", "fixture-token")
        .env("ORBITPORT_URL", url)
        .args(["--allow", allow])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    process
        .stdin
        .take()
        .unwrap()
        .write_all(input.as_bytes())
        .unwrap();
    process.wait_with_output().unwrap()
}

#[test]
fn executable_help_uses_kms_mcp_name() {
    let output = Command::new(env!("CARGO_BIN_EXE_kms-mcp"))
        .arg("--help")
        .output()
        .unwrap();
    assert!(output.status.success());
    assert!(String::from_utf8_lossy(&output.stdout).contains("Usage: kms-mcp"));
    assert!(output.stderr.is_empty());
}

#[test]
fn stdio_protocol_calls_hidden_calls_and_bad_arguments_make_no_network_requests() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let input = [
        r#"{"jsonrpc":"2.0","id":"init","method":"initialize","params":{"protocolVersion":"2025-06-18"}}"#,
        r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#,
        r#"{"jsonrpc":"2.0","id":2,"method":"tools/list"}"#,
        r#"{"jsonrpc":"2.0","id":3,"method":"ping"}"#,
        r#"{"jsonrpc":"2.0","id":4,"method":"server/discover"}"#,
        r#"{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"kms_keystore_get","arguments":{"Name":"a"}}}"#,
        r#"{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"kms_sign","arguments":{"KeyId":"a","Message":"never-log-me","SigningAlgorithm":"INVALID"}}}"#,
        r#"{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"kms_get_public_key","arguments":{"KeyId":"a","Version":"never-log-me"}}}"#,
        "{",
        r#"{"jsonrpc":"2.0","id":8,"method":"unsupported"}"#,
    ].join("\n") + "\n";
    let output = subprocess(
        &input,
        &format!("http://{}", listener.local_addr().unwrap()),
        "",
    );
    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(!stdout.contains("never-log-me"));
    let replies: Vec<Value> = stdout
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert_eq!(replies.len(), 9);
    assert_eq!(replies[0]["id"], "init");
    assert_eq!(replies[0]["result"]["protocolVersion"], "2025-06-18");
    assert_eq!(replies[1]["result"]["tools"].as_array().unwrap().len(), 9);
    assert_eq!(replies[4]["error"]["code"], -32602);
    assert_eq!(replies[5]["result"]["isError"], true);
    assert_eq!(
        replies[5]["result"]["content"][0]["text"],
        "SigningAlgorithm is not supported",
    );
    assert_eq!(replies[6]["result"]["isError"], true);
    assert_eq!(
        replies[6]["result"]["content"][0]["text"],
        "Invalid value for Version.",
    );
    assert!(listener.accept().is_err());
}

#[test]
fn put_sends_exact_raw_secret_and_pat_once() {
    let fixture = Fixture::new(
        200,
        r#"{"jsonrpc":"2.0","id":__ID__,"result":{"Name":"a","Version":1}}"#,
    );
    let input = r#"{"jsonrpc":"2.0","id":"external-id","method":"tools/call","params":{"name":"kms_keystore_put","arguments":{"Name":"a","Secret":{"max_wei":123456789012345678901234567890,"pi":3.14159265358979323846}}}}"#;
    let output = subprocess(input, &fixture.url, "");
    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    let reply: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(reply["id"], "external-id");
    assert_eq!(reply["result"]["isError"], false);
    let requests = fixture.finish();
    assert_eq!(requests.len(), 1);
    assert!(requests[0].starts_with("POST /api/v1/rpc HTTP/1.1"));
    assert!(
        requests[0]
            .to_ascii_lowercase()
            .contains("authorization: bearer fixture-token")
    );
    assert!(requests[0].contains(r#""method":"kms_keystore.Put""#));
    assert!(requests[0].contains(
        r#""Secret":{"max_wei":123456789012345678901234567890,"pi":3.14159265358979323846}"#
    ));
}

#[test]
fn get_preserves_precision_in_the_actual_stdio_response() {
    let secret = r#"{"Name":"a","Secret":{"max_wei":123456789012345678901234567890,"pi":3.14159265358979323846}}"#;
    let fixture = Fixture::new(
        200,
        &format!(r#"{{"jsonrpc":"2.0","id":__ID__,"result":{secret}}}"#),
    );
    let input = r#"{"jsonrpc":"2.0","id":9007199254740993,"method":"tools/call","params":{"name":"kms_keystore_get","arguments":{"Name":"a"}}}"#;
    let output = subprocess(input, &fixture.url, "keystore-get");
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains(&format!(r#""structuredContent":{secret}"#)));
    assert!(stdout.contains(r#""id":9007199254740993"#));
    assert_eq!(fixture.finish().len(), 1);
}

#[tokio::test]
async fn errors_are_sanitized_and_redirects_and_failures_are_not_retried() {
    let cases = [
        (
            401,
            r#"{"error":"token_expired","detail":"internal-secret"}"#,
            "expired",
            McpError::PatExpired,
        ),
        (
            401,
            r#"{"error":"invalid_credential"}"#,
            "revoked",
            McpError::InvalidCredential,
        ),
        (402, "{}", "credits", McpError::InsufficientCredits),
        (
            403,
            r#"{"error":"account_inactive"}"#,
            "inactive",
            McpError::AccountInactive,
        ),
        (403, "{}", "refused", McpError::PermissionDenied),
        (
            403,
            r#"{"message":"account_inactive"}"#,
            "refused",
            McpError::PermissionDenied,
        ),
        (429, "{}", "rate limit", McpError::RateLimitExceeded),
        (
            503,
            r#"{"detail":"internal-secret"}"#,
            "temporarily",
            McpError::BackendUnavailable,
        ),
        (307, "{}", "redirects", McpError::Redirect),
        (413, "{}", "body size", McpError::RequestTooLarge),
        (
            200,
            r#"{"jsonrpc":"2.0","id":__ID__,"error":{"code":-32001,"message":"internal-secret"}}"#,
            "operation failed",
            McpError::OperationFailed,
        ),
        (
            200,
            r#"{"jsonrpc":"2.0","id":__ID__,"error":{"code":-32602,"message":"internal-secret"}}"#,
            "Invalid KMS parameters",
            McpError::InvalidParameters,
        ),
        (
            200,
            r#"{"jsonrpc":"2.0","id":999999,"result":{}}"#,
            "Invalid gateway",
            McpError::InvalidRpcResponse,
        ),
        (
            200,
            r#"{"jsonrpc":"2.0","id":__ID__,"result":{},"error":{"code":0}}"#,
            "Invalid gateway",
            McpError::InvalidRpcResponse,
        ),
    ];
    for (status, body, expected_message, expected_error) in cases {
        let fixture = Fixture::new(status, body);
        let client = GatewayClient::new(&fixture.url, "fixture-token").unwrap();
        let call = ToolPolicy::default()
            .prepare("kms_get_capabilities", serde_json::from_str("{}").unwrap())
            .unwrap();
        let error = client.execute(&call).await.unwrap_err();
        assert_eq!(error, expected_error);
        let message = error.to_string();
        assert!(message.contains(expected_message), "{message}");
        assert!(!message.contains("internal-secret"));
        assert!(!format!("{error:?}").contains("internal-secret"));
        assert_eq!(fixture.finish().len(), 1);
    }
}

#[tokio::test]
async fn timeout_does_not_retry_and_warns_about_indeterminate_completion() {
    let fixture = Fixture::delayed(
        200,
        r#"{"jsonrpc":"2.0","id":__ID__,"result":{}}"#,
        Duration::from_millis(200),
    );
    let client =
        GatewayClient::with_timeout(&fixture.url, "fixture-token", Duration::from_millis(100))
            .unwrap();
    let call = ToolPolicy::default()
        .prepare("kms_get_capabilities", serde_json::from_str("{}").unwrap())
        .unwrap();
    let error = client.execute(&call).await.unwrap_err();
    assert_eq!(error, McpError::GatewayRequest);
    assert!(error.to_string().contains("may have completed"));
    assert_eq!(fixture.finish().len(), 1);
}

#[test]
fn gateway_rpc_errors_have_safe_actionable_stdio_messages() {
    let verify = |error: Value, expected: &str| {
        let body = format!(r#"{{"jsonrpc":"2.0","id":__ID__,"error":{error}}}"#);
        let fixture = Fixture::new(200, &body);
        let output = subprocess(
            r#"{"jsonrpc":"2.0","id":"rotate","method":"tools/call","params":{"name":"kms_rotate_key","arguments":{"KeyId":"kms:test"}}}"#,
            &fixture.url,
            "",
        );
        assert!(output.status.success());
        assert!(output.stderr.is_empty());
        let stdout = String::from_utf8(output.stdout).unwrap();
        assert!(!stdout.contains("internal-secret"));
        let reply: Value = serde_json::from_str(&stdout).unwrap();
        assert_eq!(reply["id"], "rotate");
        assert_eq!(reply["result"]["isError"], true);
        assert_eq!(reply["result"]["content"][0]["text"], expected);
        assert_eq!(fixture.finish().len(), 1);
    };

    verify(
        json!({"code": -32002, "message": "Request timed out"}),
        &McpError::GatewayRequest.to_string(),
    );
    verify(
        json!({"code": -32602, "message": "Invalid request: KeyId is required"}),
        "Invalid request: KeyId is required",
    );
    for message in [
        Value::Null,
        json!({"detail": "internal-secret"}),
        json!("Invalid request: "),
        json!("Invalid request: Bad input\ninternal-secret"),
        json!(format!("Invalid request: {}", "internal-secret".repeat(40))),
    ] {
        verify(
            json!({"code": -32602, "message": message}),
            "Invalid KMS parameters",
        );
    }

    for (reason, message) in [
        ("not_found", "The requested KMS resource was not found."),
        (
            "permission_denied",
            "The key or resource does not exist or does not belong to you.",
        ),
        (
            "failed_precondition",
            "The resource is not in a state that allows this KMS operation.",
        ),
        ("invalid_argument", "KMS rejected the operation arguments."),
    ] {
        verify(
            json!({
                "code": -32001,
                "message": "Invalid request: internal-secret",
                "data": {"reason": reason},
            }),
            message,
        );
    }
    for data in [
        Value::Null,
        json!("not_found"),
        json!({"reason": 5}),
        json!({"reason": "internal-secret"}),
    ] {
        verify(
            json!({"code": -32001, "message": "internal-secret", "data": data}),
            "KMS operation failed; check the resource, permissions and parameters",
        );
    }
}

#[test]
fn startup_rejects_insecure_urls_tokens_in_arguments_and_unknown_opt_ins() {
    for url in [
        "http://example.com",
        "https://user:password@example.com",
        "https://example.com/mcp",
        "https://example.com?token=bad",
        "file:///tmp/server",
    ] {
        assert!(GatewayClient::new(url, "fixture-token").is_err());
    }
    assert!(GatewayClient::new("http://[::1]:8080", "fixture-token").is_ok());
    assert!(matches!(
        GatewayClient::new("https://op.spacecomputer.io", ""),
        Err(McpError::MissingPat)
    ));
    assert!(matches!(
        GatewayClient::new("https://op.spacecomputer.io", "never-log-me\n"),
        Err(McpError::InvalidPat)
    ));
    let out = subprocess("", "http://127.0.0.1:1", "all");
    assert!(!out.status.success());
    assert!(out.stdout.is_empty());
    let out = Command::new(env!("CARGO_BIN_EXE_kms-mcp"))
        .args(["--pat", "never-log-me"])
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert!(!String::from_utf8_lossy(&out.stderr).contains("never-log-me"));
}

#[test]
fn transit_and_keystore_tools_forward_their_existing_public_contracts() {
    let metadata = json_metadata();
    let cases = [
        (
            "kms_create_key",
            "kms.CreateKey",
            r#"{"Alias":"demo","Description":"","Tags":[],"KeySpec":"ECDSA_P256","KeyUsage":"SIGN_VERIFY"}"#,
            metadata.as_str(),
            "",
        ),
        (
            "kms_get_key_metadata",
            "kms.GetKeyMetadata",
            r#"{"KeyId":"demo"}"#,
            metadata.as_str(),
            "",
        ),
        (
            "kms_get_public_key",
            "kms.GetPublicKey",
            r#"{"KeyId":"demo","Version":1}"#,
            r#"{"PublicKey":"public","Version":1}"#,
            "",
        ),
        (
            "kms_encrypt",
            "kms.Encrypt",
            r#"{"KeyId":"demo","Plaintext":"YQ=="}"#,
            r#"{"CiphertextBlob":"blob","KeyId":"kms:demo","EncryptionAlgorithm":"AES_256_GCM96"}"#,
            "",
        ),
        (
            "kms_decrypt",
            "kms.Decrypt",
            r#"{"CiphertextBlob":"blob"}"#,
            r#"{"Plaintext":"YQ==","KeyId":"kms:demo","EncryptionAlgorithm":"AES_256_GCM96"}"#,
            "decrypt",
        ),
        (
            "kms_sign",
            "kms.Sign",
            r#"{"KeyId":"demo","Message":"YQ==","SigningAlgorithm":"ECDSA_SHA_256"}"#,
            r#"{"KeyId":"kms:demo","Signature":"signed","SigningAlgorithm":"ECDSA_SHA_256","KeyVersion":1}"#,
            "",
        ),
        (
            "kms_generate_data_key",
            "kms.GenerateDataKey",
            r#"{"KeyId":"demo","DataKeySpec":"AES_256"}"#,
            r#"{"KeyId":"kms:demo","Plaintext":"YQ==","CiphertextBlob":"blob"}"#,
            "generate-data-key",
        ),
        (
            "kms_rotate_key",
            "kms.RotateKey",
            r#"{"KeyId":"demo"}"#,
            metadata.as_str(),
            "",
        ),
        (
            "kms_keystore_list",
            "kms_keystore.List",
            r#"{"Prefix":"github"}"#,
            r#"{"Names":["github/prod","github/ci/"]}"#,
            "",
        ),
        (
            "kms_keystore_delete",
            "kms_keystore.Delete",
            r#"{"Name":"github/prod"}"#,
            r#"{"Name":"github/prod"}"#,
            "keystore-delete",
        ),
    ];
    for (tool, method, args, result, allow) in cases {
        let fixture = Fixture::new(
            200,
            &format!(r#"{{"jsonrpc":"2.0","id":__ID__,"result":{result}}}"#),
        );
        let request = format!(
            r#"{{"jsonrpc":"2.0","id":"external-id","method":"tools/call","params":{{"name":"{tool}","arguments":{args}}}}}"#
        );
        let output = subprocess(&request, &fixture.url, allow);
        assert!(output.status.success(), "{tool}");
        assert!(output.stderr.is_empty(), "{tool}");
        let reply: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(reply["result"]["isError"], false, "{tool}");
        assert_eq!(
            reply["result"]["structuredContent"],
            serde_json::from_str::<Value>(result).unwrap(),
            "{tool}"
        );
        let requests = fixture.finish();
        assert_eq!(requests.len(), 1, "{tool}");
        let envelope: Value =
            serde_json::from_str(requests[0].split("\r\n\r\n").nth(1).unwrap()).unwrap();
        assert_eq!(envelope["method"], method);
        assert_eq!(
            envelope["params"],
            serde_json::from_str::<Value>(args).unwrap()
        );
    }
}

fn json_metadata() -> String {
    r#"{"KeyMetadata":{"KeyId":"kms:demo","Description":"","KeySpec":"ECDSA_P256","KeyUsage":"SIGN_VERIFY","Tags":[],"Enabled":true,"PrimaryVersion":1,"CreationDate":"2026-11-02","Scheme":"TRANSIT","Alias":"demo","PublicKey":null,"Address":null}}"#.to_string()
}

#[test]
fn oversized_input_is_discarded_and_the_next_message_is_answered() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let oversized = json!({
        "jsonrpc": "2.0", "id": "oversized", "method": "tools/call",
        "params": {"name": "kms_keystore_put", "arguments": {
            "Name": "oversized", "Secret": {
                "value": format!("discard-this-secret{}", "x".repeat(2 * MAX_MESSAGE_BYTES))
            }
        }}
    });
    let ping = r#"{"jsonrpc":"2.0","id":"next","method":"ping"}"#;
    let padding = " ".repeat(MAX_MESSAGE_BYTES - ping.len() - 1);
    let output = subprocess(
        &format!("{oversized}\n{ping}{padding}\n"),
        &format!("http://{}", listener.local_addr().unwrap()),
        "",
    );
    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(!stdout.contains("discard-this-secret"));
    let replies: Vec<Value> = stdout
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert_eq!(
        replies,
        vec![
            json!({"jsonrpc":"2.0","id":null,"error":{"code":-32000,"message":"MCP message exceeds size limit"}}),
            json!({"jsonrpc":"2.0","id":"next","result":{}}),
        ]
    );
    assert!(matches!(listener.accept(), Err(e) if e.kind() == std::io::ErrorKind::WouldBlock));
}

#[test]
fn oversized_unterminated_input_reports_one_error_at_eof() {
    let output = subprocess(&"x".repeat(MAX_MESSAGE_BYTES + 1), "http://127.0.0.1:1", "");
    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    let reply: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(reply["id"], Value::Null);
    assert_eq!(reply["error"]["code"], -32000);
    assert_eq!(reply["error"]["message"], "MCP message exceeds size limit");
}

#[test]
fn framing_headroom_forwards_near_limit_puts_and_reports_gateway_413() {
    const DEFAULT_GATEWAY_BODY_BYTES: usize = 64 * 1024;
    let mut arguments = json!({"Name":"near-limit","Secret":{"value":""}});
    let empty_body = json!({
        "jsonrpc":"2.0", "id":1, "method":"kms_keystore.Put", "params":arguments
    });
    let body_overhead = empty_body.to_string().len();
    for (body_bytes, status, response_body) in [
        (
            DEFAULT_GATEWAY_BODY_BYTES,
            200,
            r#"{"jsonrpc":"2.0","id":__ID__,"result":{"Name":"near-limit","Version":1}}"#,
        ),
        (
            DEFAULT_GATEWAY_BODY_BYTES + 1,
            413,
            r#"{"error":"payload_too_large"}"#,
        ),
    ] {
        arguments["Secret"]["value"] = json!("x".repeat(body_bytes - body_overhead));
        let request = json!({
            "jsonrpc": "2.0", "id": "near-limit-request", "method": "tools/call",
            "params": {
                "name": "kms_keystore_put", "arguments": arguments,
                "_meta": {
                    "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                    "io.modelcontextprotocol/clientInfo": {"name":"limit-test","version":"1.0"},
                    "io.modelcontextprotocol/clientCapabilities": {"sampling":{}}
                }
            }
        });
        let line = format!("{request}\n");
        assert!(line.len() > DEFAULT_GATEWAY_BODY_BYTES);
        assert!(line.len() <= MAX_MESSAGE_BYTES);
        let fixture = Fixture::new(status, response_body);
        let ping = r#"{"jsonrpc":"2.0","id":"next","method":"ping"}"#;
        let output = subprocess(&format!("{line}{ping}\n"), &fixture.url, "");
        assert!(output.status.success());
        assert!(output.stderr.is_empty());
        let stdout = String::from_utf8(output.stdout).unwrap();
        let replies: Vec<Value> = stdout
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        assert_eq!(replies.len(), 2);
        assert_eq!(replies[0]["id"], "near-limit-request");
        assert_eq!(replies[0]["result"]["isError"], status == 413);
        if status == 413 {
            assert_eq!(
                replies[0]["result"]["content"][0]["text"],
                "The request exceeds the gateway body size limit.",
            );
        }
        assert_eq!(replies[1], json!({"jsonrpc":"2.0","id":"next","result":{}}));
        let requests = fixture.finish();
        assert_eq!(requests.len(), 1);
        let body = requests[0].split("\r\n\r\n").nth(1).unwrap();
        assert_eq!(body.len(), body_bytes);
        let forwarded: Value = serde_json::from_str(body).unwrap();
        assert_eq!(forwarded["params"], arguments);
    }
}

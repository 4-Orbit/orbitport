//! MCP protocol and tools without transport, credentials, or plugin dependencies.
pub mod tools;
pub use tools::{PrepareError, PreparedCall, ToolPolicy};

use serde::{Deserialize, Deserializer, Serialize};
use serde_json::{Value, json, value::RawValue};
use std::collections::HashMap;

pub const SERVER_NAME: &str = "spacecomputer-kms";
pub const MODERN_VERSION: &str = "2026-07-28";
pub const LEGACY_VERSION: &str = "2025-11-25";
pub const SUPPORTED_VERSIONS: &[&str] =
    &[MODERN_VERSION, LEGACY_VERSION, "2025-06-18", "2025-03-26"];

#[derive(Deserialize)]
struct JsonRpcRequest {
    jsonrpc: String,
    #[serde(default, deserialize_with = "present_raw")]
    id: Option<Box<RawValue>>,
    method: String,
    #[serde(default)]
    params: Option<Box<RawValue>>,
}

fn present_raw<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<Box<RawValue>>, D::Error> {
    Box::<RawValue>::deserialize(deserializer).map(Some)
}

#[derive(Deserialize)]
struct ToolCallParams {
    name: String,
    #[serde(default, deserialize_with = "present_raw")]
    arguments: Option<Box<RawValue>>,
}

pub enum Dispatch {
    Reply(String),
    Notification,
    Call(PendingCall),
}

pub struct PendingCall {
    id: Box<RawValue>,
    modern: bool,
    pub call: PreparedCall,
}

impl PendingCall {
    pub fn success(self, result: Box<RawValue>) -> String {
        success_response(
            &self.id,
            ToolResult {
                result_type: self.modern.then_some("complete"),
                content: vec![TextContent {
                    kind: "text",
                    text: result.get().to_string(),
                }],
                structured_content: Some(result),
                is_error: false,
            },
        )
    }

    pub fn failure(self, message: impl Into<String>) -> String {
        tool_failure_response(&self.id, self.modern, message.into())
    }
}

fn tool_failure_response(id: &RawValue, modern: bool, message: String) -> String {
    success_response(
        id,
        ToolResult {
            result_type: modern.then_some("complete"),
            content: vec![TextContent {
                kind: "text",
                text: message,
            }],
            structured_content: None,
            is_error: true,
        },
    )
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ToolResult {
    #[serde(skip_serializing_if = "Option::is_none")]
    result_type: Option<&'static str>,
    content: Vec<TextContent>,
    #[serde(skip_serializing_if = "Option::is_none")]
    structured_content: Option<Box<RawValue>>,
    is_error: bool,
}

#[derive(Serialize)]
struct TextContent {
    #[serde(rename = "type")]
    kind: &'static str,
    text: String,
}

#[derive(Serialize)]
struct JsonRpcSuccessResponse<'a, T> {
    jsonrpc: &'static str,
    id: &'a RawValue,
    result: T,
}

#[derive(Serialize)]
struct JsonRpcErrorResponse<'a> {
    jsonrpc: &'static str,
    id: Option<&'a RawValue>,
    error: JsonRpcError<'a>,
}

#[derive(Serialize)]
struct JsonRpcError<'a> {
    code: i32,
    message: &'a str,
}

fn success_response<T: Serialize>(id: &RawValue, result: T) -> String {
    serde_json::to_string(&JsonRpcSuccessResponse {
        jsonrpc: "2.0",
        id,
        result,
    })
    .expect("MCP response is JSON")
}

pub fn protocol_error(id: Option<&RawValue>, code: i32, message: &str) -> String {
    serde_json::to_string(&JsonRpcErrorResponse {
        jsonrpc: "2.0",
        id,
        error: JsonRpcError { code, message },
    })
    .expect("MCP error is JSON")
}

fn valid_id(id: &RawValue) -> bool {
    let raw = id.get();
    raw.starts_with('"') || {
        let number = raw.strip_prefix('-').unwrap_or(raw);
        !number.is_empty() && number.bytes().all(|c| c.is_ascii_digit())
    }
}

fn initialize_response(id: &RawValue, fields: &HashMap<String, Box<RawValue>>) -> String {
    let version = match fields.get("protocolVersion") {
        Some(raw) => match serde_json::from_str::<String>(raw.get()) {
            Ok(version)
                if SUPPORTED_VERSIONS.contains(&version.as_str()) && version != MODERN_VERSION =>
            {
                version
            }
            Ok(_) => LEGACY_VERSION.to_string(),
            Err(_) => return protocol_error(Some(id), -32602, "Invalid protocolVersion"),
        },
        None => LEGACY_VERSION.to_string(),
    };
    success_response(
        id,
        json!({
            "protocolVersion": version,
            "capabilities": {"tools": {}},
            "serverInfo": {"name": SERVER_NAME, "version": env!("CARGO_PKG_VERSION")}
        }),
    )
}

fn prepare_tool_call(
    id: Box<RawValue>,
    modern: bool,
    params: &str,
    policy: &ToolPolicy,
) -> Dispatch {
    let params: ToolCallParams = match serde_json::from_str(params) {
        Ok(params) => params,
        Err(_) => {
            return Dispatch::Reply(protocol_error(
                Some(&id),
                -32602,
                "Invalid tools/call params",
            ));
        }
    };
    let arguments = params
        .arguments
        .unwrap_or_else(|| serde_json::from_str("{}").expect("empty arguments are valid JSON"));
    if !arguments.get().trim_start().starts_with('{') {
        return Dispatch::Reply(protocol_error(
            Some(&id),
            -32602,
            "tools/call arguments must be a JSON object",
        ));
    }
    match policy.prepare(&params.name, arguments) {
        Ok(call) => Dispatch::Call(PendingCall { id, modern, call }),
        Err(PrepareError::UnknownOrDisabledTool) => {
            Dispatch::Reply(protocol_error(Some(&id), -32602, "Unknown tool"))
        }
        Err(PrepareError::InvalidArguments(message)) => {
            Dispatch::Reply(tool_failure_response(&id, modern, message))
        }
    }
}

pub fn dispatch(line: &str, policy: &ToolPolicy) -> Dispatch {
    let request: JsonRpcRequest = match serde_json::from_str(line) {
        Ok(request) => request,
        Err(_) => {
            let valid_json = RawValue::from_string(line.to_string()).is_ok();
            return Dispatch::Reply(protocol_error(
                None,
                if valid_json { -32600 } else { -32700 },
                if valid_json {
                    "Invalid JSON-RPC request"
                } else {
                    "Parse error"
                },
            ));
        }
    };
    if request.jsonrpc != "2.0" || request.id.as_deref().is_some_and(|id| !valid_id(id)) {
        return Dispatch::Reply(protocol_error(None, -32600, "Invalid JSON-RPC request"));
    }
    let Some(id) = request.id else {
        // Notifications never execute a KMS operation and never produce stdout.
        return Dispatch::Notification;
    };
    let params = request.params.as_deref().map(RawValue::get).unwrap_or("{}");
    // Inspect only metadata, leaving secret-bearing arguments opaque.
    let fields: HashMap<String, Box<RawValue>> = match serde_json::from_str(params) {
        Ok(fields) => fields,
        Err(_) => {
            return Dispatch::Reply(protocol_error(
                Some(&id),
                -32602,
                "Params must be an object",
            ));
        }
    };
    let protocol_version = fields
        .get("_meta")
        .and_then(|raw| serde_json::from_str::<Value>(raw.get()).ok())
        .and_then(|v| {
            v.get("io.modelcontextprotocol/protocolVersion")
                .and_then(Value::as_str)
                .map(str::to_owned)
        });
    if protocol_version
        .as_deref()
        .is_some_and(|v| !SUPPORTED_VERSIONS.contains(&v))
    {
        return Dispatch::Reply(protocol_error(
            Some(&id),
            -32600,
            "Unsupported MCP protocol version",
        ));
    }
    let modern = protocol_version.as_deref() == Some(MODERN_VERSION);
    match request.method.as_str() {
        "initialize" => Dispatch::Reply(initialize_response(&id, &fields)),
        "server/discover" => Dispatch::Reply(success_response(
            &id,
            json!({
                "resultType": "complete", "supportedVersions": [MODERN_VERSION],
                "capabilities": {"tools": {}},
                "_meta": {"io.modelcontextprotocol/serverInfo": {"name": SERVER_NAME, "version": env!("CARGO_PKG_VERSION")}},
                "cacheScope": "private", "ttlMs": 3600000
            }),
        )),
        "ping" => Dispatch::Reply(success_response(&id, json!({}))),
        "tools/list" => {
            let mut result = json!({"tools": policy.definitions()});
            if modern {
                result["resultType"] = json!("complete");
            }
            Dispatch::Reply(success_response(&id, result))
        }
        "tools/call" => prepare_tool_call(id, modern, params, policy),
        _ => Dispatch::Reply(protocol_error(Some(&id), -32601, "Method not found")),
    }
}

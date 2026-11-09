use crate::{plugins::PluginCatalog, proto::services::ctrng::CTrngResponse};
use serde::de::{self, DeserializeOwned};
use serde::{Deserialize, Serialize};

use crate::proto::services::ctrng::CTrngRequest;
use crate::proto::services::kms::{
    CreateKeyRequest, DecapsulateRequest, DecryptRequest, EncapsulateRequest, EncryptRequest,
    GenerateDataKeyRequest, GetCapabilitiesRequest, GetKeyMetadataRequest, GetPublicKeyRequest,
    RotateKeyRequest, SignRequest,
};
use crate::proto::services::threshold::DkgRequest;

use crate::services::ctrng::{CTrngService, MAX_CHUNKS};
use crate::services::kms::{
    KeyStoreDeleteRequest, KeyStoreGetRequest, KeyStoreListRequest, KeyStorePutRequest, KmsRpcCall,
    KmsService,
};
use crate::services::threshold::{ThresholdRpcCall, ThresholdService};

type JsonRpcRawResponse = Box<serde_json::value::RawValue>;

#[derive(Serialize)]
pub struct JsonRpcError {
    code: i32,
    message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    data: Option<serde_json::Value>,
}

/// Struct representing a JSON-RPC request, which includes the JSON-RPC version,
/// an ID for correlating requests and responses, and the RPC call details.
#[derive(Debug)]
pub struct JsonRpcRequest {
    _jsonrpc: String,
    pub id: u64,
    pub call: RpcCall,
}

impl<'de> Deserialize<'de> for JsonRpcRequest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Envelope {
            #[serde(rename = "jsonrpc")]
            jsonrpc: String,
            id: u64,
            method: String,
            params: Box<serde_json::value::RawValue>,
        }

        let envelope = Envelope::deserialize(deserializer)?;
        let call = RpcCall::from_method_and_params(&envelope.method, envelope.params.get())
            .map_err(de::Error::custom)?;

        Ok(Self {
            _jsonrpc: envelope.jsonrpc,
            id: envelope.id,
            call,
        })
    }
}
/// Struct representing a JSON-RPC response.
/// It can be either a success with a result or an error with a message.
/// The `id` field is used to correlate the response with the original request.
#[derive(Serialize)]
pub struct JsonRpcResponse<T> {
    jsonrpc: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<T>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<JsonRpcError>,
    pub id: u64,
}

impl<T> JsonRpcResponse<T> {
    pub fn success(id: u64, result: T) -> Self {
        Self {
            jsonrpc: "2.0",
            result: Some(result),
            error: None,
            id,
        }
    }

    pub fn error(id: u64, code: i32, message: impl Into<String>) -> Self {
        Self::error_with_data(id, code, message.into(), None)
    }

    pub fn execution_error(id: u64, status: &tonic::Status) -> Self {
        let reason = match status.code() {
            tonic::Code::NotFound => Some("not_found"),
            tonic::Code::PermissionDenied => Some("permission_denied"),
            tonic::Code::FailedPrecondition => Some("failed_precondition"),
            tonic::Code::InvalidArgument => Some("invalid_argument"),
            _ => None,
        };
        Self::error_with_data(
            id,
            -32001,
            status.to_string(),
            reason.map(|reason| serde_json::json!({"reason": reason})),
        )
    }

    fn error_with_data(
        id: u64,
        code: i32,
        message: String,
        data: Option<serde_json::Value>,
    ) -> Self {
        Self {
            jsonrpc: "2.0",
            result: None,
            error: Some(JsonRpcError {
                code,
                message,
                data,
            }),
            id,
        }
    }
}

/// Enum representing the different RPC calls that the gateway can handle.
/// Each variant corresponds to a specific RPC method and contains the parameters for that method.
/// The "method" format is `{service}.{method}`, where the service is always lowercase and the method is in CamelCase.
/// This allows for easy routing of RPC calls to the appropriate service handlers.
#[derive(Debug)]
pub enum RpcCall {
    GetCTRNG(CTrngRequest),
    GetCapabilities(GetCapabilitiesRequest),
    CreateKey(CreateKeyRequest),
    Decrypt(DecryptRequest),
    Encrypt(EncryptRequest),
    GenerateDataKey(GenerateDataKeyRequest),
    RotateKey(RotateKeyRequest),
    KeyStorePut(KeyStorePutRequest),
    KeyStoreGet(KeyStoreGetRequest),
    KeyStoreList(KeyStoreListRequest),
    KeyStoreDelete(KeyStoreDeleteRequest),
    Sign(SignRequest),
    Encapsulate(EncapsulateRequest),
    Decapsulate(DecapsulateRequest),
    CoordinateDKG(DkgRequest),
    GetKeyMetadata(GetKeyMetadataRequest),
    GetPublicKey(GetPublicKeyRequest),
}

impl RpcCall {
    fn from_method_and_params(method: &str, params_json: &str) -> Result<Self, String> {
        match method {
            "ctrng.Get" => Ok(Self::GetCTRNG(Self::parse_params(method, params_json)?)),
            "kms.GetCapabilities" => Ok(Self::GetCapabilities(Self::parse_params(
                method,
                params_json,
            )?)),
            "kms.CreateKey" => Ok(Self::CreateKey(Self::parse_params(method, params_json)?)),
            "kms.GetKeyMetadata" => Ok(Self::GetKeyMetadata(Self::parse_params(
                method,
                params_json,
            )?)),
            "kms.GetPublicKey" => Ok(Self::GetPublicKey(Self::parse_params(method, params_json)?)),
            "kms.Decrypt" => Ok(Self::Decrypt(Self::parse_params(method, params_json)?)),
            "kms.Encrypt" => Ok(Self::Encrypt(Self::parse_params(method, params_json)?)),
            "kms.GenerateDataKey" => Ok(Self::GenerateDataKey(Self::parse_params(
                method,
                params_json,
            )?)),
            "kms.RotateKey" => Ok(Self::RotateKey(Self::parse_params(method, params_json)?)),
            "kms_keystore.Put" => Ok(Self::KeyStorePut(Self::parse_params(method, params_json)?)),
            "kms_keystore.Get" => Ok(Self::KeyStoreGet(Self::parse_params(method, params_json)?)),
            "kms_keystore.List" => Ok(Self::KeyStoreList(Self::parse_params(method, params_json)?)),
            "kms_keystore.Delete" => Ok(Self::KeyStoreDelete(Self::parse_params(
                method,
                params_json,
            )?)),
            "kms.Sign" => Ok(Self::Sign(Self::parse_params(method, params_json)?)),
            "kms.Encapsulate" => Ok(Self::Encapsulate(Self::parse_params(method, params_json)?)),
            "kms.Decapsulate" => Ok(Self::Decapsulate(Self::parse_params(method, params_json)?)),
            "kms_threshold.CoordinateDKG" => Ok(Self::CoordinateDKG(Self::parse_params(
                method,
                params_json,
            )?)),
            _ => Err(format!("Unsupported method: {method}")),
        }
    }

    fn parse_params<T>(method: &str, params_json: &str) -> Result<T, String>
    where
        T: DeserializeOwned,
    {
        serde_json::from_str(params_json).map_err(|e| format!("Invalid params for {method}: {e}"))
    }

    /// Validates the parameters of the RPC call.
    pub fn validate(&self) -> Result<(), String> {
        match self {
            RpcCall::GetCTRNG(req) => {
                if let Some(chunks) = req.chunks {
                    if chunks > MAX_CHUNKS {
                        return Err("Max chunks exceeded".to_string());
                    }
                    if chunks < 1 {
                        return Err("Chunks must be at least 1".to_string());
                    }
                }
            }
            RpcCall::GetCapabilities(_) => {}
            RpcCall::Encrypt(req) => KmsService::validate_encrypt(req)?,
            RpcCall::Decrypt(req) => KmsService::validate_decrypt(req)?,
            RpcCall::Sign(req) => KmsService::validate_sign(req)?,
            RpcCall::Encapsulate(req) => KmsService::validate_encapsulate(req)?,
            RpcCall::Decapsulate(req) => KmsService::validate_decapsulate(req)?,
            RpcCall::CreateKey(req) => KmsService::validate_create_key(req)?,
            RpcCall::GetKeyMetadata(req) => KmsService::validate_get_key_metadata(req)?,
            RpcCall::GetPublicKey(req) => KmsService::validate_get_public_key(req)?,
            RpcCall::GenerateDataKey(req) => KmsService::validate_generate_data_key(req)?,
            RpcCall::RotateKey(req) => KmsService::validate_rotate_key(req)?,
            RpcCall::KeyStorePut(req) => KmsService::validate_key_store_put(req)?,
            RpcCall::KeyStoreGet(req) => KmsService::validate_key_store_get(req)?,
            RpcCall::KeyStoreList(req) => KmsService::validate_key_store_list(req)?,
            RpcCall::KeyStoreDelete(req) => KmsService::validate_key_store_delete(req)?,
            RpcCall::CoordinateDKG(req) => {
                ThresholdService::validate_coordinate_dkg(req).map_err(|e| e.to_string())?
            }
        }
        Ok(())
    }

    /// Account-plugin hold tag: `method` or `method:variant`. Call only after
    /// `validate()` passes, which pins the variant to an exact known value.
    pub fn operation(&self) -> String {
        match self {
            RpcCall::GetCTRNG(_) => "ctrng.Get".to_string(),
            RpcCall::GetCapabilities(_) => "kms.GetCapabilities".to_string(),
            RpcCall::CreateKey(req) => format!("kms.CreateKey:{}", req.key_spec),
            RpcCall::GetKeyMetadata(_) => "kms.GetKeyMetadata".to_string(),
            RpcCall::GetPublicKey(_) => "kms.GetPublicKey".to_string(),
            RpcCall::Decrypt(_) => "kms.Decrypt".to_string(),
            RpcCall::Encrypt(_) => "kms.Encrypt".to_string(),
            RpcCall::GenerateDataKey(_) => "kms.GenerateDataKey".to_string(),
            RpcCall::RotateKey(_) => "kms.RotateKey".to_string(),
            RpcCall::KeyStorePut(_) => "kms_keystore.Put".to_string(),
            RpcCall::KeyStoreGet(_) => "kms_keystore.Get".to_string(),
            RpcCall::KeyStoreList(_) => "kms_keystore.List".to_string(),
            RpcCall::KeyStoreDelete(_) => "kms_keystore.Delete".to_string(),
            RpcCall::Sign(req) => format!("kms.Sign:{}", req.signing_algorithm),
            RpcCall::Encapsulate(_) => "kms.Encapsulate".to_string(),
            RpcCall::Decapsulate(_) => "kms.Decapsulate".to_string(),
            RpcCall::CoordinateDKG(_) => "kms_threshold.CoordinateDKG".to_string(),
        }
    }

    /// Executes the RPC call using the provided plugin catalog.
    pub async fn execute(
        self,
        req_id: u64,
        client_id: &str,
        plugin_catalog: &PluginCatalog,
    ) -> Result<JsonRpcRawResponse, tonic::Status> {
        match self {
            RpcCall::GetCTRNG(req) => {
                let grpc_client = plugin_catalog.get_masterseed_client().await.map_err(|_| {
                    if plugin_catalog.ctrng_enabled() {
                        tonic::Status::unavailable("Masterseed plugin unavailable")
                    } else {
                        tonic::Status::unavailable("cTRNG feature disabled")
                    }
                })?;
                let mut svc = CTrngService::new(grpc_client);
                let results: CTrngResponse = svc.get_values(req).await.map_err(|e| {
                    // We can log _e here for debugging, but we don't want to expose internal errors to the client
                    tracing::warn!("Failed to get mixed cTRNG: {:?}", e);
                    tonic::Status::internal("Failed to get mixed cTRNG")
                })?;
                serialize_success_response(req_id, results)
            }
            RpcCall::GetCapabilities(_) => {
                serialize_success_response(req_id, KmsService::get_capabilities())
            }
            RpcCall::Encrypt(req) => {
                execute_kms(req_id, client_id, plugin_catalog, KmsRpcCall::Encrypt(req)).await
            }
            RpcCall::Decrypt(req) => {
                execute_kms(req_id, client_id, plugin_catalog, KmsRpcCall::Decrypt(req)).await
            }
            RpcCall::Sign(req) => {
                execute_kms(req_id, client_id, plugin_catalog, KmsRpcCall::Sign(req)).await
            }
            RpcCall::Encapsulate(req) => {
                execute_kms(
                    req_id,
                    client_id,
                    plugin_catalog,
                    KmsRpcCall::Encapsulate(req),
                )
                .await
            }
            RpcCall::Decapsulate(req) => {
                execute_kms(
                    req_id,
                    client_id,
                    plugin_catalog,
                    KmsRpcCall::Decapsulate(req),
                )
                .await
            }
            RpcCall::CreateKey(req) => {
                execute_kms(
                    req_id,
                    client_id,
                    plugin_catalog,
                    KmsRpcCall::CreateKey(req),
                )
                .await
            }
            RpcCall::GetKeyMetadata(req) => {
                execute_kms(
                    req_id,
                    client_id,
                    plugin_catalog,
                    KmsRpcCall::GetKeyMetadata(req),
                )
                .await
            }
            RpcCall::GetPublicKey(req) => {
                execute_kms(
                    req_id,
                    client_id,
                    plugin_catalog,
                    KmsRpcCall::GetPublicKey(req),
                )
                .await
            }
            RpcCall::GenerateDataKey(req) => {
                execute_kms(
                    req_id,
                    client_id,
                    plugin_catalog,
                    KmsRpcCall::GenerateDataKey(req),
                )
                .await
            }
            RpcCall::RotateKey(req) => {
                execute_kms(
                    req_id,
                    client_id,
                    plugin_catalog,
                    KmsRpcCall::RotateKey(req),
                )
                .await
            }
            RpcCall::KeyStorePut(req) => {
                execute_kms(
                    req_id,
                    client_id,
                    plugin_catalog,
                    KmsRpcCall::KeyStorePut(req),
                )
                .await
            }
            RpcCall::KeyStoreGet(req) => {
                execute_kms(
                    req_id,
                    client_id,
                    plugin_catalog,
                    KmsRpcCall::KeyStoreGet(req),
                )
                .await
            }
            RpcCall::KeyStoreList(req) => {
                execute_kms(
                    req_id,
                    client_id,
                    plugin_catalog,
                    KmsRpcCall::KeyStoreList(req),
                )
                .await
            }
            RpcCall::KeyStoreDelete(req) => {
                execute_kms(
                    req_id,
                    client_id,
                    plugin_catalog,
                    KmsRpcCall::KeyStoreDelete(req),
                )
                .await
            }
            RpcCall::CoordinateDKG(req) => {
                execute_threshold(
                    req_id,
                    client_id,
                    plugin_catalog,
                    ThresholdRpcCall::CoordinateDkg(req),
                )
                .await
            }
        }
    }
}

fn serialize_success_response<T: Serialize>(
    req_id: u64,
    result: T,
) -> Result<JsonRpcRawResponse, tonic::Status> {
    let res = JsonRpcResponse::success(req_id, result);
    serde_json::value::to_raw_value(&res)
        .map_err(|e| tonic::Status::internal(format!("Failed to serialize response: {e}")))
}

async fn execute_kms(
    req_id: u64,
    client_id: &str,
    plugin_catalog: &PluginCatalog,
    call: KmsRpcCall,
) -> Result<JsonRpcRawResponse, tonic::Status> {
    let grpc_client = plugin_catalog
        .get_kms_client()
        .await
        .map_err(|_| tonic::Status::unavailable("KMS plugin unavailable"))?;
    let mut svc = KmsService::new(grpc_client);
    let results = svc.execute(client_id, req_id, call).await?;
    serialize_success_response(req_id, results)
}

async fn execute_threshold(
    req_id: u64,
    client_id: &str,
    plugin_catalog: &PluginCatalog,
    call: ThresholdRpcCall,
) -> Result<JsonRpcRawResponse, tonic::Status> {
    if !plugin_catalog.threshold_enabled() {
        return Err(tonic::Status::unavailable("Threshold feature disabled"));
    }

    let grpc_client = plugin_catalog
        .get_threshold_client()
        .await
        .map_err(|_| tonic::Status::unavailable("Threshold plugin unavailable"))?;
    let mut svc = ThresholdService::new(grpc_client, plugin_catalog.threshold_groups());
    let results = svc.execute(client_id, req_id, call).await?;
    serialize_success_response(req_id, results)
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn execution_errors_preserve_legacy_fields_and_include_known_reasons() {
        for (code, reason) in [
            (tonic::Code::NotFound, Some("not_found")),
            (tonic::Code::PermissionDenied, Some("permission_denied")),
            (tonic::Code::FailedPrecondition, Some("failed_precondition")),
            (tonic::Code::InvalidArgument, Some("invalid_argument")),
            (tonic::Code::Internal, None),
        ] {
            let status = tonic::Status::new(code, "backend detail");
            let reply =
                serde_json::to_value(JsonRpcResponse::<()>::execution_error(7, &status)).unwrap();
            assert_eq!(reply["jsonrpc"], "2.0");
            assert_eq!(reply["id"], 7);
            let error = &reply["error"];
            assert_eq!(error["code"], -32001);
            assert_eq!(error["message"], status.to_string());
            match reason {
                Some(reason) => assert_eq!(error["data"], serde_json::json!({"reason": reason})),
                None => assert!(error.get("data").is_none()),
            }
        }
    }

    fn request_from_value(raw: serde_json::Value) -> JsonRpcRequest {
        let raw_json = serde_json::to_string(&raw).unwrap();
        serde_json::from_str(&raw_json).unwrap()
    }

    #[test]
    fn test_deserialize_kms_encrypt_pascal_case() {
        let raw = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 7,
            "method": "kms.Encrypt",
            "params": {
                "KeyId": "kms:abc",
                "Plaintext": "Zm9v",
                "EncryptionAlgorithm": "AES_256_GCM96"
            }
        });

        let req = request_from_value(raw);
        match req.call {
            RpcCall::Encrypt(params) => {
                assert_eq!(params.key_id, "kms:abc");
                assert_eq!(params.plaintext, "Zm9v");
                assert_eq!(
                    params.encryption_algorithm.as_deref(),
                    Some("AES_256_GCM96")
                );
            }
            _ => panic!("expected kms.Encrypt"),
        }
    }

    #[test]
    fn test_deserialize_kms_get_capabilities_pascal_case() {
        let raw = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 8,
            "method": "kms.GetCapabilities",
            "params": {}
        });

        let req = request_from_value(raw);
        match req.call {
            RpcCall::GetCapabilities(_) => {}
            _ => panic!("expected kms.GetCapabilities"),
        }
    }

    #[test]
    fn test_deserialize_kms_get_key_metadata_pascal_case() {
        let raw = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 8,
            "method": "kms.GetKeyMetadata",
            "params": {
                "KeyId": "kms:telemetry-signing"
            }
        });

        let req = request_from_value(raw);
        match req.call {
            RpcCall::GetKeyMetadata(params) => {
                assert_eq!(params.key_id, "kms:telemetry-signing");
            }
            _ => panic!("expected kms.GetKeyMetadata"),
        }
    }

    #[test]
    fn test_deserialize_kms_get_key_metadata_accepts_alias() {
        let raw = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 8,
            "method": "kms.GetKeyMetadata",
            "params": {
                "KeyId": "telemetry-signing"
            }
        });

        let req = request_from_value(raw);
        match req.call {
            RpcCall::GetKeyMetadata(params) => {
                assert_eq!(params.key_id, "telemetry-signing");
            }
            _ => panic!("expected kms.GetKeyMetadata"),
        }
    }

    #[test]
    fn test_deserialize_kms_get_public_key_accepts_alias() {
        let raw = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 8,
            "method": "kms.GetPublicKey",
            "params": {
                "KeyId": "telemetry-signing",
                "Version": 1
            }
        });

        let req = request_from_value(raw);
        match req.call {
            RpcCall::GetPublicKey(params) => {
                assert_eq!(params.key_id, "telemetry-signing");
                assert_eq!(params.version, Some(1));
            }
            _ => panic!("expected kms.GetPublicKey"),
        }
    }

    #[test]
    fn test_serialize_kms_get_capabilities_includes_pascal_case_tags() {
        let response =
            serialize_success_response(8, KmsService::get_capabilities()).expect("serialize");
        let response: serde_json::Value = serde_json::from_str(response.get()).unwrap();
        let schemes = response["result"]["Schemes"]
            .as_array()
            .expect("Schemes should be an array");
        let pqc = schemes
            .iter()
            .find(|scheme| scheme["Scheme"] == "PQC")
            .expect("missing PQC capability");

        assert_eq!(pqc["Tags"], serde_json::json!(["experimental"]));

        let signing = pqc["SigningCapabilities"]
            .as_array()
            .expect("SigningCapabilities should be an array")
            .iter()
            .find(|capability| capability["SigningAlgorithm"] == "ML_DSA")
            .expect("missing ML_DSA signing capability");
        assert_eq!(signing["Tags"], serde_json::json!(["experimental"]));

        assert_eq!(pqc["KeyAgreementCapabilities"], serde_json::json!([]));
        assert_eq!(pqc["SupportsEncapsulate"], false);
        assert_eq!(pqc["SupportsDecapsulate"], false);
    }

    #[test]
    fn test_serialize_kms_get_key_metadata_includes_pascal_case_public_key() {
        let response = serialize_success_response(
            8,
            crate::proto::services::kms::GetKeyMetadataResponse {
                key_metadata: Some(crate::proto::services::kms::KeyMetadata {
                    key_id: "kms:telemetry-signing".to_string(),
                    description: "telemetry signing".to_string(),
                    key_spec: "ECDSA_P256".to_string(),
                    key_usage: "SIGN_VERIFY".to_string(),
                    enabled: true,
                    primary_version: 1,
                    creation_date: "2026-09-22T18:42:00Z".to_string(),
                    tags: vec![],
                    scheme: "TRANSIT".to_string(),
                    public_key: Some("-----BEGIN PUBLIC KEY-----demo".to_string()),
                    address: None,
                    alias: "telemetry-signing".to_string(),
                }),
            },
        )
        .expect("serialize");

        let response: serde_json::Value = serde_json::from_str(response.get()).unwrap();
        assert_eq!(
            response["result"]["KeyMetadata"]["PublicKey"],
            "-----BEGIN PUBLIC KEY-----demo"
        );
        assert_eq!(
            response["result"]["KeyMetadata"]["KeyId"],
            "kms:telemetry-signing"
        );
    }

    #[test]
    fn test_serialize_kms_sign_includes_key_version() {
        let response = serialize_success_response(
            8,
            crate::proto::services::kms::SignResponse {
                key_id: "kms:telemetry-signing".to_string(),
                signature: "vault:v2:signature".to_string(),
                signing_algorithm: "ECDSA_SHA_256".to_string(),
                key_version: 2,
            },
        )
        .expect("serialize");

        let response: serde_json::Value = serde_json::from_str(response.get()).unwrap();
        assert_eq!(
            response["result"],
            serde_json::json!({
                "KeyId": "kms:telemetry-signing",
                "Signature": "vault:v2:signature",
                "SigningAlgorithm": "ECDSA_SHA_256",
                "KeyVersion": 2
            })
        );
    }

    #[test]
    fn test_serialize_kms_get_public_key_includes_version() {
        let response = serialize_success_response(
            8,
            crate::proto::services::kms::GetPublicKeyResponse {
                public_key: "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----\n"
                    .to_string(),
                version: 2,
            },
        )
        .expect("serialize");

        let response: serde_json::Value = serde_json::from_str(response.get()).unwrap();
        assert_eq!(
            response["result"],
            serde_json::json!({
                "PublicKey": "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----\n",
                "Version": 2
            })
        );
    }

    #[test]
    fn test_deserialize_kms_decapsulate_pascal_case() {
        let raw = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 9,
            "method": "kms.Decapsulate",
            "params": {
                "KeyId": "kms:abc",
                "Ciphertext": "Y3Q="
            }
        });

        let req = request_from_value(raw);
        match req.call {
            RpcCall::Decapsulate(params) => {
                assert_eq!(params.key_id, "kms:abc");
                assert_eq!(params.ciphertext, "Y3Q=");
            }
            _ => panic!("expected kms.Decapsulate"),
        }
    }

    #[test]
    fn test_deserialize_kms_key_store_put_pascal_case() {
        let raw = r#"{
            "jsonrpc": "2.0",
            "id": 10,
            "method": "kms_keystore.Put",
            "params": {
                "Name": "github/prod",
                "Secret": {
                    "api_key": "secret-value"
                }
            }
        }"#;

        let req: JsonRpcRequest = serde_json::from_str(raw).unwrap();
        match req.call {
            RpcCall::KeyStorePut(params) => {
                assert_eq!(params.name, "github/prod");
                let secret: serde_json::Value =
                    serde_json::from_str(params.secret.as_json_str()).unwrap();
                assert_eq!(secret["api_key"], "secret-value");
            }
            _ => panic!("expected kms_keystore.Put"),
        }
    }

    #[test]
    fn test_deserialize_kms_key_store_put_preserves_large_integer_secret() {
        let raw = r#"{
            "jsonrpc": "2.0",
            "id": 10,
            "method": "kms_keystore.Put",
            "params": {
                "Name": "github/prod",
                "Secret": {
                    "max_wei": 123456789012345678901234567890,
                    "pi": 3.14159265358979323846
                }
            }
        }"#;

        let req: JsonRpcRequest = serde_json::from_str(raw).unwrap();
        match req.call {
            RpcCall::KeyStorePut(params) => {
                let secret_json = params.secret.as_json_str();
                assert!(secret_json.contains("123456789012345678901234567890"));
                assert!(secret_json.contains("3.14159265358979323846"));
                assert!(!secret_json.contains("1.2345678901234568e29"));
                assert!(!secret_json.contains("3.141592653589793}"));
            }
            _ => panic!("expected kms_keystore.Put"),
        }
    }

    #[test]
    fn test_serialize_key_store_get_preserves_large_number_secret() {
        let secret_json =
            r#"{"max_wei":123456789012345678901234567890,"pi":3.14159265358979323846}"#;
        let secret: crate::services::kms::KeyStoreSecret =
            serde_json::from_str(secret_json).unwrap();
        let response = serialize_success_response(
            11,
            crate::services::kms::KeyStoreGetResponse {
                name: "github/prod".to_string(),
                secret,
            },
        )
        .unwrap();
        let response_json = response.get();
        let http_json = serde_json::to_string(&response).unwrap();

        assert_eq!(http_json, response_json);
        assert!(response_json.contains("123456789012345678901234567890"));
        assert!(response_json.contains("3.14159265358979323846"));
        assert!(!response_json.contains("1.2345678901234568e29"));
        assert!(!response_json.contains(r#""pi":3.141592653589793}"#));
        assert!(!response_json.contains(r#""pi":3.141592653589793,"#));
    }

    #[test]
    fn test_deserialize_kms_key_store_put_rejects_non_object_secret() {
        let raw = r#"{
            "jsonrpc": "2.0",
            "id": 10,
            "method": "kms_keystore.Put",
            "params": {
                "Name": "github/prod",
                "Secret": ["not", "an", "object"]
            }
        }"#;

        let err = serde_json::from_str::<JsonRpcRequest>(raw).unwrap_err();
        assert!(err.to_string().contains("Secret must be a JSON object"));
    }

    #[test]
    fn test_deserialize_kms_key_store_get_pascal_case() {
        let raw = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 11,
            "method": "kms_keystore.Get",
            "params": {
                "Name": "github/prod"
            }
        });

        let req = request_from_value(raw);
        match req.call {
            RpcCall::KeyStoreGet(params) => {
                assert_eq!(params.name, "github/prod");
            }
            _ => panic!("expected kms_keystore.Get"),
        }
    }

    #[test]
    fn test_deserialize_kms_key_store_delete_pascal_case() {
        let raw = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 12,
            "method": "kms_keystore.Delete",
            "params": {
                "Name": "github/prod"
            }
        });

        let req = request_from_value(raw);
        match req.call {
            RpcCall::KeyStoreDelete(params) => {
                assert_eq!(params.name, "github/prod");
            }
            _ => panic!("expected kms_keystore.Delete"),
        }
    }

    #[test]
    fn test_deserialize_threshold_coordinate_dkg_pascal_case() {
        let raw = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 9,
            "method": "kms_threshold.CoordinateDKG",
            "params": {
                "Alias": "key-1",
                "GroupName": "team-a",
                "SessionId": "dkg-1"
            }
        });

        let req = request_from_value(raw);
        match req.call {
            RpcCall::CoordinateDKG(params) => {
                assert_eq!(params.alias, "key-1");
                assert_eq!(params.group_name, "team-a");
                assert_eq!(params.session_id, "dkg-1");
            }
            _ => panic!("expected kms_threshold.CoordinateDKG"),
        }
    }

    fn operation_of(method: &str, params: serde_json::Value) -> String {
        let raw =
            serde_json::json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": params});
        let req: JsonRpcRequest = serde_json::from_value(raw).unwrap();
        req.call.validate().unwrap();
        req.call.operation()
    }

    #[test]
    fn test_operation_tags() {
        assert_eq!(
            operation_of(
                "kms.CreateKey",
                serde_json::json!({
                    "Alias": "pq-key",
                    "Description": "",
                    "KeySpec": "ML_DSA_65",
                    "KeyUsage": "SIGN_VERIFY",
                    "Scheme": "PQC",
                    "Tags": []
                })
            ),
            "kms.CreateKey:ML_DSA_65"
        );
        assert_eq!(
            operation_of(
                "kms.Sign",
                serde_json::json!({
                    "KeyId": "kms:abc",
                    "Message": "aGVsbG8=",
                    "SigningAlgorithm": "ECDSA_SHA_256",
                    "MessageType": "RAW"
                })
            ),
            "kms.Sign:ECDSA_SHA_256"
        );
        assert_eq!(
            operation_of(
                "kms.Encrypt",
                serde_json::json!({"KeyId": "kms:abc", "Plaintext": "Zm9v"})
            ),
            "kms.Encrypt"
        );
        assert_eq!(
            operation_of("kms.GetCapabilities", serde_json::json!({})),
            "kms.GetCapabilities"
        );
        assert_eq!(
            operation_of(
                "kms.GetKeyMetadata",
                serde_json::json!({"KeyId": "telemetry-signing"})
            ),
            "kms.GetKeyMetadata"
        );
        assert_eq!(
            operation_of(
                "kms.GetPublicKey",
                serde_json::json!({"KeyId": "telemetry-signing"})
            ),
            "kms.GetPublicKey"
        );
        assert_eq!(
            operation_of("ctrng.Get", serde_json::json!({})),
            "ctrng.Get"
        );
        assert_eq!(
            operation_of(
                "kms_keystore.Put",
                serde_json::json!({"Name": "github/prod", "Secret": {"api_key": "secret"}})
            ),
            "kms_keystore.Put"
        );
        assert_eq!(
            operation_of(
                "kms_keystore.Get",
                serde_json::json!({"Name": "github/prod"})
            ),
            "kms_keystore.Get"
        );
        assert_eq!(
            operation_of("kms_keystore.List", serde_json::json!({"Prefix": "github"})),
            "kms_keystore.List"
        );
        assert_eq!(
            operation_of(
                "kms_keystore.Delete",
                serde_json::json!({"Name": "github/prod"})
            ),
            "kms_keystore.Delete"
        );
    }

    #[tokio::test]
    async fn test_threshold_coordinate_dkg_disabled() {
        let plugin_catalog = PluginCatalog::new(
            "http://auth:50000",
            Some("http://masterseed:50003"),
            "http://kms:50004",
            None,
            None,
            false,
            "",
            crate::services::threshold::ThresholdGroupRegistry::default(),
        );

        let err = execute_threshold(
            9,
            "client-1",
            &plugin_catalog,
            ThresholdRpcCall::CoordinateDkg(DkgRequest {
                alias: "key-1".to_string(),
                group_name: "team-a".to_string(),
                session_id: "dkg-1".to_string(),
            }),
        )
        .await
        .expect_err("threshold feature should be disabled");

        assert_eq!(err.code(), tonic::Code::Unavailable);
        assert_eq!(err.message(), "Threshold feature disabled");
    }
}

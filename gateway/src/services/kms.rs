use orbitport_kms_api::KmsValidation;
use serde::Serialize;
use tonic::transport::Channel;

use crate::caller::Caller;
use crate::proto::plugins::kms::{
    CreateKeyRequest as PluginCreateKeyRequest, CreateKeyResponse as PluginCreateKeyResponse,
    DecapsulateRequest as PluginDecapsulateRequest,
    DecapsulateResponse as PluginDecapsulateResponse, DecryptRequest as PluginDecryptRequest,
    DecryptResponse as PluginDecryptResponse, EncapsulateRequest as PluginEncapsulateRequest,
    EncapsulateResponse as PluginEncapsulateResponse, EncryptRequest as PluginEncryptRequest,
    EncryptResponse as PluginEncryptResponse,
    GenerateDataKeyRequest as PluginGenerateDataKeyRequest,
    GenerateDataKeyResponse as PluginGenerateDataKeyResponse,
    GetKeyMetadataRequest as PluginGetKeyMetadataRequest,
    GetKeyMetadataResponse as PluginGetKeyMetadataResponse,
    GetPublicKeyRequest as PluginGetPublicKeyRequest,
    GetPublicKeyResponse as PluginGetPublicKeyResponse,
    KeyStoreDeleteRequest as PluginKeyStoreDeleteRequest,
    KeyStoreDeleteResponse as PluginKeyStoreDeleteResponse,
    KeyStoreGetRequest as PluginKeyStoreGetRequest,
    KeyStoreGetResponse as PluginKeyStoreGetResponse,
    KeyStoreListRequest as PluginKeyStoreListRequest,
    KeyStoreListResponse as PluginKeyStoreListResponse,
    KeyStorePutRequest as PluginKeyStorePutRequest,
    KeyStorePutResponse as PluginKeyStorePutResponse, ListKeysRequest as PluginListKeysRequest,
    RotateKeyRequest as PluginRotateKeyRequest, RotateKeyResponse as PluginRotateKeyResponse,
    SignRequest as PluginSignRequest, SignResponse as PluginSignResponse, Tag as PluginTag,
    kms_plugin_client::KmsPluginClient,
};
use crate::proto::services::kms::{
    CreateKeyRequest, CreateKeyResponse, DecapsulateRequest, DecapsulateResponse, DecryptRequest,
    DecryptResponse, EncapsulateRequest, EncapsulateResponse, EncryptRequest, EncryptResponse,
    GenerateDataKeyRequest, GenerateDataKeyResponse, GetCapabilitiesResponse,
    GetKeyMetadataRequest, GetKeyMetadataResponse, GetPublicKeyRequest, GetPublicKeyResponse,
    RotateKeyRequest, RotateKeyResponse, SignRequest, SignResponse, Tag,
};

pub use orbitport_kms_api::{
    KeyStoreDeleteRequest, KeyStoreDeleteResponse, KeyStoreGetRequest, KeyStoreGetResponse,
    KeyStoreListRequest, KeyStoreListResponse, KeyStorePutRequest, KeyStorePutResponse,
    KeyStoreSecret,
};

#[derive(Debug)]
pub enum KmsRpcCall {
    Encrypt(EncryptRequest),
    Decrypt(DecryptRequest),
    Sign(SignRequest),
    Encapsulate(EncapsulateRequest),
    Decapsulate(DecapsulateRequest),
    CreateKey(CreateKeyRequest),
    GetKeyMetadata(GetKeyMetadataRequest),
    GetPublicKey(GetPublicKeyRequest),
    GenerateDataKey(GenerateDataKeyRequest),
    RotateKey(RotateKeyRequest),
    KeyStorePut(KeyStorePutRequest),
    KeyStoreGet(KeyStoreGetRequest),
    KeyStoreList(KeyStoreListRequest),
    KeyStoreDelete(KeyStoreDeleteRequest),
}

impl KmsRpcCall {
    pub fn validate(&self) -> Result<(), String> {
        match self {
            Self::Encrypt(req) => KmsService::validate_encrypt(req),
            Self::Decrypt(req) => KmsService::validate_decrypt(req),
            Self::Sign(req) => KmsService::validate_sign(req),
            Self::Encapsulate(req) => KmsService::validate_encapsulate(req),
            Self::Decapsulate(req) => KmsService::validate_decapsulate(req),
            Self::CreateKey(req) => KmsService::validate_create_key(req),
            Self::GetKeyMetadata(req) => KmsService::validate_get_key_metadata(req),
            Self::GetPublicKey(req) => KmsService::validate_get_public_key(req),
            Self::GenerateDataKey(req) => KmsService::validate_generate_data_key(req),
            Self::RotateKey(req) => KmsService::validate_rotate_key(req),
            Self::KeyStorePut(req) => KmsService::validate_key_store_put(req),
            Self::KeyStoreGet(req) => KmsService::validate_key_store_get(req),
            Self::KeyStoreList(req) => KmsService::validate_key_store_list(req),
            Self::KeyStoreDelete(req) => KmsService::validate_key_store_delete(req),
        }
    }

    fn log_start(&self, req_id: u64) {
        match self {
            Self::Encrypt(req) => tracing::debug!(
                "Executing KMS Encrypt RPC [id={} key_id={}]",
                req_id,
                req.key_id
            ),
            Self::Decrypt(req) => tracing::debug!(
                "Executing KMS Decrypt RPC [id={} key_id={}]",
                req_id,
                req.key_id.as_deref().unwrap_or("<blob>")
            ),
            Self::Sign(req) => tracing::debug!(
                "Executing KMS Sign RPC [id={} key_id={} signing_algorithm={}]",
                req_id,
                req.key_id,
                req.signing_algorithm
            ),
            Self::Encapsulate(req) => tracing::debug!(
                "Executing KMS Encapsulate RPC [id={} key_id={}]",
                req_id,
                req.key_id
            ),
            Self::Decapsulate(req) => tracing::debug!(
                "Executing KMS Decapsulate RPC [id={} key_id={}]",
                req_id,
                req.key_id
            ),
            Self::CreateKey(req) => tracing::debug!(
                "Executing KMS CreateKey RPC [id={} scheme={} key_spec={} key_usage={}]",
                req_id,
                req.scheme.as_deref().unwrap_or("TRANSIT"),
                req.key_spec,
                req.key_usage
            ),
            Self::GetKeyMetadata(req) => tracing::debug!(
                "Executing KMS GetKeyMetadata RPC [id={} key_id={}]",
                req_id,
                req.key_id
            ),
            Self::GetPublicKey(req) => tracing::debug!(
                "Executing KMS GetPublicKey RPC [id={} key_id={}]",
                req_id,
                req.key_id
            ),
            Self::GenerateDataKey(req) => tracing::debug!(
                "Executing KMS GenerateDataKey RPC [id={} key_id={}]",
                req_id,
                req.key_id
            ),
            Self::RotateKey(req) => tracing::debug!(
                "Executing KMS RotateKey RPC [id={} key_id={}]",
                req_id,
                req.key_id
            ),
            Self::KeyStorePut(req) => {
                tracing::debug!(
                    "Executing KMS KeyStorePut RPC [id={} name={}]",
                    req_id,
                    req.name
                )
            }
            Self::KeyStoreGet(req) => {
                tracing::debug!(
                    "Executing KMS KeyStoreGet RPC [id={} name={}]",
                    req_id,
                    req.name
                )
            }
            Self::KeyStoreList(req) => tracing::debug!(
                "Executing KMS KeyStoreList RPC [id={} prefix={}]",
                req_id,
                req.prefix.as_deref().unwrap_or("")
            ),
            Self::KeyStoreDelete(req) => {
                tracing::debug!(
                    "Executing KMS KeyStoreDelete RPC [id={} name={}]",
                    req_id,
                    req.name
                )
            }
        }
    }
}

#[derive(Serialize)]
#[serde(untagged)]
pub enum KmsRpcResult {
    Encrypt(EncryptResponse),
    Decrypt(DecryptResponse),
    Sign(SignResponse),
    Encapsulate(EncapsulateResponse),
    Decapsulate(DecapsulateResponse),
    CreateKey(CreateKeyResponse),
    GetKeyMetadata(GetKeyMetadataResponse),
    GetPublicKey(GetPublicKeyResponse),
    GenerateDataKey(GenerateDataKeyResponse),
    RotateKey(RotateKeyResponse),
    KeyStorePut(KeyStorePutResponse),
    KeyStoreGet(KeyStoreGetResponse),
    KeyStoreList(KeyStoreListResponse),
    KeyStoreDelete(KeyStoreDeleteResponse),
}

impl KmsRpcResult {
    fn log_success(&self, req_id: u64) {
        match self {
            Self::Encrypt(result) => tracing::debug!(
                "KMS Encrypt RPC succeeded [id={} key_id={}]",
                req_id,
                result.key_id
            ),
            Self::Decrypt(result) => tracing::debug!(
                "KMS Decrypt RPC succeeded [id={} key_id={}]",
                req_id,
                result.key_id
            ),
            Self::Sign(result) => tracing::debug!(
                "KMS Sign RPC succeeded [id={} key_id={} signing_algorithm={}]",
                req_id,
                result.key_id,
                result.signing_algorithm
            ),
            Self::Encapsulate(result) => tracing::debug!(
                "KMS Encapsulate RPC succeeded [id={} key_id={} key_agreement_algorithm={}]",
                req_id,
                result.key_id,
                result.key_agreement_algorithm
            ),
            Self::Decapsulate(result) => tracing::debug!(
                "KMS Decapsulate RPC succeeded [id={} key_id={} key_agreement_algorithm={}]",
                req_id,
                result.key_id,
                result.key_agreement_algorithm
            ),
            Self::CreateKey(result) => {
                if let Some(metadata) = result.key_metadata.as_ref() {
                    tracing::debug!(
                        "KMS CreateKey RPC succeeded [id={} key_id={} scheme={}]",
                        req_id,
                        metadata.key_id,
                        metadata.scheme
                    );
                }
            }
            Self::GetKeyMetadata(result) => {
                if let Some(metadata) = result.key_metadata.as_ref() {
                    tracing::debug!(
                        "KMS GetKeyMetadata RPC succeeded [id={} key_id={} scheme={}]",
                        req_id,
                        metadata.key_id,
                        metadata.scheme
                    );
                }
            }
            Self::GetPublicKey(_) => {
                tracing::debug!("KMS GetPublicKey RPC succeeded [id={}]", req_id)
            }
            Self::GenerateDataKey(result) => tracing::debug!(
                "KMS GenerateDataKey RPC succeeded [id={} key_id={}]",
                req_id,
                result.key_id
            ),
            Self::RotateKey(result) => {
                if let Some(metadata) = result.key_metadata.as_ref() {
                    tracing::debug!(
                        "KMS RotateKey RPC succeeded [id={} key_id={} primary_version={}]",
                        req_id,
                        metadata.key_id,
                        metadata.primary_version
                    );
                }
            }
            Self::KeyStorePut(result) => tracing::debug!(
                "KMS KeyStorePut RPC succeeded [id={} name={} version={}]",
                req_id,
                result.name,
                result.version
            ),
            Self::KeyStoreGet(result) => tracing::debug!(
                "KMS KeyStoreGet RPC succeeded [id={} name={}]",
                req_id,
                result.name
            ),
            Self::KeyStoreList(result) => tracing::debug!(
                "KMS KeyStoreList RPC succeeded [id={} count={}]",
                req_id,
                result.names.len()
            ),
            Self::KeyStoreDelete(result) => tracing::debug!(
                "KMS KeyStoreDelete RPC succeeded [id={} name={}]",
                req_id,
                result.name
            ),
        }
    }
}

#[derive(Clone)]
pub struct KmsService {
    client: KmsPluginClient<Channel>,
    caller: Caller,
}

impl KmsService {
    pub fn new(client: KmsPluginClient<Channel>) -> Self {
        Self {
            client,
            caller: Caller::default(),
        }
    }

    /// Attaches the caller identity (agent id, token hash) that the KMS
    /// plugin authorizes against. Without it every call is an account call.
    pub fn with_caller(mut self, caller: Caller) -> Self {
        self.caller = caller;
        self
    }

    /// Lists the tenant's key metadata (policy playground). Authorized by the
    /// KMS plugin as kms.ListKeys.
    pub async fn list_keys(&mut self, client_id: &str) -> Result<serde_json::Value, tonic::Status> {
        let response = self
            .client
            .list_keys(self.caller.request(PluginListKeysRequest {
                client_id: client_id.to_string(),
            }))
            .await?
            .into_inner();
        let keys: Vec<serde_json::Value> = response
            .keys
            .into_iter()
            .map(|k| {
                serde_json::json!({
                    "keyId": k.key_id,
                    "alias": k.alias,
                    "scheme": k.scheme,
                    "keySpec": k.key_spec,
                    "keyUsage": k.key_usage,
                    "enabled": k.enabled,
                    "primaryVersion": k.primary_version,
                    "creationDate": k.creation_date,
                    "description": k.description,
                    "tags": k.tags.into_iter().map(|t| serde_json::json!({"key": t.tag_key, "value": t.tag_value})).collect::<Vec<_>>(),
                })
            })
            .collect();
        Ok(serde_json::json!({"keys": keys, "truncated": response.truncated}))
    }

    pub fn validate_encrypt(req: &EncryptRequest) -> Result<(), String> {
        KmsValidation::validate_encrypt(req)
    }

    pub fn validate_decrypt(req: &DecryptRequest) -> Result<(), String> {
        KmsValidation::validate_decrypt(req)
    }

    pub fn validate_sign(req: &SignRequest) -> Result<(), String> {
        KmsValidation::validate_sign(req)
    }

    pub fn validate_encapsulate(req: &EncapsulateRequest) -> Result<(), String> {
        KmsValidation::validate_encapsulate(req)
    }

    pub fn validate_decapsulate(req: &DecapsulateRequest) -> Result<(), String> {
        KmsValidation::validate_decapsulate(req)
    }

    pub fn validate_create_key(req: &CreateKeyRequest) -> Result<(), String> {
        KmsValidation::validate_create_key(req)
    }

    pub fn validate_generate_data_key(req: &GenerateDataKeyRequest) -> Result<(), String> {
        KmsValidation::validate_generate_data_key(req)
    }

    pub fn validate_get_key_metadata(req: &GetKeyMetadataRequest) -> Result<(), String> {
        KmsValidation::validate_get_key_metadata(req)
    }

    pub fn validate_get_public_key(req: &GetPublicKeyRequest) -> Result<(), String> {
        KmsValidation::validate_get_public_key(req)
    }

    pub fn validate_rotate_key(req: &RotateKeyRequest) -> Result<(), String> {
        KmsValidation::validate_rotate_key(req)
    }

    pub fn validate_key_store_put(req: &KeyStorePutRequest) -> Result<(), String> {
        KmsValidation::validate_key_store_put(req)
    }

    pub fn validate_key_store_get(req: &KeyStoreGetRequest) -> Result<(), String> {
        KmsValidation::validate_key_store_get(req)
    }

    pub fn validate_key_store_list(req: &KeyStoreListRequest) -> Result<(), String> {
        KmsValidation::validate_key_store_list(req)
    }

    pub fn validate_key_store_delete(req: &KeyStoreDeleteRequest) -> Result<(), String> {
        KmsValidation::validate_key_store_delete(req)
    }

    pub fn get_capabilities() -> GetCapabilitiesResponse {
        KmsValidation::get_capabilities()
    }

    pub async fn execute(
        &mut self,
        client_id: &str,
        req_id: u64,
        call: KmsRpcCall,
    ) -> Result<KmsRpcResult, tonic::Status> {
        call.log_start(req_id);

        let result = match call {
            KmsRpcCall::Encrypt(req) => KmsRpcResult::Encrypt(self.encrypt(client_id, req).await?),
            KmsRpcCall::Decrypt(req) => KmsRpcResult::Decrypt(self.decrypt(client_id, req).await?),
            KmsRpcCall::Sign(req) => KmsRpcResult::Sign(self.sign(client_id, req).await?),
            KmsRpcCall::Encapsulate(req) => {
                KmsRpcResult::Encapsulate(self.encapsulate(client_id, req).await?)
            }
            KmsRpcCall::Decapsulate(req) => {
                KmsRpcResult::Decapsulate(self.decapsulate(client_id, req).await?)
            }
            KmsRpcCall::CreateKey(req) => {
                KmsRpcResult::CreateKey(self.create_key(client_id, req).await?)
            }
            KmsRpcCall::GetKeyMetadata(req) => {
                KmsRpcResult::GetKeyMetadata(self.get_key_metadata(client_id, req).await?)
            }
            KmsRpcCall::GetPublicKey(req) => {
                KmsRpcResult::GetPublicKey(self.get_public_key(client_id, req).await?)
            }
            KmsRpcCall::GenerateDataKey(req) => {
                KmsRpcResult::GenerateDataKey(self.generate_data_key(client_id, req).await?)
            }
            KmsRpcCall::RotateKey(req) => {
                KmsRpcResult::RotateKey(self.rotate_key(client_id, req).await?)
            }
            KmsRpcCall::KeyStorePut(req) => {
                KmsRpcResult::KeyStorePut(self.key_store_put(client_id, req).await?)
            }
            KmsRpcCall::KeyStoreGet(req) => {
                KmsRpcResult::KeyStoreGet(self.key_store_get(client_id, req).await?)
            }
            KmsRpcCall::KeyStoreList(req) => {
                KmsRpcResult::KeyStoreList(self.key_store_list(client_id, req).await?)
            }
            KmsRpcCall::KeyStoreDelete(req) => {
                KmsRpcResult::KeyStoreDelete(self.key_store_delete(client_id, req).await?)
            }
        };

        result.log_success(req_id);
        Ok(result)
    }

    pub async fn encrypt(
        &mut self,
        client_id: &str,
        req: EncryptRequest,
    ) -> Result<EncryptResponse, tonic::Status> {
        let response: PluginEncryptResponse = self
            .client
            .encrypt(self.caller.request(PluginEncryptRequest {
                key_id: req.key_id,
                plaintext: req.plaintext,
                encryption_algorithm: req.encryption_algorithm,
                client_id: client_id.to_string(),
            }))
            .await?
            .into_inner();

        Ok(EncryptResponse {
            ciphertext_blob: response.ciphertext_blob,
            key_id: response.key_id,
            encryption_algorithm: response.encryption_algorithm,
        })
    }

    pub async fn decrypt(
        &mut self,
        client_id: &str,
        req: DecryptRequest,
    ) -> Result<DecryptResponse, tonic::Status> {
        let response: PluginDecryptResponse = self
            .client
            .decrypt(self.caller.request(PluginDecryptRequest {
                ciphertext_blob: req.ciphertext_blob,
                key_id: req.key_id,
                encryption_algorithm: req.encryption_algorithm,
                client_id: client_id.to_string(),
            }))
            .await?
            .into_inner();

        Ok(DecryptResponse {
            plaintext: response.plaintext,
            key_id: response.key_id,
            encryption_algorithm: response.encryption_algorithm,
        })
    }

    pub async fn sign(
        &mut self,
        client_id: &str,
        req: SignRequest,
    ) -> Result<SignResponse, tonic::Status> {
        let response: PluginSignResponse = self
            .client
            .sign(self.caller.request(PluginSignRequest {
                key_id: req.key_id,
                message: req.message,
                signing_algorithm: req.signing_algorithm,
                message_type: req.message_type,
                client_id: client_id.to_string(),
            }))
            .await?
            .into_inner();

        Ok(SignResponse {
            key_id: response.key_id,
            signature: response.signature,
            signing_algorithm: response.signing_algorithm,
            key_version: response.key_version,
        })
    }

    pub async fn encapsulate(
        &mut self,
        client_id: &str,
        req: EncapsulateRequest,
    ) -> Result<EncapsulateResponse, tonic::Status> {
        let response: PluginEncapsulateResponse = self
            .client
            .encapsulate(self.caller.request(PluginEncapsulateRequest {
                key_id: req.key_id,
                client_id: client_id.to_string(),
            }))
            .await?
            .into_inner();

        Ok(EncapsulateResponse {
            key_id: response.key_id,
            ciphertext: response.ciphertext,
            shared_key: response.shared_key,
            key_agreement_algorithm: response.key_agreement_algorithm,
        })
    }

    pub async fn decapsulate(
        &mut self,
        client_id: &str,
        req: DecapsulateRequest,
    ) -> Result<DecapsulateResponse, tonic::Status> {
        let response: PluginDecapsulateResponse = self
            .client
            .decapsulate(self.caller.request(PluginDecapsulateRequest {
                key_id: req.key_id,
                ciphertext: req.ciphertext,
                client_id: client_id.to_string(),
            }))
            .await?
            .into_inner();

        Ok(DecapsulateResponse {
            key_id: response.key_id,
            key_agreement_algorithm: response.key_agreement_algorithm,
            shared_key: response.shared_key,
        })
    }

    pub async fn create_key(
        &mut self,
        client_id: &str,
        req: CreateKeyRequest,
    ) -> Result<CreateKeyResponse, tonic::Status> {
        let response: PluginCreateKeyResponse = self
            .client
            .create_key(
                self.caller.request(PluginCreateKeyRequest {
                    description: req.description,
                    key_spec: req.key_spec,
                    key_usage: req.key_usage,
                    scheme: req.scheme,
                    alias: req.alias,
                    tags: req
                        .tags
                        .into_iter()
                        .map(|tag| PluginTag {
                            tag_key: tag.tag_key,
                            tag_value: tag.tag_value,
                        })
                        .collect(),
                    client_id: client_id.to_string(),
                }),
            )
            .await?
            .into_inner();

        Ok(CreateKeyResponse {
            key_metadata: response.key_metadata.map(map_key_metadata),
        })
    }

    pub async fn get_key_metadata(
        &mut self,
        client_id: &str,
        req: GetKeyMetadataRequest,
    ) -> Result<GetKeyMetadataResponse, tonic::Status> {
        let response: PluginGetKeyMetadataResponse = self
            .client
            .get_key_metadata(self.caller.request(PluginGetKeyMetadataRequest {
                key_id: req.key_id,
                client_id: client_id.to_string(),
            }))
            .await?
            .into_inner();

        Ok(GetKeyMetadataResponse {
            key_metadata: response.key_metadata.map(map_key_metadata),
        })
    }

    pub async fn get_public_key(
        &mut self,
        client_id: &str,
        req: GetPublicKeyRequest,
    ) -> Result<GetPublicKeyResponse, tonic::Status> {
        let response: PluginGetPublicKeyResponse = self
            .client
            .get_public_key(self.caller.request(PluginGetPublicKeyRequest {
                key_id: req.key_id,
                client_id: client_id.to_string(),
                version: req.version,
            }))
            .await?
            .into_inner();

        Ok(GetPublicKeyResponse {
            public_key: response.public_key,
            version: response.version,
        })
    }

    pub async fn generate_data_key(
        &mut self,
        client_id: &str,
        req: GenerateDataKeyRequest,
    ) -> Result<GenerateDataKeyResponse, tonic::Status> {
        let response: PluginGenerateDataKeyResponse = self
            .client
            .generate_data_key(self.caller.request(PluginGenerateDataKeyRequest {
                key_id: req.key_id,
                data_key_spec: req.data_key_spec,
                number_of_bytes: req.number_of_bytes,
                client_id: client_id.to_string(),
            }))
            .await?
            .into_inner();

        Ok(GenerateDataKeyResponse {
            key_id: response.key_id,
            plaintext: response.plaintext,
            ciphertext_blob: response.ciphertext_blob,
        })
    }

    pub async fn rotate_key(
        &mut self,
        client_id: &str,
        req: RotateKeyRequest,
    ) -> Result<RotateKeyResponse, tonic::Status> {
        let response: PluginRotateKeyResponse = self
            .client
            .rotate_key(self.caller.request(PluginRotateKeyRequest {
                key_id: req.key_id,
                client_id: client_id.to_string(),
            }))
            .await?
            .into_inner();

        Ok(RotateKeyResponse {
            key_metadata: response.key_metadata.map(map_key_metadata),
        })
    }

    pub async fn key_store_put(
        &mut self,
        client_id: &str,
        req: KeyStorePutRequest,
    ) -> Result<KeyStorePutResponse, tonic::Status> {
        let secret_json = req.secret.as_json_str().to_string();
        let response: PluginKeyStorePutResponse = self
            .client
            .key_store_put(self.caller.request(PluginKeyStorePutRequest {
                name: req.name,
                secret_json,
                client_id: client_id.to_string(),
            }))
            .await?
            .into_inner();

        Ok(KeyStorePutResponse {
            name: response.name,
            version: response.version,
        })
    }

    pub async fn key_store_get(
        &mut self,
        client_id: &str,
        req: KeyStoreGetRequest,
    ) -> Result<KeyStoreGetResponse, tonic::Status> {
        let response: PluginKeyStoreGetResponse = self
            .client
            .key_store_get(self.caller.request(PluginKeyStoreGetRequest {
                name: req.name,
                client_id: client_id.to_string(),
            }))
            .await?
            .into_inner();
        let secret = KeyStoreSecret::from_json_string(response.secret_json)
            .map_err(|_| tonic::Status::internal("key-store backend returned invalid secret"))?;

        Ok(KeyStoreGetResponse {
            name: response.name,
            secret,
        })
    }

    pub async fn key_store_list(
        &mut self,
        client_id: &str,
        req: KeyStoreListRequest,
    ) -> Result<KeyStoreListResponse, tonic::Status> {
        let response: PluginKeyStoreListResponse = self
            .client
            .key_store_list(self.caller.request(PluginKeyStoreListRequest {
                client_id: client_id.to_string(),
                prefix: req.prefix,
            }))
            .await?
            .into_inner();

        Ok(KeyStoreListResponse {
            names: response.names,
        })
    }

    pub async fn key_store_delete(
        &mut self,
        client_id: &str,
        req: KeyStoreDeleteRequest,
    ) -> Result<KeyStoreDeleteResponse, tonic::Status> {
        let response: PluginKeyStoreDeleteResponse = self
            .client
            .key_store_delete(self.caller.request(PluginKeyStoreDeleteRequest {
                name: req.name,
                client_id: client_id.to_string(),
            }))
            .await?
            .into_inner();

        Ok(KeyStoreDeleteResponse {
            name: response.name,
        })
    }
}

fn map_key_metadata(
    metadata: crate::proto::plugins::kms::KeyMetadata,
) -> crate::proto::services::kms::KeyMetadata {
    crate::proto::services::kms::KeyMetadata {
        key_id: metadata.key_id,
        description: metadata.description,
        key_spec: metadata.key_spec,
        key_usage: metadata.key_usage,
        enabled: metadata.enabled,
        primary_version: metadata.primary_version,
        creation_date: metadata.creation_date,
        scheme: metadata.scheme,
        alias: metadata.alias,
        public_key: metadata.public_key,
        address: metadata.address,
        tags: metadata
            .tags
            .into_iter()
            .map(|tag| Tag {
                tag_key: tag.tag_key,
                tag_value: tag.tag_value,
            })
            .collect(),
    }
}

#[cfg(test)]
mod test {
    use super::*;

    fn key_store_secret(raw: &str) -> KeyStoreSecret {
        serde_json::from_str(raw).unwrap()
    }

    #[test]
    fn test_validate_create_key_usage() {
        let req = CreateKeyRequest {
            description: String::new(),
            key_spec: "AES_256_GCM96".to_string(),
            key_usage: "SIGN_VERIFY".to_string(),
            scheme: None,
            alias: "transit-main".to_string(),
            tags: vec![],
        };
        let err = KmsService::validate_create_key(&req).unwrap_err();
        assert!(err.contains("ENCRYPT_DECRYPT"));
    }

    #[test]
    fn test_validate_create_key_ethereum_scheme() {
        let req = CreateKeyRequest {
            description: String::new(),
            key_spec: "ECC_SECG_P256K1".to_string(),
            key_usage: "SIGN_VERIFY".to_string(),
            scheme: Some("ETHEREUM".to_string()),
            alias: "eth-main".to_string(),
            tags: vec![],
        };
        KmsService::validate_create_key(&req).unwrap();
    }

    #[test]
    fn test_validate_create_key_pqc_scheme() {
        for key_spec in ["ML_DSA_44", "ML_DSA_65", "ML_DSA_87"] {
            let req = CreateKeyRequest {
                description: String::new(),
                key_spec: key_spec.to_string(),
                key_usage: "SIGN_VERIFY".to_string(),
                scheme: Some("PQC".to_string()),
                alias: "pqc-main".to_string(),
                tags: vec![],
            };
            KmsService::validate_create_key(&req).unwrap();
        }
    }

    #[test]
    fn test_validate_create_key_rejects_mlkem() {
        for key_spec in ["ML_KEM_768", "ML_KEM_1024"] {
            let req = CreateKeyRequest {
                description: String::new(),
                key_spec: key_spec.to_string(),
                key_usage: "KEY_AGREEMENT".to_string(),
                scheme: Some("PQC".to_string()),
                alias: "pqc-kem-main".to_string(),
                tags: vec![],
            };
            assert_eq!(
                KmsService::validate_create_key(&req).unwrap_err(),
                "ML-KEM is temporarily disabled"
            );
        }
    }

    #[test]
    fn test_validate_create_key_pqc_kem_rejects_sign_usage() {
        let req = CreateKeyRequest {
            description: String::new(),
            key_spec: "ML_KEM_768".to_string(),
            key_usage: "SIGN_VERIFY".to_string(),
            scheme: Some("PQC".to_string()),
            alias: "pqc-kem-main".to_string(),
            tags: vec![],
        };
        let err = KmsService::validate_create_key(&req).unwrap_err();
        assert_eq!(err, "ML-KEM is temporarily disabled");
    }

    #[test]
    fn test_validate_create_key_pqc_rejects_transit_spec() {
        let req = CreateKeyRequest {
            description: String::new(),
            key_spec: "ECDSA_P256".to_string(),
            key_usage: "SIGN_VERIFY".to_string(),
            scheme: Some("PQC".to_string()),
            alias: "pqc-main".to_string(),
            tags: vec![],
        };
        let err = KmsService::validate_create_key(&req).unwrap_err();
        assert!(err.contains("ML_DSA_44"));
    }

    #[test]
    fn test_validate_create_key_alias() {
        let req = CreateKeyRequest {
            description: String::new(),
            key_spec: "AES_256_GCM96".to_string(),
            key_usage: "ENCRYPT_DECRYPT".to_string(),
            scheme: None,
            alias: "kms:11111111-1111-1111-1111-111111111111".to_string(),
            tags: vec![],
        };
        let err = KmsService::validate_create_key(&req).unwrap_err();
        assert!(err.contains("reserved kms:<alias> format"));
    }

    #[test]
    fn test_validate_create_key_alias_required() {
        let req = CreateKeyRequest {
            description: String::new(),
            key_spec: "AES_256_GCM96".to_string(),
            key_usage: "ENCRYPT_DECRYPT".to_string(),
            scheme: None,
            alias: String::new(),
            tags: vec![],
        };
        let err = KmsService::validate_create_key(&req).unwrap_err();
        assert!(err.to_ascii_lowercase().contains("alias is required"));
    }

    #[test]
    fn test_validate_key_store_put_allows_nested_name() {
        let req = KeyStorePutRequest {
            name: "github/prod".to_string(),
            secret: key_store_secret(r#"{"api_key":"secret"}"#),
        };

        KmsService::validate_key_store_put(&req).unwrap();
    }

    #[test]
    fn test_validate_key_store_name_rejects_traversal() {
        let req = KeyStoreGetRequest {
            name: "github/../prod".to_string(),
        };

        let err = KmsService::validate_key_store_get(&req).unwrap_err();
        assert!(err.contains("invalid path segment"));
    }

    #[test]
    fn test_key_store_put_debug_redacts_secret() {
        let req = KeyStorePutRequest {
            name: "github/prod".to_string(),
            secret: key_store_secret(r#"{"api_key":"super-sensitive"}"#),
        };

        let debug = format!("{req:?}");
        assert!(debug.contains("<redacted>"));
        assert!(!debug.contains("super-sensitive"));
    }

    #[test]
    fn test_key_store_secret_from_plugin_preserves_precise_json_numbers() {
        let raw = r#"{"max_wei":123456789012345678901234567890,"pi":3.14159265358979323846}"#;

        let secret = KeyStoreSecret::from_json_string(raw.to_string()).unwrap();
        let serialized = serde_json::to_string(&secret).unwrap();

        assert_eq!(secret.as_json_str(), raw);
        assert_eq!(serialized, raw);
    }

    #[test]
    fn test_validate_generate_data_key_xor() {
        let req = GenerateDataKeyRequest {
            key_id: "kms:abc".to_string(),
            data_key_spec: Some("AES_256".to_string()),
            number_of_bytes: Some(32),
        };
        let err = KmsService::validate_generate_data_key(&req).unwrap_err();
        assert!(err.contains("Exactly one"));
    }

    #[test]
    fn test_validate_get_key_metadata_reference() {
        KmsService::validate_get_key_metadata(&GetKeyMetadataRequest {
            key_id: "kms:telemetry-signing".to_string(),
        })
        .unwrap();
        KmsService::validate_get_key_metadata(&GetKeyMetadataRequest {
            key_id: "telemetry-signing".to_string(),
        })
        .unwrap();

        let err = KmsService::validate_get_key_metadata(&GetKeyMetadataRequest {
            key_id: String::new(),
        })
        .unwrap_err();
        assert!(err.to_ascii_lowercase().contains("keyid is required"));

        let err = KmsService::validate_get_key_metadata(&GetKeyMetadataRequest {
            key_id: "telemetry/signing".to_string(),
        })
        .unwrap_err();
        assert!(err.contains("unsupported characters"));
    }

    #[test]
    fn test_validate_get_public_key_reference() {
        KmsService::validate_get_public_key(&GetPublicKeyRequest {
            key_id: "kms:telemetry-signing".to_string(),
            version: None,
        })
        .unwrap();
        KmsService::validate_get_public_key(&GetPublicKeyRequest {
            key_id: "telemetry-signing".to_string(),
            version: Some(2),
        })
        .unwrap();

        let err = KmsService::validate_get_public_key(&GetPublicKeyRequest {
            key_id: String::new(),
            version: None,
        })
        .unwrap_err();
        assert!(err.to_ascii_lowercase().contains("keyid is required"));

        let err = KmsService::validate_get_public_key(&GetPublicKeyRequest {
            key_id: "telemetry/signing".to_string(),
            version: None,
        })
        .unwrap_err();
        assert!(err.contains("unsupported characters"));

        let err = KmsService::validate_get_public_key(&GetPublicKeyRequest {
            key_id: "telemetry-signing".to_string(),
            version: Some(0),
        })
        .unwrap_err();
        assert!(err.contains("Version must be greater than 0"));
    }

    #[test]
    fn test_validate_decapsulate_requires_ciphertext() {
        let req = DecapsulateRequest {
            key_id: "kms:abc".to_string(),
            ciphertext: "".to_string(),
        };
        let err = KmsService::validate_decapsulate(&req).unwrap_err();
        assert!(err.to_ascii_lowercase().contains("ciphertext is required"));
    }

    #[test]
    fn test_validate_sign_message_type() {
        let req = SignRequest {
            key_id: "kms:abc".to_string(),
            message: "YWJj".to_string(),
            signing_algorithm: "ETHEREUM_SECP256K1".to_string(),
            message_type: Some("INVALID".to_string()),
        };
        let err = KmsService::validate_sign(&req).unwrap_err();
        assert!(err.contains("MessageType"));
    }

    #[test]
    fn test_get_capabilities_includes_transit_and_ethereum() {
        let capabilities = KmsService::get_capabilities();

        let transit = capabilities
            .schemes
            .iter()
            .find(|scheme| scheme.scheme == "TRANSIT")
            .expect("missing TRANSIT capability");
        assert!(transit.key_specs.contains(&"AES_256_GCM96".to_string()));
        assert!(
            transit
                .encryption_algorithms
                .contains(&"AES_256_GCM96".to_string())
        );
        assert!(transit.supports_encrypt);
        assert!(transit.supports_decrypt);
        assert!(transit.supports_generate_data_key);
        assert!(transit.supports_rotate_key);
        assert!(transit.tags.is_empty());
        assert!(
            transit
                .signing_capabilities
                .iter()
                .all(|capability| capability.tags.is_empty())
        );

        let ethereum = capabilities
            .schemes
            .iter()
            .find(|scheme| scheme.scheme == "ETHEREUM")
            .expect("missing ETHEREUM capability");
        assert!(ethereum.key_specs.contains(&"ECC_SECG_P256K1".to_string()));
        assert!(ethereum.signing_capabilities.iter().any(|capability| {
            capability.signing_algorithm == "ETHEREUM_SECP256K1"
                && capability.message_types.contains(&"EIP191".to_string())
        }));
        assert!(!ethereum.supports_encrypt);
        assert!(!ethereum.supports_generate_data_key);
        assert!(!ethereum.supports_rotate_key);
        assert!(ethereum.tags.is_empty());
        assert!(
            ethereum
                .signing_capabilities
                .iter()
                .all(|capability| capability.tags.is_empty())
        );

        let pqc = capabilities
            .schemes
            .iter()
            .find(|scheme| scheme.scheme == "PQC")
            .expect("missing PQC capability");
        assert_eq!(pqc.key_specs, vec!["ML_DSA_44", "ML_DSA_65", "ML_DSA_87"]);
        assert_eq!(pqc.key_usages, vec!["SIGN_VERIFY"]);
        assert_eq!(pqc.tags, vec!["experimental".to_string()]);
        let pqc_signing = pqc
            .signing_capabilities
            .iter()
            .find(|capability| capability.signing_algorithm == "ML_DSA")
            .expect("missing PQC signing capability");
        assert_eq!(pqc_signing.message_types, vec!["RAW".to_string()]);
        assert_eq!(pqc_signing.tags, vec!["experimental".to_string()]);
        assert!(pqc.key_agreement_capabilities.is_empty());
        assert!(!pqc.supports_encrypt);
        assert!(!pqc.supports_generate_data_key);
        assert!(!pqc.supports_rotate_key);
        assert!(!pqc.supports_encapsulate);
        assert!(!pqc.supports_decapsulate);
    }

    #[test]
    fn test_validate_sign_rejects_unsupported_message_type_for_algorithm() {
        let req = SignRequest {
            key_id: "kms:abc".to_string(),
            message: "YWJj".to_string(),
            signing_algorithm: "ECDSA_SHA_256".to_string(),
            message_type: Some("EIP191".to_string()),
        };
        let err = KmsService::validate_sign(&req).unwrap_err();
        assert_eq!(
            err,
            "MessageType EIP191 is not supported for SigningAlgorithm ECDSA_SHA_256"
        );
    }

    #[test]
    fn test_validate_sign_mldsa_raw_only() {
        let raw_req = SignRequest {
            key_id: "kms:abc".to_string(),
            message: "YWJj".to_string(),
            signing_algorithm: "ML_DSA".to_string(),
            message_type: Some("RAW".to_string()),
        };
        KmsService::validate_sign(&raw_req).unwrap();

        let digest_req = SignRequest {
            message_type: Some("DIGEST".to_string()),
            ..raw_req
        };
        let err = KmsService::validate_sign(&digest_req).unwrap_err();
        assert!(err.contains("ML_DSA"));
    }
}

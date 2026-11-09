//! Public KMS contract and pure validation shared by the gateway and MCP.
use serde::de;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::value::RawValue;
use std::fmt;

pub mod kms {
    include!(concat!(env!("OUT_DIR"), "/kms.rs"));
}
pub use kms::*;
pub mod schema;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Scheme {
    Transit,
    Ethereum,
    Pqc,
}

impl Scheme {
    fn parse_optional(value: Option<&str>) -> Result<Self, String> {
        match value.map(str::trim).filter(|v| !v.is_empty()) {
            None | Some("TRANSIT") => Ok(Self::Transit),
            Some("ETHEREUM") => Ok(Self::Ethereum),
            Some("PQC") => Ok(Self::Pqc),
            Some(_) => Err("Scheme is not supported".to_string()),
        }
    }

    fn supports_key_spec(self, key_spec: KeySpec) -> bool {
        key_spec.requires_scheme() == self
    }

    fn supports_signing_algorithm(self, signing_algorithm: SigningAlgorithm) -> bool {
        matches!(
            (self, signing_algorithm),
            (Self::Transit, SigningAlgorithm::EcdsaSha256)
                | (Self::Transit, SigningAlgorithm::EcdsaSha384)
                | (Self::Transit, SigningAlgorithm::Ed25519)
                | (Self::Transit, SigningAlgorithm::RsassaPkcs1V15Sha256)
                | (Self::Transit, SigningAlgorithm::RsassaPssSha256)
                | (Self::Ethereum, SigningAlgorithm::EthereumSecp256k1)
                | (Self::Pqc, SigningAlgorithm::MlDsa)
        )
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Transit => "TRANSIT",
            Self::Ethereum => "ETHEREUM",
            Self::Pqc => "PQC",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum KeySpec {
    Aes256Gcm96,
    EcdsaP256,
    EcdsaP384,
    Ed25519,
    Rsa4096,
    EccSecgP256k1,
    MlKem768,
    MlKem1024,
    MlDsa44,
    MlDsa65,
    MlDsa87,
}

impl KeySpec {
    fn parse(value: &str) -> Result<Self, String> {
        match value {
            "AES_256_GCM96" => Ok(Self::Aes256Gcm96),
            "ECDSA_P256" => Ok(Self::EcdsaP256),
            "ECDSA_P384" => Ok(Self::EcdsaP384),
            "ED25519" => Ok(Self::Ed25519),
            "RSA_4096" => Ok(Self::Rsa4096),
            "ECC_SECG_P256K1" => Ok(Self::EccSecgP256k1),
            "ML_KEM_768" => Ok(Self::MlKem768),
            "ML_KEM_1024" => Ok(Self::MlKem1024),
            "ML_DSA_44" => Ok(Self::MlDsa44),
            "ML_DSA_65" => Ok(Self::MlDsa65),
            "ML_DSA_87" => Ok(Self::MlDsa87),
            _ => Err("KeySpec is not supported".to_string()),
        }
    }

    fn allowed_usage(self) -> KeyUsage {
        match self {
            Self::Aes256Gcm96 => KeyUsage::EncryptDecrypt,
            Self::MlKem768 | Self::MlKem1024 => KeyUsage::KeyAgreement,
            Self::EcdsaP256
            | Self::EcdsaP384
            | Self::Ed25519
            | Self::Rsa4096
            | Self::EccSecgP256k1
            | Self::MlDsa44
            | Self::MlDsa65
            | Self::MlDsa87 => KeyUsage::SignVerify,
        }
    }

    fn requires_scheme(self) -> Scheme {
        match self {
            Self::EccSecgP256k1 => Scheme::Ethereum,
            Self::MlKem768 | Self::MlKem1024 | Self::MlDsa44 | Self::MlDsa65 | Self::MlDsa87 => {
                Scheme::Pqc
            }
            Self::Aes256Gcm96
            | Self::EcdsaP256
            | Self::EcdsaP384
            | Self::Ed25519
            | Self::Rsa4096 => Scheme::Transit,
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Aes256Gcm96 => "AES_256_GCM96",
            Self::EcdsaP256 => "ECDSA_P256",
            Self::EcdsaP384 => "ECDSA_P384",
            Self::Ed25519 => "ED25519",
            Self::Rsa4096 => "RSA_4096",
            Self::EccSecgP256k1 => "ECC_SECG_P256K1",
            Self::MlKem768 => "ML_KEM_768",
            Self::MlKem1024 => "ML_KEM_1024",
            Self::MlDsa44 => "ML_DSA_44",
            Self::MlDsa65 => "ML_DSA_65",
            Self::MlDsa87 => "ML_DSA_87",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum KeyUsage {
    EncryptDecrypt,
    KeyAgreement,
    SignVerify,
}

impl KeyUsage {
    fn parse(value: &str) -> Result<Self, String> {
        match value {
            "ENCRYPT_DECRYPT" => Ok(Self::EncryptDecrypt),
            "KEY_AGREEMENT" => Ok(Self::KeyAgreement),
            "SIGN_VERIFY" => Ok(Self::SignVerify),
            _ => Err("KeyUsage must be ENCRYPT_DECRYPT, KEY_AGREEMENT, or SIGN_VERIFY".to_string()),
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::EncryptDecrypt => "ENCRYPT_DECRYPT",
            Self::KeyAgreement => "KEY_AGREEMENT",
            Self::SignVerify => "SIGN_VERIFY",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum EncryptionAlgorithm {
    Aes256Gcm96,
}

impl EncryptionAlgorithm {
    fn parse(value: &str) -> Result<Self, String> {
        match value {
            "AES_256_GCM96" => Ok(Self::Aes256Gcm96),
            _ => Err("EncryptionAlgorithm must be AES_256_GCM96".to_string()),
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Aes256Gcm96 => "AES_256_GCM96",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SigningAlgorithm {
    EcdsaSha256,
    EcdsaSha384,
    Ed25519,
    EthereumSecp256k1,
    MlDsa,
    RsassaPkcs1V15Sha256,
    RsassaPssSha256,
}

impl SigningAlgorithm {
    fn parse(value: &str) -> Result<Self, String> {
        match value {
            "ECDSA_SHA_256" => Ok(Self::EcdsaSha256),
            "ECDSA_SHA_384" => Ok(Self::EcdsaSha384),
            "ED25519" => Ok(Self::Ed25519),
            "ETHEREUM_SECP256K1" => Ok(Self::EthereumSecp256k1),
            "ML_DSA" => Ok(Self::MlDsa),
            "RSASSA_PKCS1_V1_5_SHA_256" => Ok(Self::RsassaPkcs1V15Sha256),
            "RSASSA_PSS_SHA_256" => Ok(Self::RsassaPssSha256),
            _ => Err("SigningAlgorithm is not supported".to_string()),
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::EcdsaSha256 => "ECDSA_SHA_256",
            Self::EcdsaSha384 => "ECDSA_SHA_384",
            Self::Ed25519 => "ED25519",
            Self::EthereumSecp256k1 => "ETHEREUM_SECP256K1",
            Self::MlDsa => "ML_DSA",
            Self::RsassaPkcs1V15Sha256 => "RSASSA_PKCS1_V1_5_SHA_256",
            Self::RsassaPssSha256 => "RSASSA_PSS_SHA_256",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum MessageType {
    Raw,
    Digest,
    Eip191,
}

impl MessageType {
    fn parse(value: &str) -> Result<Self, String> {
        match value {
            "RAW" => Ok(Self::Raw),
            "DIGEST" => Ok(Self::Digest),
            "EIP191" => Ok(Self::Eip191),
            _ => Err("MessageType must be RAW, DIGEST, or EIP191".to_string()),
        }
    }

    fn allowed_for(self, signing_algorithm: SigningAlgorithm) -> bool {
        match (self, signing_algorithm) {
            (Self::Raw, _) => true,
            (Self::Digest, SigningAlgorithm::MlDsa) => false,
            (Self::Digest, _) => true,
            (Self::Eip191, _) => Scheme::Ethereum.supports_signing_algorithm(signing_algorithm),
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Raw => "RAW",
            Self::Digest => "DIGEST",
            Self::Eip191 => "EIP191",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DataKeySpec {
    Aes128,
    Aes256,
}

impl DataKeySpec {
    fn parse(value: &str) -> Result<Self, String> {
        match value {
            "AES_128" => Ok(Self::Aes128),
            "AES_256" => Ok(Self::Aes256),
            _ => Err("DataKeySpec must be AES_128 or AES_256".to_string()),
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Aes128 => "AES_128",
            Self::Aes256 => "AES_256",
        }
    }
}

const MAX_ALIAS_LEN: usize = 128;
const KEY_ID_PREFIX: &str = "kms:";
const EXPERIMENTAL_TAG: &str = "experimental";
const ML_KEM_DISABLED: &str = "ML-KEM is temporarily disabled";
const MAX_KEY_STORE_NAME_LEN: usize = 256;

#[derive(Clone)]
pub struct KeyStoreSecret(Box<RawValue>);

impl KeyStoreSecret {
    pub fn as_json_str(&self) -> &str {
        self.0.get()
    }

    pub fn from_json_string(value: String) -> Result<Self, String> {
        let raw = RawValue::from_string(value).map_err(|_| "Secret must be valid JSON")?;
        Self::from_raw(raw)
    }

    fn from_raw(raw: Box<RawValue>) -> Result<Self, String> {
        if !raw.get().trim_start().starts_with('{') {
            return Err("Secret must be a JSON object".to_string());
        }
        Ok(Self(raw))
    }
}

impl<'de> Deserialize<'de> for KeyStoreSecret {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = Box::<RawValue>::deserialize(deserializer)?;
        Self::from_raw(raw).map_err(de::Error::custom)
    }
}

impl Serialize for KeyStoreSecret {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.0.serialize(serializer)
    }
}

#[derive(Clone, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(rename_all = "PascalCase")]
pub struct KeyStorePutRequest {
    pub name: String,
    pub secret: KeyStoreSecret,
}

impl fmt::Debug for KeyStorePutRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KeyStorePutRequest")
            .field("name", &self.name)
            .field("secret", &"<redacted>")
            .finish()
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(rename_all = "PascalCase")]
pub struct KeyStoreGetRequest {
    pub name: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(rename_all = "PascalCase")]
pub struct KeyStoreListRequest {
    #[serde(default)]
    pub prefix: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(rename_all = "PascalCase")]
pub struct KeyStoreDeleteRequest {
    pub name: String,
}

#[derive(Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "PascalCase")]
pub struct KeyStorePutResponse {
    pub name: String,
    pub version: u32,
}

#[derive(Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "PascalCase")]
pub struct KeyStoreGetResponse {
    pub name: String,
    pub secret: KeyStoreSecret,
}

#[derive(Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "PascalCase")]
pub struct KeyStoreListResponse {
    pub names: Vec<String>,
}

#[derive(Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "PascalCase")]
pub struct KeyStoreDeleteResponse {
    pub name: String,
}

pub struct KmsValidation;
impl KmsValidation {
    pub fn validate_encrypt(req: &EncryptRequest) -> Result<(), String> {
        validate_key_reference("KeyId", &req.key_id)?;
        validate_required("Plaintext", &req.plaintext)?;

        if let Some(algorithm) = req.encryption_algorithm.as_ref() {
            validate_encryption_algorithm(algorithm)?;
        }
        Ok(())
    }

    pub fn validate_decrypt(req: &DecryptRequest) -> Result<(), String> {
        validate_required("CiphertextBlob", &req.ciphertext_blob)?;
        if let Some(key_id) = req.key_id.as_ref() {
            validate_key_reference("KeyId", key_id)?;
        }
        if let Some(algorithm) = req.encryption_algorithm.as_ref() {
            validate_encryption_algorithm(algorithm)?;
        }
        Ok(())
    }

    pub fn validate_sign(req: &SignRequest) -> Result<(), String> {
        validate_key_reference("KeyId", &req.key_id)?;
        validate_required("Message", &req.message)?;
        let signing_algorithm = validate_signing_algorithm(&req.signing_algorithm)?;
        if let Some(message_type) = req.message_type.as_ref() {
            let message_type = MessageType::parse(message_type)?;
            if !message_type.allowed_for(signing_algorithm) {
                return Err(format!(
                    "MessageType {} is not supported for SigningAlgorithm {}",
                    message_type.as_str(),
                    signing_algorithm.as_str()
                ));
            }
        }
        Ok(())
    }

    pub fn validate_encapsulate(req: &EncapsulateRequest) -> Result<(), String> {
        validate_key_reference("KeyId", &req.key_id)?;
        Err(ML_KEM_DISABLED.to_string())
    }

    pub fn validate_decapsulate(req: &DecapsulateRequest) -> Result<(), String> {
        validate_key_reference("KeyId", &req.key_id)?;
        validate_required("Ciphertext", &req.ciphertext)?;
        Err(ML_KEM_DISABLED.to_string())
    }

    pub fn validate_create_key(req: &CreateKeyRequest) -> Result<(), String> {
        let scheme = Scheme::parse_optional(req.scheme.as_deref())?;
        let key_spec = validate_key_spec(&req.key_spec, scheme)?;
        if matches!(key_spec, KeySpec::MlKem768 | KeySpec::MlKem1024) {
            return Err(ML_KEM_DISABLED.to_string());
        }
        let key_usage = validate_key_usage(&req.key_usage)?;

        validate_required("Alias", &req.alias)?;
        validate_alias(&req.alias)?;

        if key_usage != key_spec.allowed_usage() {
            return Err(match (scheme, key_spec) {
                (_, KeySpec::Aes256Gcm96) => {
                    "AES_256_GCM96 keys must use ENCRYPT_DECRYPT".to_string()
                }
                (_, KeySpec::MlKem768 | KeySpec::MlKem1024) => {
                    "PQC ML-KEM keys must use KEY_AGREEMENT".to_string()
                }
                (Scheme::Ethereum, _) => "ETHEREUM keys must use SIGN_VERIFY".to_string(),
                (Scheme::Pqc, _) => "PQC keys must use SIGN_VERIFY".to_string(),
                (Scheme::Transit, _) => "Asymmetric KMS keys must use SIGN_VERIFY".to_string(),
            });
        }

        for tag in &req.tags {
            validate_required("TagKey", &tag.tag_key)?;
        }
        Ok(())
    }

    pub fn validate_generate_data_key(req: &GenerateDataKeyRequest) -> Result<(), String> {
        validate_key_reference("KeyId", &req.key_id)?;
        let has_spec = req
            .data_key_spec
            .as_ref()
            .map(|s| !s.trim().is_empty())
            .unwrap_or(false);
        let has_size = req.number_of_bytes.is_some();
        if has_spec == has_size {
            return Err("Exactly one of DataKeySpec or NumberOfBytes must be provided".to_string());
        }
        if let Some(spec) = req.data_key_spec.as_ref() {
            DataKeySpec::parse(spec)?;
        }
        if let Some(bytes) = req.number_of_bytes
            && bytes == 0
        {
            return Err("NumberOfBytes must be greater than 0".to_string());
        }
        Ok(())
    }

    pub fn validate_get_key_metadata(req: &GetKeyMetadataRequest) -> Result<(), String> {
        validate_key_reference("KeyId", &req.key_id)
    }

    pub fn validate_get_public_key(req: &GetPublicKeyRequest) -> Result<(), String> {
        validate_key_reference("KeyId", &req.key_id)?;
        if let Some(version) = req.version
            && version == 0
        {
            return Err("Version must be greater than 0".to_string());
        }
        Ok(())
    }

    pub fn validate_rotate_key(req: &RotateKeyRequest) -> Result<(), String> {
        validate_key_reference("KeyId", &req.key_id)
    }

    pub fn validate_key_store_put(req: &KeyStorePutRequest) -> Result<(), String> {
        validate_key_store_name("Name", &req.name)
    }

    pub fn validate_key_store_get(req: &KeyStoreGetRequest) -> Result<(), String> {
        validate_key_store_name("Name", &req.name)
    }

    pub fn validate_key_store_list(req: &KeyStoreListRequest) -> Result<(), String> {
        if let Some(prefix) = req.prefix.as_ref() {
            validate_key_store_prefix("Prefix", prefix)?;
        }
        Ok(())
    }

    pub fn validate_key_store_delete(req: &KeyStoreDeleteRequest) -> Result<(), String> {
        validate_key_store_name("Name", &req.name)
    }

    pub fn get_capabilities() -> GetCapabilitiesResponse {
        GetCapabilitiesResponse {
            schemes: vec![
                transit_capability(),
                ethereum_capability(),
                pqc_capability(),
            ],
        }
    }
}

fn transit_capability() -> SchemeCapability {
    SchemeCapability {
        scheme: Scheme::Transit.as_str().to_string(),
        key_specs: vec![
            KeySpec::Aes256Gcm96,
            KeySpec::EcdsaP256,
            KeySpec::EcdsaP384,
            KeySpec::Ed25519,
            KeySpec::Rsa4096,
        ]
        .into_iter()
        .map(|spec| spec.as_str().to_string())
        .collect(),
        key_usages: vec![KeyUsage::EncryptDecrypt, KeyUsage::SignVerify]
            .into_iter()
            .map(|usage| usage.as_str().to_string())
            .collect(),
        encryption_algorithms: vec![EncryptionAlgorithm::Aes256Gcm96.as_str().to_string()],
        data_key_specs: vec![DataKeySpec::Aes128, DataKeySpec::Aes256]
            .into_iter()
            .map(|spec| spec.as_str().to_string())
            .collect(),
        signing_capabilities: vec![
            signing_capability(
                SigningAlgorithm::EcdsaSha256,
                &[MessageType::Raw, MessageType::Digest],
                &[],
            ),
            signing_capability(
                SigningAlgorithm::EcdsaSha384,
                &[MessageType::Raw, MessageType::Digest],
                &[],
            ),
            signing_capability(
                SigningAlgorithm::Ed25519,
                &[MessageType::Raw, MessageType::Digest],
                &[],
            ),
            signing_capability(
                SigningAlgorithm::RsassaPkcs1V15Sha256,
                &[MessageType::Raw, MessageType::Digest],
                &[],
            ),
            signing_capability(
                SigningAlgorithm::RsassaPssSha256,
                &[MessageType::Raw, MessageType::Digest],
                &[],
            ),
        ],
        supports_encrypt: true,
        supports_decrypt: true,
        supports_generate_data_key: true,
        supports_rotate_key: true,
        key_agreement_capabilities: vec![],
        supports_encapsulate: false,
        supports_decapsulate: false,
        tags: vec![],
    }
}

fn ethereum_capability() -> SchemeCapability {
    SchemeCapability {
        scheme: Scheme::Ethereum.as_str().to_string(),
        key_specs: vec![KeySpec::EccSecgP256k1.as_str().to_string()],
        key_usages: vec![KeyUsage::SignVerify.as_str().to_string()],
        encryption_algorithms: vec![],
        data_key_specs: vec![],
        signing_capabilities: vec![signing_capability(
            SigningAlgorithm::EthereumSecp256k1,
            &[MessageType::Raw, MessageType::Digest, MessageType::Eip191],
            &[],
        )],
        supports_encrypt: false,
        supports_decrypt: false,
        supports_generate_data_key: false,
        supports_rotate_key: false,
        key_agreement_capabilities: vec![],
        supports_encapsulate: false,
        supports_decapsulate: false,
        tags: vec![],
    }
}

fn pqc_capability() -> SchemeCapability {
    SchemeCapability {
        scheme: Scheme::Pqc.as_str().to_string(),
        key_specs: vec![KeySpec::MlDsa44, KeySpec::MlDsa65, KeySpec::MlDsa87]
            .into_iter()
            .map(|spec| spec.as_str().to_string())
            .collect(),
        key_usages: vec![KeyUsage::SignVerify.as_str().to_string()],
        encryption_algorithms: vec![],
        data_key_specs: vec![],
        signing_capabilities: vec![signing_capability(
            SigningAlgorithm::MlDsa,
            &[MessageType::Raw],
            &[EXPERIMENTAL_TAG],
        )],
        supports_encrypt: false,
        supports_decrypt: false,
        supports_generate_data_key: false,
        supports_rotate_key: false,
        key_agreement_capabilities: vec![],
        supports_encapsulate: false,
        supports_decapsulate: false,
        tags: capability_tags(&[EXPERIMENTAL_TAG]),
    }
}

fn signing_capability(
    signing_algorithm: SigningAlgorithm,
    message_types: &[MessageType],
    tags: &[&str],
) -> SigningCapability {
    SigningCapability {
        signing_algorithm: signing_algorithm.as_str().to_string(),
        message_types: message_types
            .iter()
            .map(|message_type| message_type.as_str().to_string())
            .collect(),
        tags: capability_tags(tags),
    }
}

fn capability_tags(tags: &[&str]) -> Vec<String> {
    tags.iter().map(|tag| (*tag).to_string()).collect()
}

fn validate_required(field_name: &str, value: &str) -> Result<(), String> {
    if value.trim().is_empty() {
        return Err(format!("{field_name} is required"));
    }
    Ok(())
}

fn validate_key_spec(value: &str, scheme: Scheme) -> Result<KeySpec, String> {
    let key_spec = KeySpec::parse(value).map_err(|_| match scheme {
        Scheme::Transit => "KeySpec is not supported".to_string(),
        Scheme::Ethereum => "ETHEREUM keys must use ECC_SECG_P256K1".to_string(),
        Scheme::Pqc => "PQC keys must use ML_DSA_44, ML_DSA_65, or ML_DSA_87".to_string(),
    })?;

    if scheme.supports_key_spec(key_spec) {
        Ok(key_spec)
    } else {
        Err(match scheme {
            Scheme::Transit => "KeySpec is not supported".to_string(),
            Scheme::Ethereum => "ETHEREUM keys must use ECC_SECG_P256K1".to_string(),
            Scheme::Pqc => "PQC keys must use ML_DSA_44, ML_DSA_65, or ML_DSA_87".to_string(),
        })
    }
}

fn validate_key_usage(value: &str) -> Result<KeyUsage, String> {
    KeyUsage::parse(value)
}

fn validate_encryption_algorithm(value: &str) -> Result<EncryptionAlgorithm, String> {
    EncryptionAlgorithm::parse(value)
}

fn validate_signing_algorithm(value: &str) -> Result<SigningAlgorithm, String> {
    SigningAlgorithm::parse(value)
}

fn validate_alias(value: &str) -> Result<(), String> {
    let trimmed = value.trim();
    if trimmed.len() > MAX_ALIAS_LEN {
        return Err(format!("alias must be at most {MAX_ALIAS_LEN} characters"));
    }
    if trimmed.starts_with(KEY_ID_PREFIX) {
        return Err("alias must not use the reserved kms:<alias> format".to_string());
    }
    if !trimmed
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '.'))
    {
        return Err("alias contains unsupported characters".to_string());
    }
    Ok(())
}

fn validate_key_store_name(field_name: &str, value: &str) -> Result<(), String> {
    let trimmed = value.trim();
    validate_required(field_name, trimmed)?;
    if trimmed.len() > MAX_KEY_STORE_NAME_LEN {
        return Err(format!(
            "{field_name} must be at most {MAX_KEY_STORE_NAME_LEN} characters"
        ));
    }
    if trimmed.starts_with('/') || trimmed.ends_with('/') {
        return Err(format!("{field_name} must not start or end with /"));
    }
    for segment in trimmed.split('/') {
        validate_key_store_segment(field_name, segment)?;
    }
    Ok(())
}

fn validate_key_store_prefix(field_name: &str, value: &str) -> Result<(), String> {
    let trimmed = value.trim().trim_matches('/');
    if trimmed.is_empty() {
        return Ok(());
    }
    if trimmed.len() > MAX_KEY_STORE_NAME_LEN {
        return Err(format!(
            "{field_name} must be at most {MAX_KEY_STORE_NAME_LEN} characters"
        ));
    }
    for segment in trimmed.split('/') {
        validate_key_store_segment(field_name, segment)?;
    }
    Ok(())
}

fn validate_key_store_segment(field_name: &str, segment: &str) -> Result<(), String> {
    if segment.is_empty() || matches!(segment, "." | "..") {
        return Err(format!("{field_name} contains an invalid path segment"));
    }
    if !segment
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
    {
        return Err(format!("{field_name} contains unsupported characters"));
    }
    Ok(())
}

fn validate_key_reference(field_name: &str, value: &str) -> Result<(), String> {
    validate_required(field_name, value)?;
    let trimmed = value.trim();
    let alias = trimmed.strip_prefix(KEY_ID_PREFIX).unwrap_or(trimmed);
    if alias.is_empty() {
        return Err(format!("{field_name} is required"));
    }
    validate_alias(alias)
}

impl schemars::JsonSchema for KeyStoreSecret {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        "KeyStoreSecret".into()
    }
    fn json_schema(_: &mut schemars::SchemaGenerator) -> schemars::Schema {
        schemars::json_schema!({"type":"object","additionalProperties":true})
    }
}

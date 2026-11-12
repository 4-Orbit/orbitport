//! 4Orbit: the verified agent identity reaches the KMS and policy plugins as
//! gateway-set metadata, and policy.* methods are forwarded with tenancy from
//! the Hold, never from params.

use std::sync::{Arc, Mutex};

use gateway::{
    caller::{Caller, MD_AGENT_ID, MD_JTI_HASH, hash_jti},
    plugins::PluginCatalog,
    proto::plugins::{
        kms::{
            kms_plugin_server::{KmsPlugin, KmsPluginServer},
            *,
        },
        policy::{
            CallRequest, CallResponse, GetActiveRequest, GetActiveResponse, RecordAuditRequest,
            RecordAuditResponse,
            policy_plugin_server::{PolicyPlugin, PolicyPluginServer},
        },
    },
    services::{jrpc::JsonRpcRequest, threshold::ThresholdGroupRegistry},
};
use tokio::net::TcpListener;
use tokio_stream::wrappers::TcpListenerStream;
use tonic::{Request, Response, Status, transport::Server};

#[derive(Default, Clone)]
struct Seen {
    agent: Arc<Mutex<Vec<Option<String>>>>,
    jti: Arc<Mutex<Vec<Option<String>>>>,
    tenant: Arc<Mutex<Vec<String>>>,
}

impl Seen {
    fn record<T>(&self, req: &Request<T>, tenant: &str) {
        let md = req.metadata();
        self.agent
            .lock()
            .unwrap()
            .push(md.get(MD_AGENT_ID).map(|v| v.to_str().unwrap().to_string()));
        self.jti
            .lock()
            .unwrap()
            .push(md.get(MD_JTI_HASH).map(|v| v.to_str().unwrap().to_string()));
        self.tenant.lock().unwrap().push(tenant.to_string());
    }
}

struct MockKms(Seen);

#[tonic::async_trait]
impl KmsPlugin for MockKms {
    async fn encrypt(
        &self,
        req: Request<EncryptRequest>,
    ) -> Result<Response<EncryptResponse>, Status> {
        let tenant = req.get_ref().client_id.clone();
        self.0.record(&req, &tenant);
        Ok(Response::new(EncryptResponse {
            ciphertext_blob: "blob".into(),
            key_id: req.get_ref().key_id.clone(),
            encryption_algorithm: "AES_256_GCM96".into(),
        }))
    }

    async fn list_keys(
        &self,
        req: Request<ListKeysRequest>,
    ) -> Result<Response<ListKeysResponse>, Status> {
        let tenant = req.get_ref().client_id.clone();
        self.0.record(&req, &tenant);
        Ok(Response::new(ListKeysResponse {
            keys: vec![KeyMetadata {
                key_id: "kms:dev-key".into(),
                alias: "dev-key".into(),
                key_spec: "AES_256_GCM96".into(),
                tags: vec![Tag {
                    tag_key: "env".into(),
                    tag_value: "dev".into(),
                }],
                ..Default::default()
            }],
            truncated: false,
        }))
    }

    async fn decrypt(
        &self,
        _: Request<DecryptRequest>,
    ) -> Result<Response<DecryptResponse>, Status> {
        Err(Status::unimplemented("not used"))
    }
    async fn sign(&self, _: Request<SignRequest>) -> Result<Response<SignResponse>, Status> {
        Err(Status::unimplemented("not used"))
    }
    async fn encapsulate(
        &self,
        _: Request<EncapsulateRequest>,
    ) -> Result<Response<EncapsulateResponse>, Status> {
        Err(Status::unimplemented("not used"))
    }
    async fn decapsulate(
        &self,
        _: Request<DecapsulateRequest>,
    ) -> Result<Response<DecapsulateResponse>, Status> {
        Err(Status::unimplemented("not used"))
    }
    async fn create_key(
        &self,
        _: Request<CreateKeyRequest>,
    ) -> Result<Response<CreateKeyResponse>, Status> {
        Err(Status::unimplemented("not used"))
    }
    async fn get_key_metadata(
        &self,
        _: Request<GetKeyMetadataRequest>,
    ) -> Result<Response<GetKeyMetadataResponse>, Status> {
        Err(Status::unimplemented("not used"))
    }
    async fn get_public_key(
        &self,
        _: Request<GetPublicKeyRequest>,
    ) -> Result<Response<GetPublicKeyResponse>, Status> {
        Err(Status::unimplemented("not used"))
    }
    async fn generate_data_key(
        &self,
        _: Request<GenerateDataKeyRequest>,
    ) -> Result<Response<GenerateDataKeyResponse>, Status> {
        Err(Status::unimplemented("not used"))
    }
    async fn rotate_key(
        &self,
        _: Request<RotateKeyRequest>,
    ) -> Result<Response<RotateKeyResponse>, Status> {
        Err(Status::unimplemented("not used"))
    }
    async fn key_store_put(
        &self,
        _: Request<KeyStorePutRequest>,
    ) -> Result<Response<KeyStorePutResponse>, Status> {
        Err(Status::unimplemented("not used"))
    }
    async fn key_store_get(
        &self,
        _: Request<KeyStoreGetRequest>,
    ) -> Result<Response<KeyStoreGetResponse>, Status> {
        Err(Status::unimplemented("not used"))
    }
    async fn key_store_list(
        &self,
        _: Request<KeyStoreListRequest>,
    ) -> Result<Response<KeyStoreListResponse>, Status> {
        Err(Status::unimplemented("not used"))
    }
    async fn key_store_delete(
        &self,
        _: Request<KeyStoreDeleteRequest>,
    ) -> Result<Response<KeyStoreDeleteResponse>, Status> {
        Err(Status::unimplemented("not used"))
    }
}

#[derive(Clone, Default)]
struct MockPolicy {
    calls: Arc<Mutex<Vec<CallRequest>>>,
}

#[tonic::async_trait]
impl PolicyPlugin for MockPolicy {
    async fn call(&self, req: Request<CallRequest>) -> Result<Response<CallResponse>, Status> {
        let inner = req.into_inner();
        self.calls.lock().unwrap().push(inner.clone());
        Ok(Response::new(CallResponse {
            result_json: r#"{"ok":true}"#.into(),
        }))
    }
    async fn get_active(
        &self,
        _: Request<GetActiveRequest>,
    ) -> Result<Response<GetActiveResponse>, Status> {
        Err(Status::unimplemented("not used"))
    }
    async fn record_audit(
        &self,
        _: Request<RecordAuditRequest>,
    ) -> Result<Response<RecordAuditResponse>, Status> {
        Err(Status::unimplemented("not used"))
    }
}

async fn serve_kms(seen: Seen) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        Server::builder()
            .add_service(KmsPluginServer::new(MockKms(seen)))
            .serve_with_incoming(TcpListenerStream::new(listener))
            .await
            .ok();
    });
    format!("http://{addr}")
}

async fn serve_policy(policy: MockPolicy) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        Server::builder()
            .add_service(PolicyPluginServer::new(policy))
            .serve_with_incoming(TcpListenerStream::new(listener))
            .await
            .ok();
    });
    format!("http://{addr}")
}

fn catalog(kms: &str, policy: Option<&str>) -> PluginCatalog {
    PluginCatalog::new(
        "http://127.0.0.1:1",
        None,
        kms,
        None,
        None,
        false,
        "",
        ThresholdGroupRegistry::default(),
    )
    .with_policy(policy)
}

fn rpc(method: &str, params: serde_json::Value) -> JsonRpcRequest {
    serde_json::from_value(
        serde_json::json!({"jsonrpc":"2.0","id":7,"method":method,"params":params}),
    )
    .unwrap()
}

fn agent_caller() -> Caller {
    Caller {
        tenant: "tenant-from-hold".into(),
        agent_id: "developer-agent".into(),
        jti_hash: hash_jti("jti-1"),
        subject: "acct-1".into(),
        token_kms_tenant: String::new(),
    }
}

#[tokio::test]
async fn kms_calls_carry_the_verified_agent_identity() {
    let seen = Seen::default();
    let cat = catalog(&serve_kms(seen.clone()).await, None);

    let req = rpc(
        "kms.Encrypt",
        serde_json::json!({"KeyId":"kms:dev-key","Plaintext":"aGVsbG8="}),
    );
    req.call.validate().unwrap();
    req.call.execute_as(7, &agent_caller(), &cat).await.unwrap();

    // Account principal: no agent metadata at all.
    let req = rpc(
        "kms.Encrypt",
        serde_json::json!({"KeyId":"kms:dev-key","Plaintext":"aGVsbG8="}),
    );
    req.call.execute(8, "tenant-from-hold", &cat).await.unwrap();

    let agents = seen.agent.lock().unwrap().clone();
    assert_eq!(
        agents,
        vec![Some("developer-agent".to_string()), None],
        "agent id forwarded only for agent callers"
    );
    assert_eq!(
        seen.jti.lock().unwrap()[0].as_deref(),
        Some(hash_jti("jti-1").as_str())
    );
    assert!(
        seen.tenant
            .lock()
            .unwrap()
            .iter()
            .all(|t| t == "tenant-from-hold")
    );
}

#[tokio::test]
async fn policy_methods_forward_identity_and_params() {
    let policy = MockPolicy::default();
    let cat = catalog(
        "http://127.0.0.1:1",
        Some(&serve_policy(policy.clone()).await),
    );

    let req = rpc("policy.Simulate", serde_json::json!({"requests": []}));
    req.call.validate().unwrap();
    assert_eq!(req.call.operation(), "policy.Simulate");
    let raw = req.call.execute_as(7, &agent_caller(), &cat).await.unwrap();
    let body: serde_json::Value = serde_json::from_str(raw.get()).unwrap();
    assert_eq!(body["result"]["ok"], true);

    let calls = policy.calls.lock().unwrap();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].method, "policy.Simulate");
    assert_eq!(calls[0].kms_tenant, "tenant-from-hold");
    assert_eq!(calls[0].agent_id, "developer-agent");
    assert_eq!(calls[0].params_json, r#"{"requests":[]}"#);
}

#[tokio::test]
async fn policy_list_keys_goes_to_the_kms_plugin_as_the_caller() {
    let seen = Seen::default();
    let cat = catalog(&serve_kms(seen.clone()).await, None);
    let req = rpc("policy.ListKeys", serde_json::json!({}));
    let raw = req.call.execute(7, "tenant-from-hold", &cat).await.unwrap();
    let body: serde_json::Value = serde_json::from_str(raw.get()).unwrap();
    assert_eq!(body["result"]["keys"][0]["alias"], "dev-key");
    assert_eq!(body["result"]["keys"][0]["tags"][0]["key"], "env");
}

#[tokio::test]
async fn policy_methods_fail_closed_without_a_policy_plugin() {
    let cat = catalog("http://127.0.0.1:1", None);
    let req = rpc("policy.GetSchema", serde_json::json!({}));
    let err = req.call.execute(7, "tenant", &cat).await.unwrap_err();
    assert_eq!(err.code(), tonic::Code::Unavailable);
}

#[tokio::test]
async fn agents_cannot_mint_tokens_even_before_the_policy_plugin() {
    let cat = catalog("http://127.0.0.1:1", None);
    let req = rpc(
        "policy.IssueAgentToken",
        serde_json::json!({"agentId":"security-agent"}),
    );
    let err = req
        .call
        .execute_as(7, &agent_caller(), &cat)
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::PermissionDenied);
}

#[test]
fn unknown_policy_methods_are_rejected_at_parse_time() {
    let res: Result<JsonRpcRequest, _> = serde_json::from_value(
        serde_json::json!({"jsonrpc":"2.0","id":1,"method":"policy.DeleteEverything","params":{}}),
    );
    assert!(res.is_err());
}

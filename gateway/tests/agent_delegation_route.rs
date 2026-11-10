use std::{
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicU32, Ordering},
    },
};

use gateway::{
    agent_delegation::{AgentCredentialStore, AgentScope, Clock, DelegationError, issue_route},
    proto::plugins::auth::{
        ServiceTokenValidationRequest, ServiceTokenValidationResponse, TokenValidationRequest,
        TokenValidationResponse,
        auth_plugin_client::AuthPluginClient,
        auth_plugin_server::{AuthPlugin, AuthPluginServer},
    },
    types::GatewayError,
};
use tokio::net::TcpListener;
use tokio_stream::wrappers::TcpListenerStream;
use tonic::{Request, Response, Status, transport::Server};
use warp::http::{StatusCode, header::CACHE_CONTROL};

struct FixedClock;

impl Clock for FixedClock {
    fn now_epoch_seconds(&self) -> Result<i64, DelegationError> {
        Ok(1_700_000_000)
    }
}

struct MockAuth {
    calls: Arc<AtomicU32>,
}

#[tonic::async_trait]
impl AuthPlugin for MockAuth {
    async fn validate_token(
        &self,
        _: Request<TokenValidationRequest>,
    ) -> Result<Response<TokenValidationResponse>, Status> {
        Err(Status::unimplemented("customer authentication is not used"))
    }

    async fn validate_service_token(
        &self,
        request: Request<ServiceTokenValidationRequest>,
    ) -> Result<Response<ServiceTokenValidationResponse>, Status> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let request = request.into_inner();
        assert_eq!(request.required_scopes, ["agent:delegate"]);
        if request.token != "authorized-service-token" {
            return Err(Status::permission_denied("service token lacks scope"));
        }
        Ok(Response::new(ServiceTokenValidationResponse {
            ok: true,
            client_id: "trusted-issuer".into(),
        }))
    }
}

async fn mock_auth() -> (AuthPluginClient<tonic::transport::Channel>, Arc<AtomicU32>) {
    let calls = Arc::new(AtomicU32::new(0));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address: SocketAddr = listener.local_addr().unwrap();
    let plugin = MockAuth {
        calls: calls.clone(),
    };
    tokio::spawn(async move {
        Server::builder()
            .add_service(AuthPluginServer::new(plugin))
            .serve_with_incoming(TcpListenerStream::new(listener))
            .await
            .ok();
    });
    let client = AuthPluginClient::connect(format!("http://{address}"))
        .await
        .unwrap();
    (client, calls)
}

fn body() -> serde_json::Value {
    serde_json::json!({
        "accountId": "test-account",
        "agentId": "developer-agent",
        "action": "github:create-issue",
        "resource": "4-Orbit/test-repo",
        "ttlSeconds": 60
    })
}

#[tokio::test]
async fn only_authorized_internal_service_can_issue_a_scoped_credential() {
    let (auth_client, calls) = mock_auth().await;
    let store = AgentCredentialStore::new(Arc::new(FixedClock));
    let route = issue_route(store.clone(), auth_client);

    let missing = warp::test::request()
        .method("POST")
        .path("/internal/agent/credentials")
        .json(&body())
        .filter(&route)
        .await
        .unwrap_err();
    assert!(matches!(
        missing.find::<GatewayError>(),
        Some(GatewayError::NoAuthHeaderError)
    ));
    assert_eq!(calls.load(Ordering::SeqCst), 0);

    let unauthorized = warp::test::request()
        .method("POST")
        .path("/internal/agent/credentials")
        .header("authorization", "Bearer missing-scope-token")
        .json(&body())
        .filter(&route)
        .await
        .unwrap_err();
    assert!(matches!(
        unauthorized.find::<GatewayError>(),
        Some(GatewayError::ServiceAuthorizationDenied)
    ));
    assert_eq!(calls.load(Ordering::SeqCst), 1);

    let response = warp::test::request()
        .method("POST")
        .path("/internal/agent/credentials")
        .header("authorization", "Bearer authorized-service-token")
        .json(&body())
        .reply(&route)
        .await;
    assert_eq!(response.status(), StatusCode::CREATED);
    assert_eq!(response.headers().get(CACHE_CONTROL).unwrap(), "no-store");
    let issued: serde_json::Value = serde_json::from_slice(response.body()).unwrap();
    let token = issued["token"].as_str().unwrap();
    assert_eq!(issued["expiresAt"], 1_700_000_060);
    assert_eq!(
        store.authenticate(token, "github:create-issue", "4-Orbit/test-repo"),
        Ok(AgentScope {
            account_id: "test-account".into(),
            agent_id: "developer-agent".into(),
            action: "github:create-issue".into(),
            resource: "4-Orbit/test-repo".into(),
        })
    );
}

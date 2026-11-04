//! Route-level tests for the account-plugin credit-gating filter. The auth
//! filter is short-circuited with a synthetic `AuthContext` so these exercise
//! `with_account_hold` in isolation.

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::net::TcpListener;
use tokio_stream::wrappers::TcpListenerStream;
use tonic::transport::{Channel, Server};
use tonic::{Request, Response, Status};
use warp::{Filter, Rejection, Reply, http::StatusCode};

use gateway::filters::{
    AuthContext, AuthContextWithHold, account_hold, account_release, with_account_hold,
};
use gateway::proto::plugins::account::{
    HoldRequest, HoldResponse, ReleaseRequest, ReleaseResponse, SettleRequest, SettleResponse,
    account_plugin_client::AccountPluginClient,
    account_plugin_server::{AccountPlugin, AccountPluginServer},
};
use gateway::types::GatewayError;

#[derive(Clone, Copy, Debug)]
enum HoldBehavior {
    Ok,
    Insufficient,
    /// Dashboard 404 — unknown or revoked credential. The PAT revocation path.
    Revoked,
    /// Hold succeeds but resolves no tenancy, e.g. a dashboard predating the
    /// field.
    OkNoTenant,
    /// Suspended account.
    Inactive,
}

struct MockAccountPlugin {
    hold_calls: Arc<AtomicU32>,
    release_calls: Arc<AtomicU32>,
    /// (client_id, jti, operation) of the last Hold.
    last_hold: Arc<Mutex<(String, String, String)>>,
    behavior: HoldBehavior,
}

#[tonic::async_trait]
impl AccountPlugin for MockAccountPlugin {
    async fn hold(&self, req: Request<HoldRequest>) -> Result<Response<HoldResponse>, Status> {
        self.hold_calls.fetch_add(1, Ordering::SeqCst);
        {
            let body = req.into_inner();
            *self.last_hold.lock().unwrap() = (body.client_id, body.jti, body.operation);
        }
        match self.behavior {
            HoldBehavior::Ok => Ok(Response::new(HoldResponse {
                ok: true,
                ledger_id: "ledger-warp".to_string(),
                balance_after: 99,
                error: String::new(),
                kms_tenant: "tenant-from-db".to_string(),
            })),
            HoldBehavior::OkNoTenant => Ok(Response::new(HoldResponse {
                ok: true,
                ledger_id: "ledger-warp".to_string(),
                balance_after: 99,
                error: String::new(),
                kms_tenant: String::new(),
            })),
            HoldBehavior::Insufficient => Err(Status::failed_precondition("insufficient_credits")),
            HoldBehavior::Inactive => Err(Status::permission_denied("account_inactive")),
            HoldBehavior::Revoked => {
                Err(Status::permission_denied("Unknown or revoked credential"))
            }
        }
    }

    async fn release(
        &self,
        _req: Request<ReleaseRequest>,
    ) -> Result<Response<ReleaseResponse>, Status> {
        self.release_calls.fetch_add(1, Ordering::SeqCst);
        Ok(Response::new(ReleaseResponse {
            ok: true,
            balance_after: 100,
            error: String::new(),
        }))
    }

    async fn settle(
        &self,
        _req: Request<SettleRequest>,
    ) -> Result<Response<SettleResponse>, Status> {
        Ok(Response::new(SettleResponse {
            ok: true,
            balance_after: 99,
            error: String::new(),
        }))
    }
}

async fn start_mock_plugin(behavior: HoldBehavior) -> (SocketAddr, Arc<AtomicU32>, Arc<AtomicU32>) {
    let (addr, hold_calls, release_calls, _) = start_mock_plugin_capturing(behavior).await;
    (addr, hold_calls, release_calls)
}

async fn start_mock_plugin_capturing(
    behavior: HoldBehavior,
) -> (
    SocketAddr,
    Arc<AtomicU32>,
    Arc<AtomicU32>,
    Arc<Mutex<(String, String, String)>>,
) {
    let hold_calls = Arc::new(AtomicU32::new(0));
    let release_calls = Arc::new(AtomicU32::new(0));
    let last_hold = Arc::new(Mutex::new((String::new(), String::new(), String::new())));
    let plugin = MockAccountPlugin {
        hold_calls: hold_calls.clone(),
        release_calls: release_calls.clone(),
        last_hold: last_hold.clone(),
        behavior,
    };

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        Server::builder()
            .add_service(AccountPluginServer::new(plugin))
            .serve_with_incoming(TcpListenerStream::new(listener))
            .await
            .ok();
    });

    tokio::time::sleep(Duration::from_millis(50)).await;
    (addr, hold_calls, release_calls, last_hold)
}

async fn connect(addr: SocketAddr) -> AccountPluginClient<Channel> {
    AccountPluginClient::connect(format!("http://{addr}"))
        .await
        .unwrap()
}

/// Stand-in auth filter producing a fixed AuthContext, bypassing JWT validation.
fn synthetic_auth() -> impl Filter<Extract = (AuthContext,), Error = Rejection> + Clone {
    synthetic_auth_as("client-warp", "jti-warp")
}

/// Same, with a caller-chosen client_id/jti.
fn synthetic_auth_as(
    client_id: &str,
    jti: &str,
) -> impl Filter<Extract = (AuthContext,), Error = Rejection> + Clone {
    synthetic_auth_claiming(client_id, jti, "")
}

/// Same again, but with a kms_tenant claim on the token, so a test can tell
/// whether the filter honoured the claim or the Hold response.
fn synthetic_auth_claiming(
    client_id: &str,
    jti: &str,
    kms_tenant: &str,
) -> impl Filter<Extract = (AuthContext,), Error = Rejection> + Clone {
    let client_id = client_id.to_string();
    let jti = jti.to_string();
    let kms_tenant = kms_tenant.to_string();
    warp::any().and_then(move || {
        let client_id = client_id.clone();
        let jti = jti.clone();
        let kms_tenant = kms_tenant.clone();
        async move {
            Ok::<_, Rejection>(AuthContext {
                jwt: "test-jwt".to_string(),
                client_id,
                jti,
                kms_tenant,
            })
        }
    })
}

/// Echoes the tenancy the filter resolved, so tests can assert its source.
async fn tenant_handler(ctx: AuthContextWithHold) -> Result<impl Reply, Rejection> {
    Ok(warp::reply::with_status(
        warp::reply::json(&serde_json::json!({"kms_tenant": ctx.kms_tenant})),
        StatusCode::OK,
    ))
}

async fn ok_handler(_ctx: AuthContextWithHold) -> Result<impl Reply, Rejection> {
    Ok(warp::reply::with_status(
        warp::reply::json(&serde_json::json!({"status": "ok"})),
        StatusCode::OK,
    ))
}

/// Mirrors the production rejection mapping.
async fn handle_rejection(err: Rejection) -> Result<impl Reply, Infallible> {
    if let Some(gw) = err.find::<GatewayError>() {
        let status = match gw {
            GatewayError::InsufficientCredits => StatusCode::PAYMENT_REQUIRED,
            GatewayError::AccountPluginUnavailable(_) => StatusCode::SERVICE_UNAVAILABLE,
            GatewayError::InvalidCredential => StatusCode::UNAUTHORIZED,
            GatewayError::AccountInactive => StatusCode::FORBIDDEN,
            _ => StatusCode::INTERNAL_SERVER_ERROR,
        };
        return Ok(warp::reply::with_status(
            warp::reply::json(&serde_json::json!({"error": gw.to_string()})),
            status,
        ));
    }
    Ok(warp::reply::with_status(
        warp::reply::json(&serde_json::json!({"error": "not_found"})),
        StatusCode::NOT_FOUND,
    ))
}

#[tokio::test]
async fn filter_insufficient_credits_returns_402() {
    let (addr, hold_calls, release_calls) = start_mock_plugin(HoldBehavior::Insufficient).await;
    let client = connect(addr).await;

    let route = warp::path("test")
        .and(with_account_hold(
            synthetic_auth(),
            Some(client),
            1,
            "kms.GetCapabilities",
        ))
        .and_then(ok_handler)
        .recover(handle_rejection);

    let resp = warp::test::request().path("/test").reply(&route).await;

    assert_eq!(resp.status(), StatusCode::PAYMENT_REQUIRED);
    assert_eq!(hold_calls.load(Ordering::SeqCst), 1);
    assert_eq!(release_calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn filter_plugin_unreachable_returns_503() {
    // Unreachable port: every Hold RPC fails with Unavailable.
    let channel = tonic::transport::Channel::from_static("http://127.0.0.1:1").connect_lazy();
    let client = AccountPluginClient::new(channel);

    let route = warp::path("test")
        .and(with_account_hold(
            synthetic_auth(),
            Some(client),
            1,
            "kms.GetCapabilities",
        ))
        .and_then(ok_handler)
        .recover(handle_rejection);

    let resp = warp::test::request().path("/test").reply(&route).await;

    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
}

#[tokio::test]
async fn filter_no_client_returns_503_and_does_not_release() {
    let route = warp::path("test")
        .and(with_account_hold(
            synthetic_auth(),
            None,
            1,
            "kms.GetCapabilities",
        ))
        .and_then(ok_handler)
        .recover(handle_rejection);

    let resp = warp::test::request().path("/test").reply(&route).await;
    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);

    account_release(None, "").await;
}

#[tokio::test]
async fn filter_release_fires_when_handler_errors_after_hold() {
    let (addr, hold_calls, release_calls) = start_mock_plugin(HoldBehavior::Ok).await;
    let client = connect(addr).await;
    let release_client = connect(addr).await;

    // Mirrors what server.rs does on service failure.
    let release_client_filter = warp::any().map(move || release_client.clone());
    let route = warp::path("test")
        .and(with_account_hold(
            synthetic_auth(),
            Some(client),
            1,
            "kms.GetCapabilities",
        ))
        .and(release_client_filter)
        .and_then(
            |ctx: AuthContextWithHold, rc: AccountPluginClient<Channel>| async move {
                assert_eq!(ctx.ledger_id, "ledger-warp");
                account_release(Some(rc), &ctx.ledger_id).await;
                Err::<warp::reply::Json, Rejection>(warp::reject::custom(
                    GatewayError::ServiceTimeout,
                ))
            },
        )
        .recover(handle_rejection);

    let _ = warp::test::request().path("/test").reply(&route).await;

    assert_eq!(hold_calls.load(Ordering::SeqCst), 1);
    assert_eq!(release_calls.load(Ordering::SeqCst), 1);
}

/// The dashboard's 404 arrives as PermissionDenied and must become a 401,
/// not a 503.
#[tokio::test]
async fn filter_revoked_credential_returns_401() {
    let (addr, hold_calls, release_calls, _) =
        start_mock_plugin_capturing(HoldBehavior::Revoked).await;
    let client = connect(addr).await;

    let route = warp::path("test")
        .and(with_account_hold(
            synthetic_auth_as("acct-1", "revoked-jti"),
            Some(client),
            1,
            "kms.GetCapabilities",
        ))
        .and_then(ok_handler)
        .recover(handle_rejection);

    let resp = warp::test::request().path("/test").reply(&route).await;

    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(hold_calls.load(Ordering::SeqCst), 1);
    assert_eq!(release_calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn filter_account_inactive_returns_403() {
    let (addr, hold_calls, release_calls, _) =
        start_mock_plugin_capturing(HoldBehavior::Inactive).await;
    let client = connect(addr).await;

    let route = warp::path("test")
        .and(with_account_hold(
            synthetic_auth_as("acct-1", "pat-jti-1"),
            Some(client),
            1,
            "kms.GetCapabilities",
        ))
        .and_then(ok_handler)
        .recover(handle_rejection);

    let resp = warp::test::request().path("/test").reply(&route).await;

    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    assert_eq!(hold_calls.load(Ordering::SeqCst), 1);
    assert_eq!(release_calls.load(Ordering::SeqCst), 0);
}

/// A PAT carries the account id in `sub` and must reach the dashboard
/// unstripped, with its jti.
#[tokio::test]
async fn filter_pat_forwards_client_id_unstripped_with_jti() {
    let (addr, _, _, last_hold) = start_mock_plugin_capturing(HoldBehavior::Ok).await;
    let client = connect(addr).await;

    let route = warp::path("test")
        .and(with_account_hold(
            synthetic_auth_as("acct-abc@clients", "pat-jti-9"),
            Some(client),
            1,
            "kms.GetCapabilities",
        ))
        .and_then(ok_handler)
        .recover(handle_rejection);

    let resp = warp::test::request().path("/test").reply(&route).await;
    assert_eq!(resp.status(), StatusCode::OK);

    let (client_id, jti, _) = last_hold.lock().unwrap().clone();
    assert_eq!(
        client_id, "acct-abc@clients",
        "PAT sub must not be stripped"
    );
    assert_eq!(jti, "pat-jti-9");
}

/// The RPC route holds from the handler with a tag derived from the validated
/// body; that runtime tag must reach Hold verbatim.
#[tokio::test]
async fn account_hold_forwards_dynamic_operation_tag() {
    let (addr, hold_calls, _, last_hold) = start_mock_plugin_capturing(HoldBehavior::Ok).await;
    let client = connect(addr).await;

    let req: gateway::services::jrpc::JsonRpcRequest = serde_json::from_value(serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "kms.Sign",
        "params": {"KeyId": "kms:abc", "Message": "aGk=", "SigningAlgorithm": "ED25519"}
    }))
    .unwrap();
    req.call.validate().unwrap();

    let auth = AuthContext {
        jwt: "test-jwt".to_string(),
        client_id: "acct-1".to_string(),
        jti: "pat-jti-1".to_string(),
        kms_tenant: String::new(),
    };
    let ctx = account_hold(auth, Some(client), 1, &req.call.operation())
        .await
        .unwrap();

    assert_eq!(ctx.ledger_id, "ledger-warp");
    assert_eq!(hold_calls.load(Ordering::SeqCst), 1);
    let (_, _, operation) = last_hold.lock().unwrap().clone();
    assert_eq!(operation, "kms.Sign:ED25519");
}

/// The whole point of reading tenancy from Hold: a PAT that claims one tenant
/// must be routed under the one the dashboard resolved, not its own claim.
#[tokio::test]
async fn filter_pat_ignores_token_tenant_and_uses_hold() {
    let (addr, _, _, _) = start_mock_plugin_capturing(HoldBehavior::Ok).await;
    let client = connect(addr).await;

    let route = warp::path("test")
        .and(with_account_hold(
            synthetic_auth_claiming("acct-1", "pat-jti-1", "attacker-chosen-tenant"),
            Some(client),
            1,
            "kms.GetCapabilities",
        ))
        .and_then(tenant_handler)
        .recover(handle_rejection);

    let resp = warp::test::request().path("/test").reply(&route).await;
    assert_eq!(resp.status(), StatusCode::OK);

    let body: serde_json::Value = serde_json::from_slice(resp.body()).unwrap();
    assert_eq!(body["kms_tenant"], "tenant-from-db");
}

/// A PAT whose Hold resolved no tenancy is refused, never served under the
/// claim as a fallback.
#[tokio::test]
async fn filter_pat_without_hold_tenant_returns_503() {
    let (addr, _, _, _) = start_mock_plugin_capturing(HoldBehavior::OkNoTenant).await;
    let client = connect(addr).await;

    let route = warp::path("test")
        .and(with_account_hold(
            synthetic_auth_claiming("acct-1", "pat-jti-1", "attacker-chosen-tenant"),
            Some(client),
            1,
            "kms.GetCapabilities",
        ))
        .and_then(tenant_handler)
        .recover(handle_rejection);

    let resp = warp::test::request().path("/test").reply(&route).await;
    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
}

/// No account plugin means no Hold, so a PAT has no trustworthy tenancy and is
/// refused. Such a PAT is already unrevocable.
#[tokio::test]
async fn filter_pat_without_account_plugin_returns_503() {
    let route = warp::path("test")
        .and(with_account_hold(
            synthetic_auth_claiming("acct-1", "pat-jti-1", "attacker-chosen-tenant"),
            None,
            1,
            "kms.GetCapabilities",
        ))
        .and_then(tenant_handler)
        .recover(handle_rejection);

    let resp = warp::test::request().path("/test").reply(&route).await;
    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
}

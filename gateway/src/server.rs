use serde::Deserialize;
use std::convert::Infallible;
use std::sync::Arc;
use tokio::time::{Duration, Instant, timeout};
use warp::{Filter, Rejection, Reply, http::StatusCode, reject::Reject};

use crate::metrics;
use crate::service_manager::ServiceManager;
use crate::types::{EncryptionKey, GatewayError, ServiceRequest};

use crate::auth::pat_issue_route;
use crate::filters::{
    AuthContext, AuthContextWithHold, RateLimiter, account_hold, account_release, account_settle,
    with_account_hold, with_auth, with_rate_limiter,
};
use crate::plugins::PluginCatalog;
use crate::proto::plugins::account::account_plugin_client::AccountPluginClient;
use crate::proto::plugins::auth::auth_plugin_client::AuthPluginClient;
use crate::proto::plugins::patissuer::pat_issuer_plugin_client::PatIssuerPluginClient;
use crate::services::jrpc::{JsonRpcRequest, JsonRpcResponse};
use crate::trng::SRC_DERIVED_TRNG;
use tonic::transport::Channel;
use warp::filters::BoxedFilter;
use warp::reply::Response;

impl Reject for GatewayError {}

#[derive(Debug, Clone, Deserialize)]
struct QueryParams {
    /// The source of the service, i.e. the service provider
    src: Option<String>,
    /// The number of derived items to return (EXPERIMENTAL)
    bulk: Option<usize>,
    /// The key for encryption in the format of <scheme>@<key> (EXPERIMENTAL)
    /// This is used to encrypt the service result.
    /// Currently only supports tpk (threshold public key) i.e. "tpk@<key>".
    key: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct PostBody {
    /// The source of the service, i.e. the service provider
    src: Option<String>,
    /// The number of derived items to return
    bulk: Option<usize>,
    /// The key for encryption in the format of <scheme>@<key> (EXPERIMENTAL)
    /// This is used to encrypt the service result.
    /// Currently only supports tpk (threshold public key) i.e. "tpk@<key>".
    key: Option<String>,
    /// The arguments for the service
    /// in a vector of [(key, value), ...]
    args: Option<Vec<(String, String)>>,
}

/// Starts the gateway server, returns a future that resolves when the server stops or fails
/// It exposes the following enpoints:
#[allow(clippy::too_many_arguments)]
pub async fn start(
    http_port: u16,
    internal_port: u16,
    service_manager: Arc<ServiceManager>,
    plugin_catalog: Arc<PluginCatalog>,
    limit: u32,
    limit_window: u64,
    bulk_max: usize,
    rpc_body_max_bytes: u64,
    ctrng_enabled: bool,
) {
    let service_manager_clone = service_manager.clone();
    let service_manager_post_clone = service_manager.clone();

    let rate_limiter = Arc::new(RateLimiter::new(limit, Duration::from_secs(limit_window))); // 100 requests per minute

    let account_client: Option<AccountPluginClient<Channel>> =
        plugin_catalog.get_account_client().await.ok();
    let patissuer_client: Option<PatIssuerPluginClient<Channel>> =
        plugin_catalog.get_patissuer_client().await.ok();
    let account_client_rpc = account_client.clone();
    let account_client_get = account_client.clone();
    let account_client_post = account_client.clone();

    // The hold is placed inside handle_rpc: its operation tag comes from the
    // validated body, which a filter ahead of body parsing cannot see.
    // Path before method, so an unknown path is 404 rather than the 405 warp
    // returns when the method filter rejects first
    let rpc_route = warp::path!("api" / "v1" / "rpc")
        .and(warp::post())
        .and(with_rate_limiter(
            with_auth(service_manager.get_auth_client()),
            rate_limiter.clone(),
        ))
        .and(warp::body::content_length_limit(rpc_body_max_bytes))
        .and(warp::body::json())
        .and(warp::any().map(move || plugin_catalog.clone()))
        .and(warp::any().map(move || account_client_rpc.clone()))
        .and_then(handle_rpc);

    let bulk_max_get = bulk_max;
    let get_route = warp::path!("api" / "v1" / "services" / String)
        .and(warp::get())
        .and(with_account_hold(
            with_rate_limiter(
                with_auth(service_manager.get_auth_client()),
                rate_limiter.clone(),
            ),
            account_client_get.clone(),
            1,
            "ctrng.Get",
        ))
        .and(warp::query::<QueryParams>())
        .and(warp::any().map(move || service_manager_clone.clone()))
        .and(warp::any().map(move || bulk_max_get))
        .and(warp::any().map(move || account_client_get.clone()))
        .and_then(handle_get);

    let bulk_max_post = bulk_max;
    let post_route = warp::path!("api" / "v1" / "services" / String)
        .and(warp::post())
        .and(with_account_hold(
            with_rate_limiter(
                with_auth(service_manager.get_auth_client()),
                rate_limiter.clone(),
            ),
            account_client_post.clone(),
            1,
            "ctrng.Get",
        ))
        .and(warp::body::content_length_limit(1024)) // limit to 1 KB payload
        .and(warp::body::json())
        .and(warp::query::<QueryParams>())
        .and(warp::any().map(move || service_manager_post_clone.clone()))
        .and(warp::any().map(move || bulk_max_post))
        .and(warp::any().map(move || account_client_post.clone()))
        .and_then(handle_post);

    // Allowlist: `/healthz` is the only route that skips the account hold.
    // It runs without auth or rate-limiting so probes from k8s / load balancers
    // never spend credits. There is no `/version` route today.
    let health_route = warp::path("healthz").map(|| {
        warp::reply::json(&serde_json::json!({
            "status": "ok"
        }))
    });

    // REST service routes are cTRNG-only: unregistered means 404 before auth or hold
    let metered_routes: BoxedFilter<(Response,)> = if ctrng_enabled {
        get_route
            .or(post_route)
            .or(rpc_route)
            .map(warp::reply::Reply::into_response)
            .boxed()
    } else {
        rpc_route.map(warp::reply::Reply::into_response).boxed()
    };

    let routes: BoxedFilter<(Response,)> = metered_routes
        .or(health_route.with(warp::log("health_check")))
        .map(warp::reply::Reply::into_response)
        .boxed();

    // The public key set is published by the jwks plugin, not here. The
    // gateway routes and meters the API rather than republishing another
    // service's keys.
    let mut internal_task = None;
    if let Some(client) = patissuer_client {
        let internal = internal_routes(client, service_manager.get_auth_client());
        tracing::info!("Starting internal http server on: 0.0.0.0:{internal_port}");
        let server = warp::serve(internal)
            .bind(([0, 0, 0, 0], internal_port))
            .await
            .graceful(shutdown_signal());
        internal_task = Some(tokio::spawn(server.run()));
    }

    let routes = routes.recover(handle_rejection);

    tracing::info!("Starting http server on: 0.0.0.0:{}", http_port);

    let server = warp::serve(routes)
        .bind(([0, 0, 0, 0], http_port))
        .await
        .graceful(shutdown_signal());

    server.run().await;

    if let Some(task) = internal_task {
        let _ = task.await;
    }
}

async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };

    #[cfg(unix)]
    let terminate = async {
        if let Ok(mut signal) =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        {
            signal.recv().await;
        } else {
            std::future::pending().await
        }
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
    tracing::info!("Shutdown signal received, draining requests...");
}

/// Everything served on the internal listener. PAT issuance lives here and
/// nowhere else, so no configuration can expose it on the public port.
pub fn internal_routes(
    client: PatIssuerPluginClient<Channel>,
    auth_client: AuthPluginClient<Channel>,
) -> impl Filter<Extract = (impl Reply,), Error = Infallible> + Clone {
    pat_issue_route(client, auth_client).recover(handle_rejection)
}

/// Maps gateway-specific custom rejections to HTTP responses. Without this,
/// warp would default to 500 for every custom rejection.
async fn handle_rejection(err: Rejection) -> Result<impl Reply, Infallible> {
    if let Some(gw) = err.find::<GatewayError>() {
        let (status, body) = match gw {
            GatewayError::InsufficientCredits => (
                StatusCode::PAYMENT_REQUIRED,
                serde_json::json!({"error": "insufficient_credits"}),
            ),
            GatewayError::AccountPluginUnavailable(msg) => (
                StatusCode::SERVICE_UNAVAILABLE,
                serde_json::json!({"error": "account_plugin_unavailable", "detail": msg}),
            ),
            GatewayError::RateLimitExceeded => (
                StatusCode::TOO_MANY_REQUESTS,
                serde_json::json!({"error": "rate_limit_exceeded"}),
            ),
            GatewayError::NoAuthHeaderError | GatewayError::InvalidAuthHeaderError => (
                StatusCode::UNAUTHORIZED,
                serde_json::json!({"error": gw.to_string()}),
            ),
            GatewayError::AuthenticationFailed => (
                StatusCode::UNAUTHORIZED,
                serde_json::json!({"error": "authentication_failed"}),
            ),
            GatewayError::ServiceAuthorizationDenied => (
                StatusCode::FORBIDDEN,
                serde_json::json!({"error": "service_authorization_denied"}),
            ),
            GatewayError::PatExpired => (
                StatusCode::UNAUTHORIZED,
                serde_json::json!({
                    "error": "token_expired",
                    "message": "Personal access token expired — create a new one in the dashboard"
                }),
            ),
            GatewayError::InvalidCredential => (
                StatusCode::UNAUTHORIZED,
                serde_json::json!({
                    "error": "invalid_credential",
                    "message": "Unknown or revoked credential"
                }),
            ),
            GatewayError::AccountInactive => (
                StatusCode::FORBIDDEN,
                serde_json::json!({"error": "account_inactive"}),
            ),
            GatewayError::AuthPluginConnectionError(_) => (
                StatusCode::SERVICE_UNAVAILABLE,
                serde_json::json!({"error": "auth_plugin_unavailable"}),
            ),
            GatewayError::BadRequest(msg) => {
                (StatusCode::BAD_REQUEST, serde_json::json!({"error": msg}))
            }
            GatewayError::ServiceTimeout => (
                StatusCode::GATEWAY_TIMEOUT,
                serde_json::json!({"error": "service_timeout"}),
            ),
            GatewayError::ServiceNotFoundError(name) => (
                StatusCode::NOT_FOUND,
                serde_json::json!({"error": "service_not_found", "service": name}),
            ),
            _ => (
                StatusCode::INTERNAL_SERVER_ERROR,
                serde_json::json!({"error": gw.to_string()}),
            ),
        };
        return Ok(warp::reply::with_status(warp::reply::json(&body), status));
    }
    if let Some(e) = err.find::<warp::filters::body::BodyDeserializeError>() {
        return Ok(warp::reply::with_status(
            warp::reply::json(
                &serde_json::json!({"error": format!("Request body deserialize error: {e}")}),
            ),
            StatusCode::BAD_REQUEST,
        ));
    }
    if err.is_not_found() {
        return Ok(warp::reply::with_status(
            warp::reply::json(&serde_json::json!({"error": "not_found"})),
            StatusCode::NOT_FOUND,
        ));
    }
    if err.find::<warp::reject::MethodNotAllowed>().is_some() {
        return Ok(warp::reply::with_status(
            warp::reply::json(&serde_json::json!({"error": "method_not_allowed"})),
            StatusCode::METHOD_NOT_ALLOWED,
        ));
    }
    tracing::error!("unhandled rejection: {err:?}");
    Ok(warp::reply::with_status(
        warp::reply::json(&serde_json::json!({"error": "internal_error"})),
        StatusCode::INTERNAL_SERVER_ERROR,
    ))
}

async fn handle_rpc(
    auth: AuthContext,
    body: JsonRpcRequest,
    plugin_catalog: Arc<PluginCatalog>,
    account_client: Option<AccountPluginClient<Channel>>,
) -> Result<impl Reply, Rejection> {
    tracing::debug!("Handling RPC request [id={}] {:?}", body.id, body);
    let req_id = body.id;
    let rpc_call = body.call;
    // Validate before holding, so an invalid request costs nothing and needs
    // no release.
    if let Err(e) = rpc_call.validate() {
        tracing::error!("RPC validation error [id={}]: {}", req_id, e);
        let res: JsonRpcResponse<()> =
            JsonRpcResponse::error(req_id, -32602, format!("Invalid request: {e}"));
        return Ok(warp::reply::json(&res));
    }
    let ctx = account_hold(auth, account_client.clone(), 1, &rpc_call.operation()).await?;
    let ledger_id = ctx.ledger_id.clone();
    const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
    let client_id = ctx.kms_tenant;

    match timeout(
        REQUEST_TIMEOUT,
        rpc_call.execute(req_id, &client_id, &plugin_catalog),
    )
    .await
    {
        Ok(Ok(result)) => {
            tracing::debug!("RPC executed successfully [id={}]", req_id);
            tokio::spawn(async move {
                account_settle(account_client, &ledger_id).await;
            });
            Ok(warp::reply::json(&result))
        }
        Ok(Err(e)) => {
            tracing::warn!("RPC execution error [id={}]: {}", req_id, e);
            account_release(account_client, &ledger_id).await;

            let res: JsonRpcResponse<()> = JsonRpcResponse::error(req_id, -32001, e.to_string());

            Ok(warp::reply::json(&res))
        }
        Err(_) => {
            tracing::error!("RPC request timed out [id={}]", req_id);
            account_release(account_client, &ledger_id).await;

            let res: JsonRpcResponse<()> =
                JsonRpcResponse::error(req_id, -32002, "Request timed out");

            Ok(warp::reply::json(&res))
        }
    }
}

async fn handle_get(
    service: String,
    ctx: AuthContextWithHold,
    query: QueryParams,
    service_manager: Arc<ServiceManager>,
    bulk_max: usize,
    account_client: Option<AccountPluginClient<Channel>>,
) -> Result<impl Reply, Rejection> {
    let req_id = new_req_id();
    let ledger_id = ctx.ledger_id.clone();
    tracing::debug!(
        "[req={}] Handling GET request for service: {}",
        req_id,
        service
    );
    let src = if let Some(s) = query.src {
        vec![s.clone()]
    } else {
        vec![SRC_DERIVED_TRNG.to_string()]
    };
    if let Some(b) = query.bulk {
        if b > bulk_max {
            metrics::record_validation("GET", "bulk_limit_exceeded");
            account_release(account_client.clone(), &ledger_id).await;
            return Err(warp::reject::custom(GatewayError::BadRequest(format!(
                "Bulk size {b} exceeds maximum {bulk_max}"
            ))));
        } else {
            tracing::debug!("[req={}] Bulk size: {}", req_id, b);
        }
    }
    let enc_key = match query.key {
        Some(key) => match EncryptionKey::new_from_arg(&key) {
            Ok(k) => Some(k),
            Err(e) => {
                metrics::record_validation("GET", "invalid_encryption_key");
                account_release(account_client.clone(), &ledger_id).await;
                return Err(warp::reject::custom(GatewayError::BadRequest(
                    e.to_string(),
                )));
            }
        },
        None => None,
    };
    let svc_req = ServiceRequest {
        req_id,
        service,
        src,
        bulk: query.bulk,
        enc_key,
        args: None,
    };
    handle_service_req(svc_req, service_manager.clone(), account_client, ledger_id).await
}

async fn handle_post(
    service: String,
    ctx: AuthContextWithHold,
    body: PostBody,
    query: QueryParams,
    service_manager: Arc<ServiceManager>,
    bulk_max: usize,
    account_client: Option<AccountPluginClient<Channel>>,
) -> Result<impl Reply, Rejection> {
    let req_id = new_req_id();
    let ledger_id = ctx.ledger_id.clone();
    let src = if let Some(s) = body.src {
        s.clone()
    } else {
        query.src.unwrap_or(SRC_DERIVED_TRNG.to_string()).clone()
    };

    let bulk = if let Some(b) = body.bulk {
        Some(b)
    } else {
        query.bulk
    };
    if let Some(b) = bulk {
        if b > bulk_max {
            metrics::record_validation("POST", "bulk_limit_exceeded");
            account_release(account_client.clone(), &ledger_id).await;
            return Err(warp::reject::custom(GatewayError::BadRequest(format!(
                "Bulk size {b} exceeds maximum {bulk_max}"
            ))));
        } else {
            tracing::debug!("[req={}] Bulk size: {}", req_id, b);
        }
    }
    let key = if let Some(k) = query.key {
        Some(k)
    } else {
        body.key
    };
    let enc_key = match key {
        Some(key) => match EncryptionKey::new_from_arg(&key) {
            Ok(k) => Some(k),
            Err(e) => {
                metrics::record_validation("POST", "invalid_encryption_key");
                account_release(account_client.clone(), &ledger_id).await;
                return Err(warp::reject::custom(GatewayError::BadRequest(
                    e.to_string(),
                )));
            }
        },
        None => None,
    };
    let args = body.args.clone();
    let svc_req = ServiceRequest {
        req_id,
        service,
        src: vec![src],
        bulk,
        enc_key,
        args,
    };
    handle_service_req(svc_req, service_manager.clone(), account_client, ledger_id).await
}

async fn handle_service_req(
    svc_req: ServiceRequest,
    service_manager: Arc<ServiceManager>,
    account_client: Option<AccountPluginClient<Channel>>,
    ledger_id: String,
) -> Result<impl Reply, Rejection> {
    let timer: Instant = Instant::now();

    let req_id = svc_req.req_id;
    let svc_name = svc_req.service.clone();
    metrics::API_REQ_COUNTER
        .with_label_values(&[&svc_name])
        .inc();
    let response = timeout(Duration::from_secs(10), async {
        service_manager.handle(svc_req).await
    })
    .await;

    let duration = timer.elapsed().as_secs_f64();
    metrics::API_REQ_DURATION_SECONDS
        .with_label_values(&[&svc_name])
        .observe(duration);

    match response {
        Ok(Ok(res)) => match res.result {
            Ok(result) => {
                metrics::API_REQ_OK_COUNTER
                    .with_label_values(&[&svc_name])
                    .inc();
                metrics::record_request(&svc_name, "ok", duration);
                tracing::debug!("[req={}] Got service result", req_id);
                let account_client = account_client.clone();
                let ledger_id = ledger_id.clone();
                tokio::spawn(async move {
                    account_settle(account_client, &ledger_id).await;
                });
                Ok(warp::reply::json(&result))
            }
            Err(e) => {
                metrics::API_REQ_ERR_COUNTER
                    .with_label_values(&[&svc_name])
                    .inc();
                metrics::record_request(&svc_name, "service_error", duration);
                tracing::error!("[req={}] Error result: {:?}", req_id, e);
                account_release(account_client.clone(), &ledger_id).await;
                Err(warp::reject::custom(e))
            }
        },
        Ok(Err(e)) => {
            metrics::API_REQ_FAILED_COUNTER
                .with_label_values(&[&svc_name])
                .inc();
            metrics::record_request(&svc_name, "routing_error", duration);
            tracing::error!("[req={}] Error routing request: {:?}", req_id, e);
            account_release(account_client.clone(), &ledger_id).await;
            Err(warp::reject::custom(e))
        }
        Err(_) => {
            metrics::API_REQ_TIMEOUT_COUNTER
                .with_label_values(&[&svc_name])
                .inc();
            metrics::record_request(&svc_name, "timeout", duration);
            tracing::error!("[req={}] Request timed out", req_id);
            account_release(account_client.clone(), &ledger_id).await;
            Err(warp::reject::custom(GatewayError::ServiceTimeout))
        }
    }
}

/// Generates a new random request ID.
fn new_req_id() -> u64 {
    use rand::Rng;
    let mut rng = rand::rng();
    rng.random_range(1..u64::MAX)
}

#[cfg(test)]
mod test {
    use super::*;

    #[tokio::test]
    async fn pat_expired_rejection_maps_to_401_token_expired() {
        let route = warp::any()
            .and_then(|| async {
                Err::<warp::reply::Json, Rejection>(warp::reject::custom(GatewayError::PatExpired))
            })
            .recover(handle_rejection);

        let resp = warp::test::request().reply(&route).await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        let body: serde_json::Value = serde_json::from_slice(resp.body()).unwrap();
        assert_eq!(body["error"], "token_expired");
        assert!(body["message"].as_str().unwrap().contains("expired"));
    }
}

use crate::metrics;
use crate::proto::plugins::account::{HoldRequest, account_plugin_client::AccountPluginClient};
use crate::proto::plugins::auth::{
    ServiceTokenValidationRequest, TokenValidationRequest, TokenValidationResponse,
    auth_plugin_client::AuthPluginClient,
};
use crate::types::GatewayError;
use sha2::{Digest, Sha256};
use std::{collections::HashMap, sync::Arc};
use tokio::{
    sync::Mutex,
    time::{Duration, Instant},
};
use tonic::transport::Channel;
use warp::{
    Filter,
    filters::header::headers_cloned,
    http::header::{AUTHORIZATION, HeaderMap, HeaderValue},
};

const BEARER: &str = "Bearer ";

/// Ceiling on a single auth-plugin validate_token call.
const AUTH_VALIDATE_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Clone, Debug)]
pub struct AuthContext {
    pub jwt: String,
    pub client_id: String,
    pub jti: String,
    /// The token's kms_tenant claim; ignored, tenancy comes from Hold.
    pub kms_tenant: String,
}

/// AuthContextWithHold carries the validated JWT context and the dashboard
/// CreditLedger row id. The ledger_id is empty when the account plugin is
/// unconfigured.
#[derive(Clone, Debug)]
pub struct AuthContextWithHold {
    pub auth: AuthContext,
    pub ledger_id: String,
    /// KMS tenancy to route this request under, resolved by the dashboard
    /// from the Account row during Hold. Never the token's own claim.
    pub kms_tenant: String,
}

/// Identity of an Auth0 M2M principal authorized for an internal capability.
#[derive(Clone, Debug)]
pub struct ServiceAuthContext {
    pub client_id: String,
}

/// Rate limit structure
pub type RateLimit = (u32, Instant);
/// Rate limit items
type RateLimiterItems = Arc<Mutex<HashMap<String, RateLimit>>>;

/// Rate limiter structure that holds the rate limit items, maximum requests allowed,
/// and the time window for rate limiting.
pub struct RateLimiter {
    items: RateLimiterItems,
    max_requests: u32,
    time_window: Duration,
}

impl RateLimiter {
    pub fn new(max_requests: u32, time_window: Duration) -> Self {
        RateLimiter {
            items: Arc::new(Mutex::new(HashMap::new())),
            max_requests,
            time_window,
        }
    }
}

/// Creates an authentication filter that validates JWTs using the auth plugin.
pub fn with_auth(
    auth_client: AuthPluginClient<Channel>,
) -> impl Filter<Extract = (AuthContext,), Error = warp::Rejection> + Clone {
    headers_cloned()
        .map(move |headers: HeaderMap<HeaderValue>| (headers, auth_client.clone()))
        .and_then(authorize)
}

/// Creates a filter that authorizes an Auth0 M2M token for a specific internal
/// capability. It intentionally calls a different auth-plugin RPC from
/// `with_auth`, so user and PAT validation cannot authorize service routes.
pub fn with_service_auth(
    auth_client: AuthPluginClient<Channel>,
    required_scopes: &'static [&'static str],
) -> impl Filter<Extract = (ServiceAuthContext,), Error = warp::Rejection> + Clone {
    headers_cloned()
        .map(move |headers: HeaderMap<HeaderValue>| (headers, auth_client.clone(), required_scopes))
        .and_then(authorize_service)
}

type ApiResult<T> = std::result::Result<T, warp::Rejection>;

/// Authorization logic that extracts the JWT from the Authorization header,
/// validates it using the auth plugin, and returns the JWT if valid.
async fn authorize(
    (headers, mut auth_client): (HeaderMap<HeaderValue>, AuthPluginClient<Channel>),
) -> ApiResult<AuthContext> {
    let timer = Instant::now();
    match jwt_from_header(&headers) {
        Ok(jwt) => {
            let request = tonic::Request::new(TokenValidationRequest { token: jwt.clone() });
            // The auth plugin fetches issuer JWKS on the PAT path, so a hung
            // issuer must not pin this request open forever.
            let validated =
                tokio::time::timeout(AUTH_VALIDATE_TIMEOUT, auth_client.validate_token(request))
                    .await
                    .map_err(|_| {
                        metrics::record_auth("plugin_timeout", timer.elapsed().as_secs_f64());
                        tracing::error!("Auth plugin validate_token timed out");
                        warp::reject::custom(GatewayError::AuthPluginConnectionError(
                            "timeout".to_string(),
                        ))
                    })?;
            let response: TokenValidationResponse = validated
                .map_err(|e| match e.code() {
                    tonic::Code::Unavailable | tonic::Code::NotFound => {
                        metrics::record_auth("plugin_unavailable", timer.elapsed().as_secs_f64());
                        tracing::error!("Auth plugin is unavailable: {}", e);
                        warp::reject::custom(GatewayError::AuthPluginConnectionError(
                            "unavailable".to_string(),
                        ))
                    }
                    // Expired PATs are typed Unauthenticated AND carry a
                    // "pat_expired:" message; either signal alone is enough.
                    _ if e.message().contains("pat_expired")
                        || (e.code() == tonic::Code::Unauthenticated
                            && e.message().contains("expired")) =>
                    {
                        metrics::record_auth("pat_expired", timer.elapsed().as_secs_f64());
                        tracing::info!("Rejected expired PAT");
                        warp::reject::custom(GatewayError::PatExpired)
                    }
                    tonic::Code::Unauthenticated => {
                        metrics::record_auth("invalid_credential", timer.elapsed().as_secs_f64());
                        tracing::info!("Rejected non-PAT or invalid token: {}", e);
                        warp::reject::custom(GatewayError::InvalidCredential)
                    }
                    _ => {
                        metrics::record_auth("failed", timer.elapsed().as_secs_f64());
                        tracing::error!("Failed to authorize JWT: {}", e);
                        warp::reject::custom(GatewayError::AuthenticationFailed)
                    }
                })?
                .into_inner();
            if !response.ok {
                metrics::record_auth("rejected", timer.elapsed().as_secs_f64());
                return Err(warp::reject::custom(GatewayError::AuthenticationFailed));
            }
            let client_id = response.client_id.trim().to_string();
            if client_id.is_empty() {
                metrics::record_auth("failed", timer.elapsed().as_secs_f64());
                tracing::error!("Auth plugin validated JWT but returned empty client_id");
                return Err(warp::reject::custom(GatewayError::AuthenticationFailed));
            }
            metrics::record_auth("ok", timer.elapsed().as_secs_f64());
            tracing::debug!("JWT authorized successfully");
            Ok(AuthContext {
                jwt,
                client_id,
                jti: response.jti.trim().to_string(),
                kms_tenant: response.kms_tenant.trim().to_string(),
            })
        }
        Err(GatewayError::NoAuthHeaderError) => {
            metrics::record_auth("missing_header", timer.elapsed().as_secs_f64());
            Err(warp::reject::custom(GatewayError::NoAuthHeaderError))
        }
        Err(GatewayError::InvalidAuthHeaderError) => {
            metrics::record_auth("invalid_header", timer.elapsed().as_secs_f64());
            Err(warp::reject::custom(GatewayError::InvalidAuthHeaderError))
        }
        Err(e) => {
            metrics::record_auth("failed", timer.elapsed().as_secs_f64());
            Err(warp::reject::custom(e))
        }
    }
}

async fn authorize_service(
    (headers, mut auth_client, required_scopes): (
        HeaderMap<HeaderValue>,
        AuthPluginClient<Channel>,
        &'static [&'static str],
    ),
) -> ApiResult<ServiceAuthContext> {
    let timer = Instant::now();
    let jwt = jwt_from_header(&headers)?;
    let request = tonic::Request::new(ServiceTokenValidationRequest {
        token: jwt,
        required_scopes: required_scopes
            .iter()
            .map(|scope| (*scope).to_string())
            .collect(),
    });
    let validated = tokio::time::timeout(
        AUTH_VALIDATE_TIMEOUT,
        auth_client.validate_service_token(request),
    )
    .await
    .map_err(|_| {
        metrics::record_auth("service_plugin_timeout", timer.elapsed().as_secs_f64());
        tracing::error!("Auth plugin service-token validation timed out");
        warp::reject::custom(GatewayError::AuthPluginConnectionError(
            "timeout".to_string(),
        ))
    })?
    .map_err(|e| match e.code() {
        tonic::Code::Unavailable | tonic::Code::NotFound | tonic::Code::Unimplemented => {
            metrics::record_auth("service_plugin_unavailable", timer.elapsed().as_secs_f64());
            tracing::error!("Auth plugin service-token validation unavailable: {e}");
            warp::reject::custom(GatewayError::AuthPluginConnectionError(
                "unavailable".to_string(),
            ))
        }
        tonic::Code::PermissionDenied => {
            metrics::record_auth("service_forbidden", timer.elapsed().as_secs_f64());
            warp::reject::custom(GatewayError::ServiceAuthorizationDenied)
        }
        _ => {
            metrics::record_auth("service_failed", timer.elapsed().as_secs_f64());
            warp::reject::custom(GatewayError::AuthenticationFailed)
        }
    })?
    .into_inner();

    if !validated.ok || validated.client_id.trim().is_empty() {
        metrics::record_auth("service_failed", timer.elapsed().as_secs_f64());
        return Err(warp::reject::custom(GatewayError::AuthenticationFailed));
    }

    metrics::record_auth("service_ok", timer.elapsed().as_secs_f64());
    Ok(ServiceAuthContext {
        client_id: validated.client_id,
    })
}

fn jwt_from_header(headers: &HeaderMap<HeaderValue>) -> Result<String, GatewayError> {
    let header = match headers.get(AUTHORIZATION) {
        Some(v) => v,
        None => return Err(GatewayError::NoAuthHeaderError),
    };
    let auth_header = match std::str::from_utf8(header.as_bytes()) {
        Ok(v) => v,
        Err(_) => return Err(GatewayError::NoAuthHeaderError),
    };
    extract_jwt(auth_header)
}

fn extract_jwt(auth_header: &str) -> Result<String, GatewayError> {
    if !auth_header.starts_with(BEARER) {
        return Err(GatewayError::InvalidAuthHeaderError);
    }
    Ok(auth_header.trim_start_matches(BEARER).to_owned())
}

// Create a rate limiter filter
pub fn with_rate_limiter(
    auth_filter: impl Filter<Extract = (AuthContext,), Error = warp::Rejection> + Clone,
    rate_limiter: Arc<RateLimiter>,
) -> impl Filter<Extract = (AuthContext,), Error = warp::Rejection> + Clone {
    auth_filter
        .and(warp::any().map(move || rate_limiter.clone()))
        .and_then(rate_limit)
}

/// Wraps an auth filter with a credit-hold step against the account plugin.
/// `None` passes through with an empty ledger_id — no credit gating.
/// `insufficient_credits` rejects with 402, transport failure with 503.
pub fn with_account_hold(
    auth_filter: impl Filter<Extract = (AuthContext,), Error = warp::Rejection> + Clone,
    account_client: Option<AccountPluginClient<Channel>>,
    units: u32,
    operation: &'static str,
) -> impl Filter<Extract = (AuthContextWithHold,), Error = warp::Rejection> + Clone {
    auth_filter
        .and(warp::any().map(move || account_client.clone()))
        .and_then(move |auth, account_client| account_hold(auth, account_client, units, operation))
}

/// Places a credit hold tagged with `operation`. Callable directly when the tag
/// depends on the request body (the RPC route), which a filter cannot see.
pub async fn account_hold(
    auth: AuthContext,
    account_client: Option<AccountPluginClient<Channel>>,
    units: u32,
    operation: &str,
) -> Result<AuthContextWithHold, warp::Rejection> {
    let Some(mut client) = account_client else {
        metrics::record_account_hold("no_account_plugin");
        tracing::error!("ORBITPORT_ACCOUNT_PLUGIN is unset: cannot resolve KMS tenancy");
        return Err(warp::reject::custom(
            GatewayError::AccountPluginUnavailable(
                "account plugin required to resolve tenancy".to_string(),
            ),
        ));
    };

    let request = tonic::Request::new(HoldRequest {
        client_id: auth.client_id.clone(),
        units,
        operation: operation.to_string(),
        jti: auth.jti.clone(),
    });

    match client.hold(request).await {
        Ok(resp) => {
            let body = resp.into_inner();
            if !body.ok {
                if body.error == "insufficient_credits" {
                    metrics::record_account_hold("insufficient_credits");
                    return Err(warp::reject::custom(GatewayError::InsufficientCredits));
                }
                metrics::record_account_hold("plugin_error");
                tracing::error!("Account plugin returned ok=false: {}", body.error);
                return Err(warp::reject::custom(
                    GatewayError::AccountPluginUnavailable(body.error),
                ));
            }
            let kms_tenant = match body.kms_tenant.trim() {
                // Tenancy must come from the Account row, never from the token's own claim.
                "" => {
                    metrics::record_account_hold("missing_tenant");
                    tracing::error!("Account plugin Hold returned no kms_tenant");
                    return Err(warp::reject::custom(
                        GatewayError::AccountPluginUnavailable(
                            "hold response missing kms_tenant".to_string(),
                        ),
                    ));
                }
                t => t.to_string(),
            };
            metrics::record_account_hold("ok");
            Ok(AuthContextWithHold {
                auth,
                ledger_id: body.ledger_id,
                kms_tenant,
            })
        }
        Err(e) => match e.code() {
            tonic::Code::FailedPrecondition => {
                metrics::record_account_hold("insufficient_credits");
                Err(warp::reject::custom(GatewayError::InsufficientCredits))
            }
            tonic::Code::PermissionDenied if e.message() == "account_inactive" => {
                metrics::record_account_hold("account_inactive");
                Err(warp::reject::custom(GatewayError::AccountInactive))
            }
            // Dashboard 404: unknown/revoked/expired credential — the PAT
            // revocation path. An auth failure, not a plugin outage.
            tonic::Code::PermissionDenied => {
                metrics::record_account_hold("invalid_credential");
                Err(warp::reject::custom(GatewayError::InvalidCredential))
            }
            _ => {
                metrics::record_account_hold("plugin_unavailable");
                tracing::error!("Account plugin Hold failed: {}", e);
                Err(warp::reject::custom(
                    GatewayError::AccountPluginUnavailable(e.message().to_string()),
                ))
            }
        },
    }
}

/// Best-effort settle, committing the hold so the dashboard sweeper does not
/// refund it as an orphan. A dropped settle leaves the hold unresolved and the
/// sweeper refunds it, so the customer is never overcharged.
pub async fn account_settle(account_client: Option<AccountPluginClient<Channel>>, ledger_id: &str) {
    if ledger_id.is_empty() {
        return;
    }
    let Some(mut client) = account_client else {
        return;
    };

    let req = tonic::Request::new(crate::proto::plugins::account::SettleRequest {
        ledger_id: ledger_id.to_string(),
    });

    let settle = tokio::time::timeout(Duration::from_secs(2), client.settle(req)).await;
    match settle {
        Ok(Ok(resp)) => {
            let body = resp.into_inner();
            if body.ok {
                metrics::record_account_settle("ok");
                tracing::debug!("Account settle succeeded for ledger_id={}", ledger_id);
            } else {
                metrics::record_account_settle("plugin_error");
                tracing::warn!(
                    "Account settle returned ok=false for ledger_id={}: {}. Sweeper will refund the orphan.",
                    ledger_id,
                    body.error
                );
            }
        }
        Ok(Err(e)) => {
            metrics::record_account_settle("plugin_error");
            tracing::warn!(
                "Account settle failed for ledger_id={}: {}. Sweeper will refund the orphan.",
                ledger_id,
                e
            );
        }
        Err(_) => {
            metrics::record_account_settle("timeout");
            tracing::warn!(
                "Account settle timed out for ledger_id={}. Sweeper will refund the orphan.",
                ledger_id
            );
        }
    }
}

/// Best-effort release. The dashboard sweeper backstops orphaned holds.
pub async fn account_release(
    account_client: Option<AccountPluginClient<Channel>>,
    ledger_id: &str,
) {
    if ledger_id.is_empty() {
        return;
    }
    let Some(mut client) = account_client else {
        return;
    };

    let req = tonic::Request::new(crate::proto::plugins::account::ReleaseRequest {
        ledger_id: ledger_id.to_string(),
    });

    let release = tokio::time::timeout(Duration::from_secs(2), client.release(req)).await;
    match release {
        Ok(Ok(_)) => {
            metrics::record_account_release("ok");
            tracing::debug!("Account release succeeded for ledger_id={}", ledger_id);
        }
        Ok(Err(e)) => {
            metrics::record_account_release("plugin_error");
            tracing::warn!(
                "Account release failed for ledger_id={}: {}. Sweeper will backstop.",
                ledger_id,
                e
            );
        }
        Err(_) => {
            metrics::record_account_release("timeout");
            tracing::warn!(
                "Account release timed out for ledger_id={}. Sweeper will backstop.",
                ledger_id
            );
        }
    }
}

/// Rate limiting logic.
async fn rate_limit(
    auth: AuthContext,
    rate_limiter: Arc<RateLimiter>,
) -> Result<AuthContext, warp::Rejection> {
    // Hash the token to avoid storing it directly.
    let mut hasher = Sha256::new();
    hasher.update(&auth.jwt);
    let token_hash = format!("{:x}", hasher.finalize());

    let mut items = rate_limiter.items.lock().await;

    // Check the current time and rate limit
    let now = Instant::now();
    let entry = items.entry(token_hash).or_insert((0, now));

    // Reset the count if the time window has passed
    if now.duration_since(entry.1) > rate_limiter.time_window {
        entry.0 = 0;
        entry.1 = now;
    }
    entry.0 += 1;

    // Check if the request count exceeds the limit
    if entry.0 > rate_limiter.max_requests {
        metrics::record_rate_limit("exceeded");
        return Err(warp::reject::custom(GatewayError::RateLimitExceeded)); // Use a custom rejection
    }

    metrics::record_rate_limit("ok");
    Ok(auth)
}

#[cfg(test)]
mod test {
    use super::*;

    #[tokio::test]
    async fn test_jwt_from_header() {
        let mut headers = HeaderMap::new();
        headers.insert(AUTHORIZATION, HeaderValue::from_static("Bearer test_token"));
        let jwt = jwt_from_header(&headers).unwrap();
        assert_eq!(jwt, "test_token");
    }

    #[tokio::test]
    async fn test_jwt_from_header_empty() {
        let headers = HeaderMap::new();
        match jwt_from_header(&headers) {
            Err(GatewayError::NoAuthHeaderError) => {}
            _ => panic!("Expected NoAuthHeaderError"),
        }
    }

    #[tokio::test]
    async fn test_rate_limiter() {
        let rate_limiter = Arc::new(RateLimiter::new(5, Duration::from_secs(10)));
        let auth = AuthContext {
            jwt: "test_token".to_string(),
            client_id: "client".to_string(),
            jti: "jti".to_string(),
            kms_tenant: String::new(),
        };

        for _i in 0..5 {
            rate_limit(auth.clone(), rate_limiter.clone())
                .await
                .unwrap();
        }
        match rate_limit(auth, rate_limiter.clone()).await {
            Ok(_) => panic!("Rate limit should have been exceeded"),
            Err(e) => {
                assert_eq!(
                    format!("{:?}", e),
                    "Rejection(RateLimitExceeded)".to_string(),
                    "Expected rate limit exceeded error"
                );
            }
        }
    }
}

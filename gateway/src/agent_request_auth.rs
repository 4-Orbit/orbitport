//! Credential gate for agent-facing operation routes.
//!
//! Mount this filter after the route path and method, then run policy
//! enforcement before using the authenticated request's input. No account or
//! agent identity is accepted from the agent's JSON body.

use serde::Deserialize;
use serde_json::Value;
use warp::{
    Filter, Rejection,
    filters::header::headers_cloned,
    http::header::{AUTHORIZATION, HeaderMap, HeaderValue},
};

use crate::{
    agent_delegation::{AgentCredentialStore, AgentScope, DelegationError},
    types::GatewayError,
};

const MAX_AGENT_REQUEST_BYTES: u64 = 16 * 1024;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AgentOperationRequest {
    pub action: String,
    pub resource: String,
    #[serde(default)]
    pub input: Option<Value>,
}

pub struct AuthenticatedAgentRequest {
    /// Trusted account and agent identity from the server-side grant.
    pub scope: AgentScope,
    /// Operation-specific data; the handler must validate it before use.
    pub input: Option<Value>,
}

/// Composable filter for an agent operation route. A successful extraction
/// proves credential scope only; the handler must still obtain a Cedar policy
/// decision before performing a protected operation.
pub fn with_agent_request_auth(
    store: AgentCredentialStore,
) -> impl Filter<Extract = (AuthenticatedAgentRequest,), Error = Rejection> + Clone {
    headers_cloned()
        .and_then(|headers: HeaderMap<HeaderValue>| async move {
            bearer_token(&headers)
                .map(str::to_owned)
                .map_err(warp::reject::custom)
        })
        .and(warp::body::content_length_limit(MAX_AGENT_REQUEST_BYTES))
        .and(warp::body::json::<AgentOperationRequest>())
        .and(warp::any().map(move || store.clone()))
        .and_then(authenticate_request)
}

async fn authenticate_request(
    token: String,
    request: AgentOperationRequest,
    store: AgentCredentialStore,
) -> Result<AuthenticatedAgentRequest, Rejection> {
    let scope = store
        .authenticate(&token, &request.action, &request.resource)
        .map_err(|error| {
            let gateway_error = match error {
                DelegationError::Clock | DelegationError::Unavailable => {
                    GatewayError::DelegationUnavailable
                }
                _ => GatewayError::InvalidCredential,
            };
            warp::reject::custom(gateway_error)
        })?;
    Ok(AuthenticatedAgentRequest {
        scope,
        input: request.input,
    })
}

fn bearer_token(headers: &HeaderMap<HeaderValue>) -> Result<&str, GatewayError> {
    let value = headers
        .get(AUTHORIZATION)
        .ok_or(GatewayError::NoAuthHeaderError)?
        .to_str()
        .map_err(|_| GatewayError::InvalidAuthHeaderError)?;
    value
        .strip_prefix("Bearer ")
        .filter(|token| !token.is_empty() && !token.bytes().any(|byte| byte.is_ascii_whitespace()))
        .ok_or(GatewayError::InvalidAuthHeaderError)
}

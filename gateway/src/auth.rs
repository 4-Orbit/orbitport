//! The internal PAT issuance endpoint. The public key set is published by the
//! jwks plugin, which reads it from the issuer over gRPC.

use serde::Deserialize;
use warp::{Filter, Rejection, http::StatusCode, reply::Response};

use crate::proto::plugins::patissuer::{
    IssueTokenRequest, pat_issuer_plugin_client::PatIssuerPluginClient,
};
use crate::{
    filters::{ServiceAuthContext, with_service_auth},
    proto::plugins::auth::auth_plugin_client::AuthPluginClient,
};
use tonic::transport::Channel;

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PatIssueBody {
    jti: String,
    subject: String,
    #[serde(default)]
    kms_tenant: Option<String>,
    expires_at: i64,
}

/// INTERNAL `POST /internal/pat/issue`, guarded by an Auth0 M2M capability
/// token. It intentionally does not use the public user/PAT auth filter.
pub fn pat_issue_route(
    client: PatIssuerPluginClient<Channel>,
    auth_client: AuthPluginClient<Channel>,
) -> impl Filter<Extract = (Response,), Error = Rejection> + Clone {
    warp::post()
        .and(warp::path!("internal" / "pat" / "issue"))
        .and(with_service_auth(auth_client, &["pat:issue"]))
        .and(warp::body::content_length_limit(4096))
        .and(warp::body::json())
        .and(warp::any().map(move || client.clone()))
        .and_then(handle_pat_issue)
}

async fn handle_pat_issue(
    service_auth: ServiceAuthContext,
    body: PatIssueBody,
    mut client: PatIssuerPluginClient<Channel>,
) -> Result<Response, Rejection> {
    tracing::info!(
        service_client_id = %service_auth.client_id,
        "Authorized PAT issuance request"
    );

    let request = tonic::Request::new(IssueTokenRequest {
        jti: body.jti,
        subject: body.subject,
        kms_tenant: body.kms_tenant.unwrap_or_default(),
        expires_at: body.expires_at,
        // The dashboard route mints account-level PATs only. Agent PATs are
        // minted through policy.IssueAgentToken, which the policy plugin
        // authorizes against the tenant's registered agents.
        agent_id: String::new(),
    });
    match client.issue_token(request).await {
        Ok(resp) => Ok(json_status(
            &serde_json::json!({"token": resp.into_inner().token}),
            StatusCode::OK,
        )),
        Err(e) if e.code() == tonic::Code::InvalidArgument => Ok(json_status(
            &serde_json::json!({"error": e.message()}),
            StatusCode::BAD_REQUEST,
        )),
        Err(e) => {
            tracing::error!("PatIssuer plugin IssueToken failed: {}", e);
            Ok(json_status(
                &serde_json::json!({"error": "patissuer_plugin_unavailable"}),
                StatusCode::SERVICE_UNAVAILABLE,
            ))
        }
    }
}

fn json_status(body: &serde_json::Value, status: StatusCode) -> Response {
    warp::reply::Reply::into_response(warp::reply::with_status(warp::reply::json(body), status))
}

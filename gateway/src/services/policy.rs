//! 4Orbit policy administration (policy.* JSON-RPC methods).
//!
//! Most methods are forwarded verbatim to the policy plugin, which validates
//! params strictly and authorizes the caller with the same Cedar engine the
//! KMS plugin enforces with. Two methods need other plugins and are composed
//! here: policy.ListKeys (KMS plugin) and policy.IssueAgentToken (the policy
//! plugin approves, the patissuer plugin mints).

use std::time::{SystemTime, UNIX_EPOCH};

use rand::random;
use serde::Deserialize;
use serde_json::value::RawValue;

use crate::caller::Caller;
use crate::plugins::PluginCatalog;
use crate::proto::plugins::patissuer::IssueTokenRequest;
use crate::proto::plugins::policy::CallRequest;
use crate::services::kms::KmsService;

/// Every policy.* method the gateway accepts. Anything else is rejected
/// before a hold is placed.
pub const POLICY_METHODS: &[&str] = &[
    "policy.GetSchema",
    "policy.GetActive",
    "policy.ListVersions",
    "policy.GetVersion",
    "policy.GetTests",
    "policy.ListAudit",
    "policy.Validate",
    "policy.Simulate",
    "policy.Matrix",
    "policy.Diff",
    "policy.RunTests",
    "policy.SaveDraft",
    "policy.PutTests",
    "policy.LoadTemplate",
    "policy.Activate",
    "policy.IssueAgentToken",
    "policy.ListKeys",
];

/// Upper bound on forwarded params, matching the plugin's own limit.
pub const MAX_POLICY_PARAMS_BYTES: usize = 512 * 1024;

#[derive(Debug)]
pub struct PolicyCall {
    pub method: String,
    pub params: Box<RawValue>,
}

impl PolicyCall {
    pub fn parse(method: &str, params_json: &str) -> Result<Self, String> {
        if !POLICY_METHODS.contains(&method) {
            return Err(format!("Unsupported method: {method}"));
        }
        let params = RawValue::from_string(params_json.to_string())
            .map_err(|e| format!("Invalid params for {method}: {e}"))?;
        Ok(Self {
            method: method.to_string(),
            params,
        })
    }

    pub fn validate(&self) -> Result<(), String> {
        let trimmed = self.params.get().trim_start();
        if !(trimmed.starts_with('{') || trimmed == "null") {
            return Err("params must be a JSON object".to_string());
        }
        if self.params.get().len() > MAX_POLICY_PARAMS_BYTES {
            return Err("params too large".to_string());
        }
        Ok(())
    }

    pub async fn execute(
        self,
        caller: &Caller,
        plugin_catalog: &PluginCatalog,
    ) -> Result<Box<RawValue>, tonic::Status> {
        match self.method.as_str() {
            "policy.ListKeys" => list_keys(caller, plugin_catalog).await,
            "policy.IssueAgentToken" => issue_agent_token(self, caller, plugin_catalog).await,
            _ => forward(&self.method, self.params.get(), caller, plugin_catalog).await,
        }
    }
}

async fn forward(
    method: &str,
    params_json: &str,
    caller: &Caller,
    plugin_catalog: &PluginCatalog,
) -> Result<Box<RawValue>, tonic::Status> {
    let mut client = plugin_catalog
        .get_policy_client()
        .await
        .map_err(|_| tonic::Status::unavailable("policy plugin not configured"))?;
    let response = client
        .call(tonic::Request::new(CallRequest {
            method: method.to_string(),
            kms_tenant: caller.tenant.clone(),
            agent_id: caller.agent_id.clone(),
            jti_hash: caller.jti_hash.clone(),
            params_json: params_json.to_string(),
        }))
        .await?
        .into_inner();
    RawValue::from_string(response.result_json)
        .map_err(|_| tonic::Status::internal("policy plugin returned invalid JSON"))
}

async fn list_keys(
    caller: &Caller,
    plugin_catalog: &PluginCatalog,
) -> Result<Box<RawValue>, tonic::Status> {
    let client = plugin_catalog
        .get_kms_client()
        .await
        .map_err(|_| tonic::Status::unavailable("KMS plugin unavailable"))?;
    let value = KmsService::new(client)
        .with_caller(caller.clone())
        .list_keys(&caller.tenant)
        .await?;
    serde_json::value::to_raw_value(&value)
        .map_err(|_| tonic::Status::internal("failed to encode key list"))
}

#[derive(Deserialize)]
struct Approval {
    #[serde(rename = "agentId")]
    agent_id: String,
    #[serde(rename = "ttlSeconds")]
    ttl_seconds: i64,
    #[serde(default)]
    roles: Vec<String>,
}

async fn issue_agent_token(
    call: PolicyCall,
    caller: &Caller,
    plugin_catalog: &PluginCatalog,
) -> Result<Box<RawValue>, tonic::Status> {
    // Agents never mint tokens; the policy plugin enforces this too
    // (platform.agents-never-administer-policy), this just fails early.
    if !caller.agent_id.is_empty() {
        return Err(tonic::Status::permission_denied("request denied by policy"));
    }
    let mut issuer = plugin_catalog
        .get_patissuer_client()
        .await
        .map_err(|_| tonic::Status::unavailable("PAT issuance not configured"))?;
    let approval_raw = forward(&call.method, call.params.get(), caller, plugin_catalog).await?;
    let approval: Approval = serde_json::from_str(approval_raw.get())
        .map_err(|_| tonic::Status::internal("policy plugin returned an invalid approval"))?;
    if !crate::caller::is_valid_agent_id(&approval.agent_id) || approval.ttl_seconds <= 0 {
        return Err(tonic::Status::internal(
            "policy plugin returned an invalid approval",
        ));
    }
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| tonic::Status::internal("clock unavailable"))?
        .as_secs() as i64;
    let expires_at = now + approval.ttl_seconds;
    let jti = format!("agent-{}", hex::encode(random::<[u8; 16]>()));
    let issued = issuer
        .issue_token(tonic::Request::new(IssueTokenRequest {
            jti,
            subject: caller.subject.clone(),
            kms_tenant: caller.token_kms_tenant.clone(),
            expires_at,
            agent_id: approval.agent_id.clone(),
        }))
        .await?
        .into_inner();
    if !issued.ok || issued.token.is_empty() {
        return Err(tonic::Status::unavailable("PAT issuance failed"));
    }
    tracing::info!(agent_id = %approval.agent_id, ttl = approval.ttl_seconds, "Issued agent PAT");
    let body = serde_json::json!({
        "agentId": approval.agent_id,
        "roles": approval.roles,
        "token": issued.token,
        "expiresAt": expires_at,
    });
    serde_json::value::to_raw_value(&body).map_err(|_| tonic::Status::internal("encode token"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_allowlisted_methods_parse() {
        assert!(PolicyCall::parse("policy.Simulate", "{}").is_ok());
        assert!(PolicyCall::parse("policy.DropEverything", "{}").is_err());
        assert!(PolicyCall::parse("kms.Encrypt", "{}").is_err());
    }

    #[test]
    fn params_must_be_an_object() {
        assert!(
            PolicyCall::parse("policy.GetSchema", "{}")
                .unwrap()
                .validate()
                .is_ok()
        );
        assert!(
            PolicyCall::parse("policy.GetSchema", "null")
                .unwrap()
                .validate()
                .is_ok()
        );
        assert!(
            PolicyCall::parse("policy.GetSchema", "[1]")
                .unwrap()
                .validate()
                .is_err()
        );
        assert!(
            PolicyCall::parse("policy.GetSchema", "\"x\"")
                .unwrap()
                .validate()
                .is_err()
        );
    }
}

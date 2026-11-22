//! GitHub calls use verified gateway identity and a separate enforcing plugin.
use crate::caller::Caller;
use crate::plugins::PluginCatalog;
use crate::proto::plugins::github::GithubCallRequest;
use serde_json::value::RawValue;

pub const GITHUB_METHODS: &[&str] = &[
    "github.ListRepositories",
    "github.issue.Create",
    "github.contents.Read",
    "github.issue.Comment",
    "github.branch.Create",
    "github.commit.Create",
    "github.pr.Create",
    "github.pr.Review",
    "github.pr.Merge",
    "github.pr.Get",
];

#[derive(Debug)]
pub struct GithubCall {
    pub method: String,
    params: Box<RawValue>,
}

impl GithubCall {
    pub fn parse(method: &str, params: &str) -> Result<Self, String> {
        if !GITHUB_METHODS.contains(&method) {
            return Err("unsupported GitHub method".into());
        }
        Ok(Self {
            method: method.into(),
            params: RawValue::from_string(params.into()).map_err(|_| "invalid GitHub params")?,
        })
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.params.get().len() > 65000 || !self.params.get().trim_start().starts_with('{') {
            return Err("GitHub params must be an object of at most 65000 bytes".into());
        }
        Ok(())
    }

    pub async fn execute(
        self,
        caller: &Caller,
        plugins: &PluginCatalog,
    ) -> Result<Box<RawValue>, tonic::Status> {
        let mut client = plugins
            .get_github_client()
            .await
            .map_err(|_| tonic::Status::unavailable("GitHub plugin not configured"))?;
        let out = client
            .call(tonic::Request::new(GithubCallRequest {
                method: self.method,
                kms_tenant: caller.tenant.clone(),
                agent_id: caller.agent_id.clone(),
                jti_hash: caller.jti_hash.clone(),
                params_json: self.params.get().into(),
            }))
            .await?
            .into_inner();
        RawValue::from_string(out.result_json)
            .map_err(|_| tonic::Status::internal("invalid GitHub result"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn allowlist_and_size() {
        assert!(
            GithubCall::parse("github.issue.Create", "{}")
                .unwrap()
                .validate()
                .is_ok()
        );
        assert!(GithubCall::parse("github.ListRepositories", "{}").is_ok());
        assert!(GithubCall::parse("github.contents.Read", "{}").is_ok());
        assert!(GithubCall::parse("github.issue.Comment", "{}").is_ok());
        assert!(GithubCall::parse("github.branch.Create", "{}").is_ok());
        assert!(GithubCall::parse("github.commit.Create", "{}").is_ok());
        assert!(GithubCall::parse("github.pr.Create", "{}").is_ok());
        assert!(GithubCall::parse("github.pr.Review", "{}").is_ok());
        assert!(GithubCall::parse("github.pr.Merge", "{}").is_ok());
        assert!(GithubCall::parse("github.pr.Get", "{}").is_ok());
        assert!(GithubCall::parse("github.pr.Close", "{}").is_err());
        assert!(
            GithubCall::parse("github.issue.Create", "null")
                .unwrap()
                .validate()
                .is_err()
        );
        assert!(
            GithubCall::parse(
                "github.issue.Create",
                &format!("{{\"body\":\"{}\"}}", "x".repeat(65000))
            )
            .unwrap()
            .validate()
            .is_err()
        );
    }
}

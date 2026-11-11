//! Development credential store for the UCSB agent integration.
//!
//! The store binds a random bearer credential to an account, agent, action,
//! and resource. It does not replace Orbitport authentication, Cedar policy
//! enforcement, or the account hold. The trusted issuer and operation handler
//! must supply their own verified identities and use the same store instance.

use rand::random;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};
use thiserror::Error;
use tonic::transport::Channel;
use warp::{
    Filter, Rejection, Reply,
    http::{StatusCode, header::CACHE_CONTROL},
    reply::Response,
};

use crate::{
    filters::{ServiceAuthContext, with_service_auth},
    proto::plugins::auth::auth_plugin_client::AuthPluginClient,
};

pub const MAX_TTL_SECONDS: u64 = 900;
const MAX_ACTIVE_CREDENTIALS: usize = 10_000;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentScope {
    pub account_id: String,
    pub agent_id: String,
    pub action: String,
    pub resource: String,
}

impl AgentScope {
    fn is_valid(&self) -> bool {
        [
            &self.account_id,
            &self.agent_id,
            &self.action,
            &self.resource,
        ]
        .into_iter()
        .all(|part| {
            !part.is_empty()
                && part.len() <= 128
                && part
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || b"-._:/@".contains(&byte))
        })
    }
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum DelegationError {
    #[error("invalid delegated credential scope")]
    InvalidScope,
    #[error("delegated credential lifetime must be 1 to 900 seconds")]
    InvalidLifetime,
    #[error("delegated credential store is full")]
    Capacity,
    #[error("trusted clock is unavailable")]
    Clock,
    #[error("delegated credential store is unavailable")]
    Unavailable,
    #[error("delegated credential rejected")]
    Rejected,
}

pub trait Clock: Send + Sync {
    fn now_epoch_seconds(&self) -> Result<i64, DelegationError>;
}

pub struct SystemClock;

impl Clock for SystemClock {
    fn now_epoch_seconds(&self) -> Result<i64, DelegationError> {
        let seconds = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| DelegationError::Clock)?
            .as_secs();
        i64::try_from(seconds).map_err(|_| DelegationError::Clock)
    }
}

#[derive(Clone, Debug)]
struct Grant {
    scope: AgentScope,
    issued_at: i64,
    expires_at: i64,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct IssuedCredential {
    pub token: String,
    pub expires_at: i64,
}

/// A cloneable, process-local store. It is deliberately not a distributed
/// production issuer: restart clears every grant, and a second gateway has
/// an independent store.
#[derive(Clone)]
pub struct AgentCredentialStore {
    grants: Arc<Mutex<HashMap<[u8; 32], Grant>>>,
    clock: Arc<dyn Clock>,
}

impl Default for AgentCredentialStore {
    fn default() -> Self {
        Self::new(Arc::new(SystemClock))
    }
}

impl AgentCredentialStore {
    pub fn new(clock: Arc<dyn Clock>) -> Self {
        Self {
            grants: Arc::new(Mutex::new(HashMap::new())),
            clock,
        }
    }

    /// The caller must already be a trusted issuer. Do not expose this method
    /// on an unauthenticated or customer-token route.
    pub fn issue(
        &self,
        scope: AgentScope,
        ttl_seconds: u64,
    ) -> Result<IssuedCredential, DelegationError> {
        if !scope.is_valid() {
            return Err(DelegationError::InvalidScope);
        }
        if !(1..=MAX_TTL_SECONDS).contains(&ttl_seconds) {
            return Err(DelegationError::InvalidLifetime);
        }
        let now = self.clock.now_epoch_seconds()?;
        let expires_at = now
            .checked_add(i64::try_from(ttl_seconds).map_err(|_| DelegationError::Clock)?)
            .ok_or(DelegationError::Clock)?;
        let mut grants = self
            .grants
            .lock()
            .map_err(|_| DelegationError::Unavailable)?;
        prune(&mut grants, now);
        if grants.len() >= MAX_ACTIVE_CREDENTIALS {
            return Err(DelegationError::Capacity);
        }
        let token = hex::encode(random::<[u8; 32]>());
        grants.insert(
            token_digest(&token),
            Grant {
                scope,
                issued_at: now,
                expires_at,
            },
        );
        Ok(IssuedCredential { token, expires_at })
    }

    /// Returns the identity and scope stored by the trusted issuer. An agent
    /// request supplies an action and resource, never its own account or agent ID.
    pub fn authenticate(
        &self,
        token: &str,
        action: &str,
        resource: &str,
    ) -> Result<AgentScope, DelegationError> {
        if token.len() != 64 || !token.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(DelegationError::Rejected);
        }
        let now = self.clock.now_epoch_seconds()?;
        let mut grants = self
            .grants
            .lock()
            .map_err(|_| DelegationError::Unavailable)?;
        let grant = grants.get(&token_digest(token));
        let accepted = grant.and_then(|grant| {
            (grant.scope.action == action
                && grant.scope.resource == resource
                && now >= grant.issued_at
                && now < grant.expires_at)
                .then(|| grant.scope.clone())
        });
        prune(&mut grants, now);
        accepted.ok_or(DelegationError::Rejected)
    }

    /// Optionally binds the credential to a separately verified account and
    /// agent. The expected identity must never come from request JSON.
    pub fn validate(&self, token: &str, expected: &AgentScope) -> Result<(), DelegationError> {
        let scope = self.authenticate(token, &expected.action, &expected.resource)?;
        if scope == *expected {
            Ok(())
        } else {
            Err(DelegationError::Rejected)
        }
    }

    pub fn revoke(&self, token: &str) -> Result<bool, DelegationError> {
        let mut grants = self
            .grants
            .lock()
            .map_err(|_| DelegationError::Unavailable)?;
        Ok(grants.remove(&token_digest(token)).is_some())
    }
}

fn token_digest(token: &str) -> [u8; 32] {
    Sha256::digest(token.as_bytes()).into()
}

fn prune(grants: &mut HashMap<[u8; 32], Grant>, now: i64) {
    grants.retain(|_, grant| now < grant.expires_at);
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct IssueCredentialBody {
    account_id: String,
    agent_id: String,
    action: String,
    resource: String,
    ttl_seconds: u64,
}

/// Internal-only issuance endpoint. The service auth plugin verifies both the
/// M2M client allowlist and the `agent:delegate` scope before this handler runs.
pub fn issue_route(
    store: AgentCredentialStore,
    auth_client: AuthPluginClient<Channel>,
) -> impl Filter<Extract = (Response,), Error = Rejection> + Clone {
    warp::path!("internal" / "agent" / "credentials")
        .and(warp::post())
        .and(with_service_auth(auth_client, &["agent:delegate"]))
        .and(warp::body::content_length_limit(4096))
        .and(warp::body::json())
        .and(warp::any().map(move || store.clone()))
        .and_then(handle_issue)
}

async fn handle_issue(
    service: ServiceAuthContext,
    body: IssueCredentialBody,
    store: AgentCredentialStore,
) -> Result<Response, Rejection> {
    let scope = AgentScope {
        account_id: body.account_id,
        agent_id: body.agent_id,
        action: body.action,
        resource: body.resource,
    };
    let (status, payload) = match store.issue(scope, body.ttl_seconds) {
        Ok(issued) => {
            tracing::info!(issuer_client_id = %service.client_id, "Issued delegated agent credential");
            (StatusCode::CREATED, serde_json::json!(issued))
        }
        Err(DelegationError::InvalidScope | DelegationError::InvalidLifetime) => (
            StatusCode::BAD_REQUEST,
            serde_json::json!({"error": "invalid_delegation_request"}),
        ),
        Err(DelegationError::Capacity) => (
            StatusCode::TOO_MANY_REQUESTS,
            serde_json::json!({"error": "delegation_capacity_reached"}),
        ),
        Err(_) => (
            StatusCode::SERVICE_UNAVAILABLE,
            serde_json::json!({"error": "delegation_unavailable"}),
        ),
    };
    let mut response =
        warp::reply::with_status(warp::reply::json(&payload), status).into_response();
    response.headers_mut().insert(
        CACHE_CONTROL,
        "no-store".parse().expect("valid static header"),
    );
    Ok(response)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicI64, Ordering};

    struct FixedClock(AtomicI64);

    impl Clock for FixedClock {
        fn now_epoch_seconds(&self) -> Result<i64, DelegationError> {
            Ok(self.0.load(Ordering::SeqCst))
        }
    }

    fn fixture() -> (AgentCredentialStore, Arc<FixedClock>, AgentScope) {
        let clock = Arc::new(FixedClock(AtomicI64::new(1_700_000_000)));
        let scope = AgentScope {
            account_id: "test-account".into(),
            agent_id: "developer-agent".into(),
            action: "github:create-issue".into(),
            resource: "4-Orbit/test-repo".into(),
        };
        (AgentCredentialStore::new(clock.clone()), clock, scope)
    }

    #[test]
    fn credential_is_bound_to_account_agent_action_resource_and_expiry() {
        let (store, clock, scope) = fixture();
        let issued = store.issue(scope.clone(), 60).unwrap();
        assert_eq!(issued.token.len(), 64);
        assert_eq!(issued.expires_at, 1_700_000_060);
        assert_eq!(store.validate(&issued.token, &scope), Ok(()));
        assert_eq!(
            store.authenticate(&issued.token, &scope.action, &scope.resource),
            Ok(scope.clone())
        );

        for other in [
            AgentScope {
                account_id: "other-account".into(),
                ..scope.clone()
            },
            AgentScope {
                agent_id: "security-agent".into(),
                ..scope.clone()
            },
            AgentScope {
                action: "github:close-issue".into(),
                ..scope.clone()
            },
            AgentScope {
                resource: "4-Orbit/other-repo".into(),
                ..scope.clone()
            },
        ] {
            assert_eq!(
                store.validate(&issued.token, &other),
                Err(DelegationError::Rejected)
            );
        }
        clock.0.store(1_700_000_059, Ordering::SeqCst);
        assert_eq!(store.validate(&issued.token, &scope), Ok(()));
        clock.0.store(1_700_000_060, Ordering::SeqCst);
        assert_eq!(
            store.validate(&issued.token, &scope),
            Err(DelegationError::Rejected)
        );
        assert_eq!(
            store.authenticate(&issued.token, &scope.action, &scope.resource),
            Err(DelegationError::Rejected)
        );
    }

    #[test]
    fn malformed_unknown_and_revoked_tokens_are_rejected() {
        let (store, _, scope) = fixture();
        let issued = store.issue(scope.clone(), 60).unwrap();
        assert_eq!(
            store.validate("invalid", &scope),
            Err(DelegationError::Rejected)
        );
        let other = "a".repeat(64);
        assert_eq!(
            store.validate(&other, &scope),
            Err(DelegationError::Rejected)
        );
        assert_eq!(store.revoke(&issued.token), Ok(true));
        assert_eq!(
            store.validate(&issued.token, &scope),
            Err(DelegationError::Rejected)
        );
    }

    #[test]
    fn issuance_rejects_invalid_scope_and_lifetime() {
        let (store, _, scope) = fixture();
        assert_eq!(
            store.issue(scope.clone(), 0).unwrap_err(),
            DelegationError::InvalidLifetime
        );
        assert_eq!(
            store.issue(scope.clone(), 901).unwrap_err(),
            DelegationError::InvalidLifetime
        );
        assert_eq!(
            store
                .issue(
                    AgentScope {
                        agent_id: "".into(),
                        ..scope
                    },
                    60
                )
                .unwrap_err(),
            DelegationError::InvalidScope
        );
    }
}

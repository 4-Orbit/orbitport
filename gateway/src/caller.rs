//! Caller identity forwarded from the gateway to plugins (4Orbit).
//!
//! Tenancy always comes from the account Hold; the agent id only from a
//! verified PAT. Both reach the KMS plugin as gRPC metadata the gateway sets
//! itself: client HTTP headers are never copied into plugin requests.

use sha2::{Digest, Sha256};
use tonic::metadata::MetadataValue;

pub const MD_AGENT_ID: &str = "x-orbitport-agent-id";
pub const MD_JTI_HASH: &str = "x-orbitport-jti-hash";

#[derive(Clone, Debug, Default)]
pub struct Caller {
    /// KMS tenancy from the Hold response.
    pub tenant: String,
    /// Verified agent id; empty = account principal.
    pub agent_id: String,
    /// Short hash of the token id, for audit correlation.
    pub jti_hash: String,
    /// The validated token subject (account id), used as the subject of
    /// agent PATs minted for this account.
    pub subject: String,
    /// The token's own kms_tenant claim, carried into minted agent PATs.
    pub token_kms_tenant: String,
}

impl Caller {
    /// A caller known only by tenant (account principal).
    pub fn tenant_only(tenant: &str) -> Self {
        Self {
            tenant: tenant.to_string(),
            ..Self::default()
        }
    }

    /// Wraps a plugin message in a request carrying this caller's identity.
    pub fn request<T>(&self, message: T) -> tonic::Request<T> {
        let mut req = tonic::Request::new(message);
        if is_valid_agent_id(&self.agent_id) {
            if let Ok(v) = MetadataValue::try_from(self.agent_id.as_str()) {
                req.metadata_mut().insert(MD_AGENT_ID, v);
            }
        } else if !self.agent_id.is_empty() {
            // A malformed id must not silently become an account principal.
            req.metadata_mut()
                .insert(MD_AGENT_ID, MetadataValue::from_static("invalid"));
        }
        if !self.jti_hash.is_empty()
            && let Ok(v) = MetadataValue::try_from(self.jti_hash.as_str())
        {
            req.metadata_mut().insert(MD_JTI_HASH, v);
        }
        req
    }
}

/// Same shape as the Cedar engine's agent ids: 1-64 of [a-z0-9_-].
pub fn is_valid_agent_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 64
        && id
            .bytes()
            .next()
            .is_some_and(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
        && id
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_')
}

/// sha256(jti)[..8] as hex, matching the Go authz.HashJTI.
pub fn hash_jti(jti: &str) -> String {
    if jti.is_empty() {
        return String::new();
    }
    hex::encode(&Sha256::digest(jti.as_bytes())[..8])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn agent_metadata_is_set_only_for_valid_ids() {
        let caller = Caller {
            tenant: "t".into(),
            agent_id: "developer-agent".into(),
            jti_hash: hash_jti("jti-1"),
            ..Caller::default()
        };
        let req = caller.request(());
        assert_eq!(req.metadata().get(MD_AGENT_ID).unwrap(), "developer-agent");
        assert_eq!(req.metadata().get(MD_JTI_HASH).unwrap().len(), 16);

        let account = Caller::tenant_only("t").request(());
        assert!(account.metadata().get(MD_AGENT_ID).is_none());

        let bad = Caller {
            agent_id: "Bad Agent".into(),
            ..Caller::default()
        }
        .request(());
        assert_eq!(bad.metadata().get(MD_AGENT_ID).unwrap(), "invalid");
    }

    #[test]
    fn agent_id_shape() {
        assert!(is_valid_agent_id("a"));
        assert!(is_valid_agent_id("deployment-agent_2"));
        assert!(!is_valid_agent_id(""));
        assert!(!is_valid_agent_id("-x"));
        assert!(!is_valid_agent_id("X"));
        assert!(!is_valid_agent_id(&"a".repeat(65)));
    }

    #[test]
    fn jti_hash_matches_go_engine() {
        // authz.HashJTI("abc") in Go: first 8 bytes of sha256("abc").
        assert_eq!(hash_jti("abc"), "ba7816bf8f01cfea");
        assert_eq!(hash_jti(""), "");
    }
}

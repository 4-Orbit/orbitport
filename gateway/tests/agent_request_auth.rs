use std::sync::{
    Arc,
    atomic::{AtomicI64, AtomicUsize, Ordering},
};

use gateway::{
    agent_delegation::{AgentCredentialStore, AgentScope, Clock, DelegationError},
    agent_request_auth::{AuthenticatedAgentRequest, preview_route, with_agent_request_auth},
    types::GatewayError,
};
use warp::{Filter, http::StatusCode};

struct FixedClock(AtomicI64);

impl Clock for FixedClock {
    fn now_epoch_seconds(&self) -> Result<i64, DelegationError> {
        Ok(self.0.load(Ordering::SeqCst))
    }
}

fn operation_body(action: &str, resource: &str) -> serde_json::Value {
    serde_json::json!({
        "action": action,
        "resource": resource,
        "input": {"title": "Demo issue", "agentId": "security-agent"}
    })
}

#[tokio::test]
async fn agent_identity_comes_from_token_and_rejected_requests_never_reach_handler() {
    let clock = Arc::new(FixedClock(AtomicI64::new(1_700_000_000)));
    let store = AgentCredentialStore::new(clock.clone());
    let scope = AgentScope {
        account_id: "test-account".into(),
        agent_id: "developer-agent".into(),
        action: "github:create-issue".into(),
        resource: "4-Orbit/test-repo".into(),
    };
    let issued = store.issue(scope.clone(), 60).unwrap();
    let calls = Arc::new(AtomicUsize::new(0));
    let handler_calls = calls.clone();
    let route = warp::path!("api" / "v1" / "agent" / "requests")
        .and(warp::post())
        .and(with_agent_request_auth(store))
        .map(move |request: AuthenticatedAgentRequest| {
            handler_calls.fetch_add(1, Ordering::SeqCst);
            warp::reply::json(&serde_json::json!({
                "accountId": request.scope.account_id,
                "agentId": request.scope.agent_id,
                "action": request.scope.action,
                "resource": request.scope.resource,
                "hasInput": request.input.is_some()
            }))
        });
    let path = "/api/v1/agent/requests";
    let body = operation_body(&scope.action, &scope.resource);

    let success = warp::test::request()
        .method("POST")
        .path(path)
        .header("authorization", format!("Bearer {}", issued.token))
        .json(&body)
        .reply(&route)
        .await;
    assert_eq!(success.status(), StatusCode::OK);
    let response: serde_json::Value = serde_json::from_slice(success.body()).unwrap();
    assert_eq!(response["accountId"], "test-account");
    assert_eq!(response["agentId"], "developer-agent");
    assert_eq!(response["hasInput"], true);
    assert_eq!(calls.load(Ordering::SeqCst), 1);

    for (authorization, request_body) in [
        (None, body.clone()),
        (Some("Bearer invalid".to_string()), body.clone()),
        (
            Some(format!("Bearer {}", issued.token)),
            operation_body("github:close-issue", &scope.resource),
        ),
        (
            Some(format!("Bearer {}", issued.token)),
            operation_body(&scope.action, "4-Orbit/other-repo"),
        ),
    ] {
        let request = warp::test::request()
            .method("POST")
            .path(path)
            .json(&request_body);
        let request = if let Some(value) = authorization {
            request.header("authorization", value)
        } else {
            request
        };
        let rejection = request
            .filter(&route)
            .await
            .err()
            .expect("request should be rejected");
        assert!(rejection.find::<GatewayError>().is_some());
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    let mut claimed_identity = body.clone();
    claimed_identity["agentId"] = serde_json::json!("security-agent");
    let rejection = warp::test::request()
        .method("POST")
        .path(path)
        .header("authorization", format!("Bearer {}", issued.token))
        .json(&claimed_identity)
        .filter(&route)
        .await
        .err()
        .expect("caller identity field should be rejected");
    assert!(rejection.find::<GatewayError>().is_none());
    assert_eq!(calls.load(Ordering::SeqCst), 1);

    clock.0.store(1_700_000_060, Ordering::SeqCst);
    let expired = warp::test::request()
        .method("POST")
        .path(path)
        .header("authorization", format!("Bearer {}", issued.token))
        .json(&body)
        .filter(&route)
        .await
        .err()
        .expect("expired token should be rejected");
    assert!(matches!(
        expired.find::<GatewayError>(),
        Some(GatewayError::InvalidCredential)
    ));
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn preview_uses_the_issued_store_and_reports_no_policy_or_operation() {
    let clock = Arc::new(FixedClock(AtomicI64::new(1_700_000_000)));
    let store = AgentCredentialStore::new(clock.clone());
    let scope = AgentScope {
        account_id: "test-account".into(),
        agent_id: "developer-agent".into(),
        action: "github:create-issue".into(),
        resource: "4-Orbit/test-repo".into(),
    };
    let issued = store.issue(scope.clone(), 60).unwrap();
    let route = preview_route(store);
    let path = "/api/v1/agent/requests/preview";
    let body = operation_body(&scope.action, &scope.resource);

    let success = warp::test::request()
        .method("POST")
        .path(path)
        .header("authorization", format!("Bearer {}", issued.token))
        .json(&body)
        .reply(&route)
        .await;
    assert_eq!(success.status(), StatusCode::OK);
    assert_eq!(success.headers()["cache-control"], "no-store");
    let response: serde_json::Value = serde_json::from_slice(success.body()).unwrap();
    assert_eq!(response["accountId"], scope.account_id);
    assert_eq!(response["agentId"], scope.agent_id);
    assert_eq!(response["credentialValid"], true);
    assert_eq!(response["policyEvaluated"], false);
    assert_eq!(response["operationPerformed"], false);
    assert!(response.get("input").is_none());

    clock.0.store(1_700_000_060, Ordering::SeqCst);
    assert!(
        warp::test::request()
            .method("POST")
            .path(path)
            .header("authorization", format!("Bearer {}", issued.token))
            .json(&body)
            .filter(&route)
            .await
            .is_err()
    );
}

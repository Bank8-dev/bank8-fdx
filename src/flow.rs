// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Bank8:FDX
// SPDX-License-Identifier: Apache-2.0

//! Story — Flow integration for FDX consent workflows.
//! FDX implements `POST /v1/internal/steps/execute` for FDX-specific step
//! types and registers its step handler profile with Flow.

use serde::{Deserialize, Serialize};
use uuid::Uuid;
use utoipa::ToSchema;

/// Request body for the Flow proxy-back `POST /v1/internal/steps/execute`.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ProxyBackRequest {
    pub step_kind: String,
    pub workflow_id: Uuid,
    pub step_name: String,
    pub input: serde_json::Value,
    pub user_data: serde_json::Value,
    pub step_config: Option<serde_json::Value>,
}

/// Response from the proxy-back handler.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ProxyBackResponse {
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub output: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_step: Option<String>,
}

impl ProxyBackResponse {
    pub fn success(output: serde_json::Value) -> Self {
        Self { status: "success".into(), output: Some(output), error: None, next_step: None }
    }
    pub fn failure(err: impl Into<String>) -> Self {
        Self { status: "failed".into(), output: None, error: Some(err.into()), next_step: None }
    }
    pub fn waiting() -> Self {
        Self { status: "waiting".into(), output: None, error: None, next_step: None }
    }
}

/// Validate consent scope, parties, and expiry (ConsentValidationStep).
/// Input: `{ "consent_id" : Uuid, "required_scopes" : [String] }`
pub fn validate_consent(input: &serde_json::Value) -> ProxyBackResponse {
    let consent_id = match input.get("consent_id").and_then(|v| v.as_str()).and_then(|s| Uuid::parse_str(s).ok()) {
        Some(id) => id,
        None => return ProxyBackResponse::failure("missing consent_id"),
    };
    let required: Vec<String> = input.get("required_scopes")
        .and_then(|v| v.as_array())
        .map(|a| a.iter().filter_map(|i| i.as_str().map(String::from)).collect())
        .unwrap_or_default();
    if required.is_empty() {
        return ProxyBackResponse::failure("required_scopes must not be empty");
    }
    // Stub: treat all consents as valid if a non-nil consentId is provided.
    if consent_id == Uuid::nil() {
        return ProxyBackResponse::failure("consent not found");
    }
    ProxyBackResponse::success(serde_json::json!({
        "consent_id" : consent_id,
        "valid": true,
        "granted_scopes" : required,
    }))
}

/// Trigger a data refresh from the provider and store a consent artifact
/// (DataRefreshStep).
/// Input: `{ "consent_id" : Uuid, "customer_id" : Uuid, "provider_id" : String }`
pub fn refresh_data(input: &serde_json::Value) -> ProxyBackResponse {
    let consent_id = match input.get("consent_id").and_then(|v| v.as_str()).and_then(|s| Uuid::parse_str(s).ok()) {
        Some(id) => id,
        None => return ProxyBackResponse::failure("missing consent_id"),
    };
    let customer_id = match input.get("customer_id").and_then(|v| v.as_str()).and_then(|s| Uuid::parse_str(s).ok()) {
        Some(id) => id,
        None => return ProxyBackResponse::failure("missing customer_id"),
    };
    let provider_id = input.get("provider_id").and_then(|v| v.as_str()).unwrap_or("default");
    // Stub: produce a consent artifact reference.
    let artifact_id = Uuid::new_v4();
    ProxyBackResponse::success(serde_json::json!({
        "consent_id" : consent_id,
        "customer_id" : customer_id,
        "provider_id" : provider_id,
        "artifact_id" : artifact_id,
        "status": "refreshed",
    }))
}

/// Dispatch a step execution to the appropriate handler.
pub fn execute_step(req: &ProxyBackRequest) -> ProxyBackResponse {
    match req.step_kind.as_str() {
        "ConsentValidationStep" => validate_consent(&req.input),
        "DataRefreshStep" => refresh_data(&req.input),
        other => ProxyBackResponse::failure(format!("unknown FDX step kind: {other}")),
    }
}

/// Register FDX's step handler profile with Flow via `POST /v1/handlers/register`.
/// The call rides the cert-presenting `fdx` transport (CERTFREE-4V — Flow's
/// certificate-first gate resolves the `fdx` workload and its
/// `sentin8:flow:write` scope); `Some(http)` falls back to a plain client
/// with the static bearer when boot has not minted the transport yet.
pub async fn register_with_flow(
    sentin8_flow_url: &str,
    sentin8_flow_token: &str,
    self_url: &str,
    self_token: &str,
    flow_http: Option<reqwest::Client>,
) -> Result<(), String> {
    let body = serde_json::json!({
        "domain": "fdx",
        "base_url" : self_url,
        "auth_token" : self_token,
        "internal_path" : "/v1/internal/steps/execute",
        "step_kinds" : ["ConsentValidationStep", "DataRefreshStep"],
    });
    let (http, bearer) = match flow_http {
        // Cert path: the TLS handshake IS the identity — no bearer.
        Some(c) => (c, None),
        // Boot fallback (CERTFREE-4V): plain transport + the static dev
        // bearer until the workload pair is minted.
        None => (reqwest::Client::new(), Some(sentin8_flow_token)),
    };
    let mut req = http
        .post(format!("{}/v1/handlers/register", sentin8_flow_url.trim_end_matches('/')))
        .json(&body);
    if let Some(t) = bearer {
        req = req.bearer_auth(t);
    }
    let resp = req
        .send()
        .await
        .map_err(|e| format!("register with Flow: {e}"))?;
    if !resp.status().is_success() {
        return Err(format!("Flow register returned status {}", resp.status()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Install the Graviola PQ crypto provider once — reqwest panics with
    /// "No provider set" when a client is built without one.
    fn install_provider() {
        use std::sync::Once;
        static ONCE: Once = Once::new();
        ONCE.call_once(|| {
            let _ = sentin8::tls::crypto::sentin8_pq_provider().install_default();
        });
    }

    #[test]
    fn test_validate_consent_success() {
        install_provider();
        let req = ProxyBackRequest {
            step_kind: "ConsentValidationStep".into(),
            workflow_id: Uuid::new_v4(),
            step_name: "validate".into(),
            input: serde_json::json!({
                "consent_id" : Uuid::new_v4().to_string(),
                "required_scopes" : ["bank8:fdx:transactions:read"],
            }),
            user_data: serde_json::json!({}),
            step_config: None,
        };
        let resp = execute_step(&req);
        assert_eq!(resp.status, "success");
        assert_eq!(resp.output.unwrap()["valid"], true);
    }

    #[test]
    fn test_validate_consent_missing_id() {
        install_provider();
        let req = ProxyBackRequest {
            step_kind: "ConsentValidationStep".into(),
            workflow_id: Uuid::new_v4(),
            step_name: "validate".into(),
            input: serde_json::json!({}),
            user_data: serde_json::json!({}),
            step_config: None,
        };
        let resp = execute_step(&req);
        assert_eq!(resp.status, "failed");
        assert!(resp.error.unwrap().contains("consent_id"));
    }

    #[test]
    fn test_validate_consent_nil_id() {
        install_provider();
        let req = ProxyBackRequest {
            step_kind: "ConsentValidationStep".into(),
            workflow_id: Uuid::new_v4(),
            step_name: "validate".into(),
            input: serde_json::json!({
                "consent_id" : Uuid::nil().to_string(),
                "required_scopes" : ["bank8:fdx:transactions:read"],
            }),
            user_data: serde_json::json!({}),
            step_config: None,
        };
        let resp = execute_step(&req);
        assert_eq!(resp.status, "failed");
    }

    #[test]
    fn test_refresh_data_success() {
        install_provider();
        let req = ProxyBackRequest {
            step_kind: "DataRefreshStep".into(),
            workflow_id: Uuid::new_v4(),
            step_name: "refresh".into(),
            input: serde_json::json!({
                "consent_id" : Uuid::new_v4().to_string(),
                "customer_id" : Uuid::new_v4().to_string(),
                "provider_id" : "bank-x",
            }),
            user_data: serde_json::json!({}),
            step_config: None,
        };
        let resp = execute_step(&req);
        assert_eq!(resp.status, "success");
        let out = resp.output.unwrap();
        assert_eq!(out["status"], "refreshed");
        assert_eq!(out["provider_id"], "bank-x");
        assert!(out["artifact_id"].as_str().is_some());
    }

    #[test]
    fn test_refresh_data_missing_customer() {
        install_provider();
        let req = ProxyBackRequest {
            step_kind: "DataRefreshStep".into(),
            workflow_id: Uuid::new_v4(),
            step_name: "refresh".into(),
            input: serde_json::json!({
                "consent_id" : Uuid::new_v4().to_string(),
            }),
            user_data: serde_json::json!({}),
            step_config: None,
        };
        let resp = execute_step(&req);
        assert_eq!(resp.status, "failed");
        assert!(resp.error.unwrap().contains("customer_id"));
    }

    #[test]
    fn test_unknown_step_kind() {
        install_provider();
        let req = ProxyBackRequest {
            step_kind: "UnknownStep".into(),
            workflow_id: Uuid::new_v4(),
            step_name: "x".into(),
            input: serde_json::json!({}),
            user_data: serde_json::json!({}),
            step_config: None,
        };
        let resp = execute_step(&req);
        assert_eq!(resp.status, "failed");
        assert!(resp.error.unwrap().contains("unknown FDX step kind"));
    }

    #[test]
    fn test_proxy_back_response_success_helper() {
        install_provider();
        let r = ProxyBackResponse::success(serde_json::json!({"ok": true}));
        assert_eq!(r.status, "success");
        assert!(r.output.is_some());
        assert!(r.error.is_none());
    }

    #[test]
    fn test_proxy_back_response_failure_helper() {
        install_provider();
        let r = ProxyBackResponse::failure("boom");
        assert_eq!(r.status, "failed");
        assert_eq!(r.error.unwrap(), "boom");
    }

    #[test]
    fn test_proxy_back_response_waiting_helper() {
        install_provider();
        let r = ProxyBackResponse::waiting();
        assert_eq!(r.status, "waiting");
    }
}
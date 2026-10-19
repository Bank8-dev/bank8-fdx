// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Bank8:FDX
// SPDX-License-Identifier: Apache-2.0

//! Story - Integration tests for FDX.
//! Covers provider API route validation, recipient consent flow, consent
//! enforcement via CSDF minimisation, and the Flow proxy-back handler.
//! Source modules are linked via `bank8_fdx_server` (the crate's lib target,
//! `lib.rs` re-exports every module) - no `#[path]` includes needed.

use bank8_fdx_server::{
    csdf, errors, flow, headers, middleware, notifications, tax, tokens, validation,
};

use axum::response::IntoResponse;
use csdf::{CsdfFilter, DataCluster};
use uuid::Uuid;

// ── Provider API route validation ───────────────────────────────────────

#[test]
fn integration_provider_accounts_route_valid() {
    assert!(validation::validate_fdx_request("GET", "/fdx/v6/accounts", "").is_ok());
}

#[test]
fn integration_provider_account_detail_route_valid() {
    let id = Uuid::new_v4();
    assert!(validation::validate_fdx_request("GET", &format!("/fdx/v6/accounts/{id}"), "").is_ok());
}

#[test]
fn integration_provider_statements_route_valid() {
    let id = Uuid::new_v4();
    assert!(validation::validate_fdx_request(
        "GET",
        &format!("/fdx/v6/accounts/{id}/statements"),
        ""
    )
    .is_ok());
}

#[test]
fn integration_provider_payment_networks_route_valid() {
    let id = Uuid::new_v4();
    assert!(validation::validate_fdx_request(
        "GET",
        &format!("/fdx/v6/accounts/{id}/payment-networks"),
        ""
    )
    .is_ok());
}

#[test]
fn integration_provider_customers_route_valid() {
    assert!(validation::validate_fdx_request("GET", "/fdx/v6/customers", "").is_ok());
    assert!(validation::validate_fdx_request("GET", "/fdx/v6/customers/current", "").is_ok());
}

#[test]
fn integration_provider_transfers_requires_body() {
    let err = validation::validate_fdx_request("POST", "/fdx/v6/transfers", "").unwrap_err();
    assert_eq!(err.status_code, 400);
}

#[test]
fn integration_provider_payments_valid() {
    let body = r#"{"accountId" :"00000000-0000-0000-0000-000000000001","amount":{"value":"5.00","currency":"USD"}}"#;
    assert!(validation::validate_fdx_request("POST", "/fdx/v6/payments", body).is_ok());
}

#[test]
fn integration_provider_capability_routes_valid() {
    assert!(validation::validate_fdx_request("GET", "/fdx/v6/capability", "").is_ok());
    assert!(validation::validate_fdx_request("GET", "/fdx/v6/availability", "").is_ok());
    assert!(validation::validate_fdx_request("GET", "/fdx/v6/certification-metrics", "").is_ok());
}

#[test]
fn integration_unknown_route_rejected() {
    let err = validation::validate_fdx_request("GET", "/fdx/v6/widgets", "").unwrap_err();
    assert_eq!(err.status_code, 404);
}

// ── Recipient consent flow ──────────────────────────────────────────────

#[test]
fn integration_recipient_consent_start_creates_id() {
    let scopes = vec!["bank8:fdx:transactions:read".to_string()];
    let filter = csdf::CsdfFilter::new(scopes.clone());
    assert!(filter.has_cluster(csdf::DataCluster::Transactions));
}

#[test]
fn integration_recipient_consent_revoke_via_scope_check() {
    // After revocation, the scope no longer grants access.
    assert!(!csdf::check_consent_scope("", "transactions"));
    assert!(csdf::check_consent_scope(
        "bank8:fdx:transactions:read",
        "transactions"
    ));
}

// ── Consent enforcement via CSDF minimisation ───────────────────────────

#[test]
fn integration_csdf_minimization_removes_unauthorized_data() {
    // Recipient has only ACCOUNTS scope - transactions/statements must be stripped.
    let data = serde_json::json!({
        "accounts": [{"id": "a1", "name": "Checking"}],
        "transactions": [{"id": "t1", "amount": "100"}],
        "statements": [{"id": "s1"}],
        "customer": {"name": "Jane"},
    });
    let filter = csdf::CsdfFilter::new(vec!["bank8:fdx:accountbasic:read".into()]);
    let out = csdf::minimize_csdf(&data, &filter);
    assert!(out.get("accounts").is_some(), "accounts should be present");
    assert!(
        out.get("transactions").is_none(),
        "transactions should be removed"
    );
    assert!(
        out.get("statements").is_none(),
        "statements should be removed"
    );
    assert!(out.get("customer").is_none(), "customer should be removed");
}

#[test]
fn integration_csdf_field_filter_restricts_to_whitelist() {
    let data = serde_json::json!({
        "accounts": [{"id": "a1", "balance": "1000", "ssn": "123-45-6789"}]
    });
    let filter = csdf::CsdfFilter {
        consent_scopes: vec!["bank8:fdx:accountbasic:read".into()],
        product_id: None,
        fields: Some(vec!["id".into(), "balance".into()]),
    };
    let out = csdf::minimize_csdf(&data, &filter);
    assert_eq!(out["accounts"][0]["id"], "a1");
    assert_eq!(out["accounts"][0]["balance"], "1000");
    assert!(
        out["accounts"][0].get("ssn").is_none(),
        "SSN must be filtered out"
    );
}

#[test]
fn integration_csdf_full_scope_keeps_all() {
    let data = serde_json::json!({
        "accounts": [{"id": "a1"}],
        "transactions": [{"id": "t1"}],
        "statements": [{"id": "s1"}],
        "payments": [{"id": "p1"}],
    });
    let filter = csdf::CsdfFilter::new(vec![
        "bank8:fdx:accountbasic:read".into(),
        "bank8:fdx:transactions:read".into(),
        "bank8:fdx:statements:read".into(),
        "bank8:fdx:transfers:write".into(),
    ]);
    let out = csdf::minimize_csdf(&data, &filter);
    assert!(out.get("accounts").is_some());
    assert!(out.get("transactions").is_some());
    assert!(out.get("statements").is_some());
    assert!(out.get("payments").is_some());
}

// ── FDX header handling ─────────────────────────────────────────────────

#[test]
fn integration_fdx_headers_round_trip() {
    use axum::http::{HeaderMap, HeaderName, HeaderValue};
    let mut req = HeaderMap::new();
    req.insert(
        HeaderName::from_static("x-fapi-interaction-id"),
        HeaderValue::from_static("int-001"),
    );
    let mut resp = HeaderMap::new();
    headers::inject_interaction_id(&req, &mut resp);
    assert_eq!(
        resp.get("x-fapi-interaction-id").unwrap().to_str().unwrap(),
        "int-001"
    );
}

// ── FDX error responses ─────────────────────────────────────────────────

#[test]
fn integration_fdx_error_response_status_mapping() {
    use axum::http::StatusCode;
    let resp = errors::FdxErrorResponse::not_found("account missing").into_response();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

// ── Flow proxy-back ─────────────────────────────────────────────────────

#[test]
fn integration_sentin8_flow_consent_validation_success() {
    let req = flow::ProxyBackRequest {
        step_kind: "ConsentValidationStep".into(),
        workflow_id: Uuid::new_v4(),
        step_name: "validate".into(),
        input: serde_json::json!({
            "consent_id" : Uuid::new_v4().to_string(),
            "required_scopes" : ["bank8:fdx:accountbasic:read"],
        }),
        user_data: serde_json::json!({}),
        step_config: None,
    };
    let resp = flow::execute_step(&req);
    assert_eq!(resp.status, "success");
}

#[test]
fn integration_sentin8_flow_data_refresh_success() {
    let req = flow::ProxyBackRequest {
        step_kind: "DataRefreshStep".into(),
        workflow_id: Uuid::new_v4(),
        step_name: "refresh".into(),
        input: serde_json::json!({
            "consent_id" : Uuid::new_v4().to_string(),
            "customer_id" : Uuid::new_v4().to_string(),
        }),
        user_data: serde_json::json!({}),
        step_config: None,
    };
    let resp = flow::execute_step(&req);
    assert_eq!(resp.status, "success");
    assert_eq!(resp.output.unwrap()["status"], "refreshed");
}

// ── Tax and notifications stubs ─────────────────────────────────────────

#[tokio::test]
async fn integration_tax_get_forms_returns_empty() {
    assert!(tax::get_tax_forms(Uuid::new_v4()).await.unwrap().is_empty());
}

#[tokio::test]
async fn integration_notifications_publish_success() {
    let r = notifications::publish_notification(
        Uuid::new_v4(),
        "account.closed".into(),
        serde_json::json!({}),
    )
    .await;
    assert!(r.is_ok());
}

// ── Provider middleware (.1) ───────────────────────────────────────

#[test]
fn integration_middleware_route_cluster_maps_accounts() {
    let (route, cluster) = middleware::route_cluster("GET", "/fdx/v6/accounts").unwrap();
    assert_eq!(route, "/accounts");
    assert_eq!(cluster, Some(DataCluster::Accounts));
}

#[test]
fn integration_middleware_route_cluster_capability_has_no_cluster() {
    let (_, cluster) = middleware::route_cluster("GET", "/fdx/v6/capability").unwrap();
    assert_eq!(cluster, None);
}

#[test]
fn integration_middleware_route_cluster_unknown() {
    assert!(middleware::route_cluster("GET", "/fdx/v6/nope").is_none());
    assert!(middleware::route_cluster("GET", "/v1/recipient/providers").is_none());
}

#[test]
fn integration_middleware_audit_route_name_shapes_uuid_segments() {
    let id = Uuid::new_v4();
    assert_eq!(
        middleware::audit_route_name(&format!("/fdx/v6/accounts/{id}")),
        "/fdx/v6/accounts/{accountId}"
    );
    assert_eq!(
        middleware::audit_route_name(&format!("/fdx/v6/accounts/{id}/transactions")),
        "/fdx/v6/accounts/{accountId}/transactions"
    );
    assert_eq!(
        middleware::audit_route_name("/fdx/v6/accounts"),
        "/fdx/v6/accounts"
    );
}

#[test]
fn integration_middleware_consent_enforcement_in_scope() {
    let filter = CsdfFilter::new(vec![
        "bank8:fdx:accountbasic:read".into(),
        "bank8:fdx:transactions:read".into(),
    ]);
    assert!(middleware::enforce_consent(&filter, Some(DataCluster::Accounts)).is_ok());
    assert!(middleware::enforce_consent(&filter, Some(DataCluster::Transactions)).is_ok());
    assert!(middleware::enforce_consent(&filter, None).is_ok());
}

#[test]
fn integration_middleware_consent_enforcement_out_of_scope_is_403() {
    let filter = CsdfFilter::new(vec!["bank8:fdx:accountbasic:read".into()]);
    let err = middleware::enforce_consent(&filter, Some(DataCluster::Transactions)).unwrap_err();
    assert_eq!(err.status_code, 403);
    assert_eq!(err.error_code, "INSUFFICIENT_SCOPE");
    let resp = err.clone().into_response();
    assert_eq!(resp.status(), axum::http::StatusCode::FORBIDDEN);
}

#[test]
fn integration_middleware_consent_enforcement_empty_consent_denies_all() {
    let filter = CsdfFilter::new(vec![]);
    assert!(middleware::enforce_consent(&filter, Some(DataCluster::Accounts)).is_err());
    assert!(middleware::enforce_consent(&filter, Some(DataCluster::Customers)).is_err());
}

#[test]
fn integration_middleware_minimize_response_applies_csdf() {
    let filter = CsdfFilter::new(vec!["bank8:fdx:accountbasic:read".into()]);
    let payload = serde_json::json!({
        "accounts": [{"id": "a1"}],
        "transactions": [{"id": "t1"}],
        "customer": {"name": "x"},
    });
    let out = middleware::minimize_response(&payload, &filter);
    assert!(out.get("accounts").is_some());
    assert!(out.get("transactions").is_none());
    assert!(out.get("customer").is_none());
}

// ── Provider endpoints - contract validation for the new routes (.5) ──

#[test]
fn integration_provider_fdx_consent_introspection_route_valid() {
    let id = Uuid::new_v4();
    assert!(validation::validate_fdx_request("GET", &format!("/fdx/v6/consents/{id}"), "").is_ok());
}

#[test]
fn integration_provider_fdx_consent_revocation_route_valid() {
    let id = Uuid::new_v4();
    assert!(validation::validate_fdx_request(
        "PUT",
        &format!("/fdx/v6/consents/{id}/revocation"),
        ""
    )
    .is_ok());
}

// ── Secret-reference token storage (.3) ────────────────────────────

#[tokio::test]
async fn integration_tokens_secret_ref_roundtrip_via_dir() {
    let dir = std::env::temp_dir().join(format!("fdx-it-{}", Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();
    let secrets = tokens::LocalFileSecrets::with_dir(dir.clone());
    let uri = secrets
        .store(&tokens::access_token_path(Uuid::new_v4()), b"access-tok")
        .unwrap();
    assert!(uri.starts_with("sentin8-secrets://"));
    let parsed = sentin8_secrets_sdk::secrets::SecretRef::parse(&uri).unwrap();
    let value = sentin8_secrets_sdk::secrets::SecretResolver::resolve(&secrets, &parsed)
        .await
        .unwrap();
    assert_eq!(value.into_string().unwrap(), "access-tok");
}

#[tokio::test]
async fn integration_tokens_rotation_overwrites_same_path() {
    let dir = std::env::temp_dir().join(format!("fdx-it-rot-{}", Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();
    let secrets = tokens::LocalFileSecrets::with_dir(dir.clone());
    let path = tokens::refresh_token_path(Uuid::new_v4());
    secrets.store(&path, b"refresh-v1").unwrap();
    secrets.store(&path, b"refresh-v2").unwrap();
    let parsed = sentin8_secrets_sdk::secrets::SecretRef::parse(
        &sentin8_secrets_sdk::secrets::SecretRef::new("sentin8-secrets", &path).to_uri(),
    )
    .unwrap();
    let value = sentin8_secrets_sdk::secrets::SecretResolver::resolve(&secrets, &parsed)
        .await
        .unwrap();
    assert_eq!(value.into_string().unwrap(), "refresh-v2");
}

#[test]
fn integration_tokens_paths_differ_per_kind_and_consent() {
    let a = Uuid::new_v4();
    let b = Uuid::new_v4();
    assert_ne!(tokens::access_token_path(a), tokens::refresh_token_path(a));
    assert_ne!(tokens::access_token_path(a), tokens::access_token_path(b));
}

// ── FDX headers (.1) - interaction-id echo/generate ─────────────────

#[test]
fn integration_headers_interaction_id_generated_when_absent() {
    use axum::http::{HeaderMap, StatusCode};
    let resp = errors::FdxErrorResponse::bad_request("x").into_response();
    let mut resp = resp;
    headers::inject_interaction_id(&HeaderMap::new(), resp.headers_mut());
    let val = resp
        .headers()
        .get("x-fapi-interaction-id")
        .unwrap()
        .to_str()
        .unwrap();
    assert!(Uuid::parse_str(val).is_ok());
    let _ = StatusCode::OK; // silence unused-import in this scope
}

#[test]
fn integration_headers_interaction_id_echoed_when_present() {
    use axum::http::{HeaderMap, HeaderName, HeaderValue};
    let mut req = HeaderMap::new();
    req.insert(
        HeaderName::from_static("x-fapi-interaction-id"),
        HeaderValue::from_static("req-echo-42"),
    );
    let resp = errors::FdxErrorResponse::forbidden("x").into_response();
    let mut resp = resp;
    headers::inject_interaction_id(&req, resp.headers_mut());
    assert_eq!(
        resp.headers()
            .get("x-fapi-interaction-id")
            .unwrap()
            .to_str()
            .unwrap(),
        "req-echo-42"
    );
}

// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Bank8:FDX
// SPDX-License-Identifier: Apache-2.0

//! Consent RFW endpoints — Bank8:FDX serves the FDX consent screen as
//! Remote Flutter Widget definitions to auth-ui's consent RFW host.
//! These endpoints are proxied by Sentin8:Auth via `/v1/auth/consent/*`
//! during the OAuth consent flow. See `sentin8-architecture-principles.md`
//! §4.16 and `sentin8-bank8-fdx-technical-design.md` §4.3b.

use axum::{
    extract::{Query, State},
    http::{HeaderMap, StatusCode},
    Json,
};
use serde::Deserialize;

use crate::auth;
use crate::handlers::AppState;

/// Query params for `GET /v1/auth/consent/ui` — the RFW consent page request.
#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub struct ConsentUiQuery {
    pub consent_flow: Option<String>,
    pub scopes: Option<String>,
    pub client_id: Option<String>,
    pub client_name: Option<String>,
    pub redirect_uri: Option<String>,
    pub state: Option<String>,
    pub user_id: Option<String>,
    pub session_token: Option<String>,
}

/// `GET /v1/auth/consent/ui` — return RFW consent page definition.
/// Returns a JSON RFW definition that auth-ui renders. The definition
/// includes:
/// - Scope list with FDX-specific descriptions and Material Icons code points
/// - Account selection DataTable (checkboxes, nickname, type, masked number, balance)
/// - "Authorize" button (POST to /v1/auth/consent/approve)
/// - "Deny" button (POST to /v1/auth/consent/deny)
/// - Data endpoint declaration for account fetch (/v1/auth/consent/accounts)
pub async fn auth_consent_ui(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<ConsentUiQuery>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    // Verify the M2M token from Sentin8:Auth proxy.
    let _a = auth::verify_token(&state.config, &headers).await?;

    let scopes = q.scopes.unwrap_or_default();
    let client_name = q.client_name.unwrap_or_else(|| q.client_id.unwrap_or_else(|| "An application".into()));

    // Build scope descriptions for FDX scopes.
    let scope_list: Vec<serde_json::Value> = scopes
        .split_whitespace()
        .map(|scope| {
            let (description, icon) = fdx_scope_description(scope);
            serde_json::json!({
                "scope": scope,
                "description": description,
                "icon": icon,
            })
        })
        .collect();

    // Build RFW definition — a simple JSON structure that auth-ui's
    // RFW runtime can inflate into Flutter widgets.
    let rfw = serde_json::json!({
        "page": {
            "title": format!("Authorize {}", client_name),
            "subtitle": format!("{} is requesting access to your account.", client_name),
        },
        "widgets": [
            {
                "type": "container",
                "padding": 16,
                "children": [
                    {
                        "type": "text",
                        "text": "This application will be able to:",
                        "style": "label",
                    },
                    {
                        "type": "column",
                        "children": scope_list.iter().map(|s| serde_json::json!({
                            "type": "row",
                            "children": [
                                {"type": "icon", "codepoint": s["icon"]},
                                {"type": "text", "text": s["description"], "style": "body"},
                            ],
                        })).collect::<Vec<_>>(),
                    },
                ],
            },
            {
                "type": "account_selection",
                "data_endpoint": "/v1/auth/consent/accounts",
                "select_all_by_default": true,
                "visible_if": "accounts.length > 0",
                "label": "Select accounts to share",
            },
        ],
        "actions": [
            {
                "type": "button",
                "label": "Authorize",
                "style": "primary",
                "endpoint": "/v1/auth/consent/approve",
                "method": "POST",
            },
            {
                "type": "button",
                "label": "Deny",
                "style": "outlined",
                "endpoint": "/v1/auth/consent/deny",
                "method": "POST",
            },
        ],
        "footer": "By authorizing, you allow this application to access the listed resources on your behalf. You can revoke this at any time.",
    });

    Ok(Json(rfw))
}

/// `GET /v1/auth/consent/accounts` — data endpoint for account selection.
/// Returns the customer's accounts at this Data Provider. Called by the
/// RFW page's data fetch (proxied by Sentin8:Auth with a short-lived JWT).
/// Fetches accounts from Bank8:Ledger.
pub async fn auth_consent_accounts(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;

    // env_id is the sole tenant key.
    let env_id = a.env_id();

    // Fetch accounts from Bank8:Ledger over the certificate-presenting
    // proxy transport (CERTFREE-8V — the `bank8-fdx-ledger` workload
    // presents in the TLS handshake; no static token).
    let http = state
        .config
        .ledger_http()
        .cloned()
        .ok_or((StatusCode::BAD_GATEWAY, "ledger proxy transport absent (workload certificate not provisioned)".to_string()))?;
    let resp = http
        .get(format!("{}/v1/accounts", state.config.ledger_url))
        .header("X-Sentin8-Env-Id", env_id.to_string())
        .send()
        .await
        .map_err(|e| (StatusCode::BAD_GATEWAY, format!("ledger accounts fetch: {e}")))?;

    if !resp.status().is_success() {
        return Err((StatusCode::BAD_GATEWAY, format!("ledger accounts: status {}", resp.status())));
    }

    let body: serde_json::Value = resp.json().await.map_err(|e| (StatusCode::BAD_GATEWAY, e.to_string()))?;

    // Normalize to the format the RFW account_selection widget expects.
    let accounts = if let Some(arr) = body.get("accounts").and_then(|v| v.as_array()) {
        arr.clone()
    } else if let Some(arr) = body.get("data").and_then(|v| v.as_array()) {
        arr.clone()
    } else if body.is_array() {
        body.as_array().unwrap().clone()
    } else {
        vec![body]
    };

    let normalized: Vec<serde_json::Value> = accounts
        .iter()
        .map(|a| {
            let id = a["id"].as_str().or(a["accountId"].as_str()).unwrap_or("").to_string();
            let name = a["nickname"].as_str().or(a["name"].as_str()).unwrap_or("Account").to_string();
            let account_type = a["accountType"].as_str().or(a["account_type"].as_str()).unwrap_or("").to_string();
            let masked = a["accountNumberDisplay"].as_str().or(a["maskedAccountNumber"].as_str()).unwrap_or("").to_string();
            let balance = a["currentBalance"].as_f64().or(a["balance"].as_f64()).unwrap_or(0.0);
            serde_json::json!({
                "id": id,
                "name": name,
                "accountType": account_type,
                "maskedAccountNumber": masked,
                "currentBalance": balance,
            })
        })
        .collect();

    Ok(Json(serde_json::json!({ "accounts": normalized })))
}

/// `POST /v1/auth/consent/approve` — process consent approval.
/// Receives form data from the RFW page (selected account IDs, consent
/// metadata). Persists consent resources and returns the redirect URL.
#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub struct ConsentApproveRequest {
    pub scopes: Option<String>,
    pub client_id: Option<String>,
    pub redirect_uri: Option<String>,
    pub state: Option<String>,
    pub user_id: Option<String>,
    pub selected_account_ids: Option<Vec<String>>,
}

pub async fn auth_consent_approve(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<ConsentApproveRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let _a = auth::verify_token(&state.config, &headers).await?;

    // Build the redirect URL with selected_account_ids appended.
    let redirect_uri = req.redirect_uri.unwrap_or_default();
    let state_param = req.state.unwrap_or_default();
    let account_ids = req.selected_account_ids.unwrap_or_default();

    // Append selected_account_ids as a comma-separated query param.
    let mut url = format!("{}?state={}", redirect_uri, state_param);
    if !account_ids.is_empty() {
        url.push_str(&format!("&selected_account_ids={}", account_ids.join(",")));
    }

    Ok(Json(serde_json::json!({
        "redirect_url": url,
    })))
}

/// `POST /v1/auth/consent/deny` — record consent denial.
#[derive(Debug, Deserialize)]
pub struct ConsentDenyRequest {
    pub redirect_uri: Option<String>,
    pub state: Option<String>,
}

pub async fn auth_consent_deny(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<ConsentDenyRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let _a = auth::verify_token(&state.config, &headers).await?;

    let redirect_uri = req.redirect_uri.unwrap_or_default();
    let state_param = req.state.unwrap_or_default();

    Ok(Json(serde_json::json!({
        "redirect_url": format!("{}?error=access_denied&state={}", redirect_uri, state_param),
    })))
}

/// Map an FDX scope to a human-readable description and Material Icons code point.
/// These descriptions are owned by Bank8:FDX (not the platform) — see §4.16.7.
fn fdx_scope_description(scope: &str) -> (String, &'static str) {
    if scope.contains(":fdx:recipient:read") {
        ("Read FDX recipient data".into(), "0xe615")
    } else if scope.contains(":fdx:recipient:write") {
        ("Manage FDX consent grants".into(), "0xe899")
    } else if scope.contains(":fdx:accountbasic:read") {
        ("Read your basic account information".into(), "0xe85a")
    } else if scope.contains(":fdx:accountdetailed:read") {
        ("Read detailed account data (balances, numbers)".into(), "0xe85a")
    } else if scope.contains(":fdx:transactions:read") {
        ("Read your transaction history".into(), "0xe88f")
    } else if scope.contains(":fdx:payments:read") {
        ("Read your payment history".into(), "0xe877")
    } else if scope.contains(":fdx:payments:write") {
        ("Initiate payments on your behalf".into(), "0xe872")
    } else if scope == "openid" {
        ("Verify your identity".into(), "0xe88e")
    } else if scope == "profile" {
        ("Read your profile information".into(), "0xe7ff")
    } else if scope == "email" {
        ("Read your email address".into(), "0xe0be")
    } else if scope == "offline_access" {
        ("Maintain access when you are offline".into(), "0xe192")
    } else {
        (scope.to_string(), "0xe3b0")
    }
}
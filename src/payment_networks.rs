// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Bank8:FDX
// SPDX-License-Identifier: Apache-2.0

//! FDX v6.5 completion - payment-network detail + revocation (design §5.1).

use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use serde::Deserialize;
use serde_json::Value as JsonValue;
use sqlx::Row;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::common::{db_err, set_tenant_context};
use crate::csdf;
use crate::errors::FdxErrorResponse;
use crate::handlers::{emit_event, AppState};

/// The proxy transport accessor (CERTFREE-8V): the boot-built
/// certificate-presenting client, or a loud error - the proxy NEVER
/// degrades to an unauthenticated call.
fn ledger_http(state: &AppState) -> Result<reqwest::Client, Response> {
    state
        .config
        .ledger_http()
        .cloned()
        .ok_or_else(|| {
            FdxErrorResponse::internal(
                "ledger proxy transport absent (workload certificate not provisioned)".to_string(),
            )
        })
        .map_err(IntoResponse::into_response)
}
use crate::middleware;

/// `GET /fdx/v6/accounts/{accountId}/payment-networks/{paymentNetworkId}`
/// the payment network(s) for this `bankId`/`identifier` pair (; proxy
/// to Ledger's payment-networks read, filtered to the requested id).
#[utoipa::path(
    get,
    path = "/fdx/v6/accounts/{id}/payment-networks/{paymentNetworkId}",
    responses(
        (status = 200, description = "OK", body = serde_json::Value),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Missing the FDX consent/scope gate"),
    ),
    security(),
    tag = "fdx",
)]
pub async fn get_payment_network(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((account_id, network_id)): Path<(Uuid, String)>,
) -> Result<Json<JsonValue>, Response> {
    let _a =
        middleware::provider_authz(&state, &headers, Some(csdf::DataCluster::Payments)).await?;
    let http = ledger_http(&state)?;
    let resp = http
        .get(format!(
            "{}/v1/accounts/{}/payment-networks",
            state.config.ledger_url, account_id
        ))
        .send()
        .await
        .map_err(|e| FdxErrorResponse::internal(format!("ledger fetch: {e}")))?;
    let body: JsonValue = resp
        .json()
        .await
        .map_err(|e| FdxErrorResponse::internal(format!("ledger decode: {e}")))?;
    // Filter the list to the requested paymentNetworkId (spec: returns the
    // network(s) for this bankId+identifier pair).
    let networks = body
        .get("paymentNetworks")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    let matched: Vec<&JsonValue> = networks
        .iter()
        .filter(|n| n.get("paymentNetworkId").and_then(|v| v.as_str()) == Some(network_id.as_str()))
        .collect();
    if matched.is_empty() && !networks.is_empty() {
        return Err(
            FdxErrorResponse::new(404, "1107", "Data not found for request parameters")
                .into_response(),
        );
    }
    Ok(Json(serde_json::json!({ "paymentNetworks": matched })))
}

/// The FDX RevocationRequest (reason/initiator/otherReason) - shared by the
/// payment-network revocation and the consent revocation record
/// (see `consent_records.rs`).
#[derive(Debug, Deserialize, ToSchema)]
pub struct RevocationRequest {
    /// BUSINESS_RULE | SECURITY_EVENT | USER_ACTION | OTHER
    pub reason: String,
    /// DATA_ACCESS_PLATFORM | DATA_PROVIDER | DATA_RECIPIENT | INDIVIDUAL |
    /// MERCHANT | TOKEN_ISSUER | VENDOR
    pub initiator: String,
    #[serde(default)]
    pub other_reason: Option<String>,
}

/// Validate the FDX revocation enums (reason + initiator).
pub fn validate_revocation(req: &RevocationRequest) -> Result<(), Response> {
    const REASONS: &[&str] = &["BUSINESS_RULE", "OTHER", "SECURITY_EVENT", "USER_ACTION"];
    const INITIATORS: &[&str] = &[
        "DATA_ACCESS_PLATFORM",
        "DATA_PROVIDER",
        "DATA_RECIPIENT",
        "INDIVIDUAL",
        "MERCHANT",
        "TOKEN_ISSUER",
        "VENDOR",
    ];
    if !REASONS.contains(&req.reason.as_str()) {
        return Err(FdxErrorResponse::bad_request(format!(
            "invalid reason '{}' (allowed: BUSINESS_RULE, OTHER, SECURITY_EVENT, USER_ACTION)",
            req.reason
        ))
        .into_response());
    }
    if !INITIATORS.contains(&req.initiator.as_str()) {
        return Err(FdxErrorResponse::bad_request(format!("invalid initiator '{}' (allowed: DATA_ACCESS_PLATFORM, DATA_PROVIDER, DATA_RECIPIENT, INDIVIDUAL, MERCHANT, TOKEN_ISSUER, VENDOR)", req.initiator)).into_response());
    }
    Ok(())
}

/// `PUT /fdx/v6/accounts/{accountId}/payment-networks/{paymentNetworkId}/revocation`
/// - revoke the payment network identifier (; persists the revocation
/// record and answers 204 No Content per spec).
#[utoipa::path(
    put,
    path = "/fdx/v6/accounts/{id}/payment-networks/{paymentNetworkId}/revocation",
    responses(
        (status = 200, description = "OK", body = serde_json::Value),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Missing the FDX consent/scope gate"),
    ),
    security(),
    tag = "fdx",
)]
pub async fn revoke_payment_network(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((account_id, network_id)): Path<(Uuid, String)>,
    Json(req): Json<RevocationRequest>,
) -> Result<StatusCode, Response> {
    let a = middleware::provider_authz(&state, &headers, Some(csdf::DataCluster::Payments)).await?;
    validate_revocation(&req)?;
    // Same-transaction discipline (fdx DESIGN.md §5) - see start_consent.
    let mut conn = state.pool.begin().await.map_err(db_err)?;
    set_tenant_context(&mut conn, a.env_id()).await;
    sqlx::query(
        r#"INSERT INTO payment_network_revocations (env_id, account_id, payment_network_id, reason, other_reason, initiator)
           VALUES ($1, $2, $3, $4, $5, $6)"#,
    )
    .bind(a.env_id())
    .bind(account_id)
    .bind(&network_id)
    .bind(&req.reason)
    .bind(req.other_reason.as_deref())
    .bind(&req.initiator)
    .execute(&mut *conn)
    .await
    .map_err(db_err)?;
    conn.commit().await.map_err(db_err)?;
    emit_event(
        &state.pool,
        a.env_id(),
        "bank8:fdx:paymentnetwork:revoked",
        serde_json::json!({ "payment_network_id": network_id }),
    )
    .await;
    Ok(StatusCode::NO_CONTENT)
}

/// `GET /fdx/v6/accounts/{accountId}/payment-networks/{paymentNetworkId}/revocation`
/// - revocation lifecycle events for the identifier.
#[utoipa::path(
    get,
    path = "/fdx/v6/accounts/{id}/payment-networks/{paymentNetworkId}/revocation",
    responses(
        (status = 200, description = "OK", body = serde_json::Value),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Missing the FDX consent/scope gate"),
    ),
    security(),
    tag = "fdx",
)]
pub async fn get_payment_network_revocations(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((account_id, network_id)): Path<(Uuid, String)>,
) -> Result<Json<JsonValue>, Response> {
    let _a =
        middleware::provider_authz(&state, &headers, Some(csdf::DataCluster::Payments)).await?;
    // Same-transaction discipline (fdx DESIGN.md §5) - see start_consent.
    let mut conn = state.pool.begin().await.map_err(db_err)?;
    set_tenant_context(&mut conn, _a.env_id()).await;
    let rows = sqlx::query(
        r#"SELECT id, reason, other_reason, initiator, revoked_at
             FROM payment_network_revocations
            WHERE account_id = $1 AND payment_network_id = $2
            ORDER BY revoked_at DESC"#,
    )
    .bind(account_id)
    .bind(&network_id)
    .fetch_all(&mut *conn)
    .await
    .map_err(db_err)?;
    let events: Vec<JsonValue> = rows
        .iter()
        .map(|r| {
            serde_json::json!({
                "revocationId": r.get::<Uuid, _>("id"),
                "reason": r.get::<String, _>("reason"),
                "otherReason": r.get::<Option<String>, _>("other_reason"),
                "initiator": r.get::<String, _>("initiator"),
                "revokedAt": r.get::<chrono::DateTime<chrono::Utc>, _>("revoked_at"),
            })
        })
        .collect();
    Ok(Json(
        serde_json::json!({ "paymentNetworkLifecycleEvents": events }),
    ))
}

#[cfg(test)]
mod tests {
    use super::{validate_revocation, RevocationRequest};

    #[test]
    fn revocation_reasons_validated() {
        let ok = RevocationRequest {
            reason: "USER_ACTION".into(),
            initiator: "INDIVIDUAL".into(),
            other_reason: None,
        };
        assert!(validate_revocation(&ok).is_ok());
        let bad_reason = RevocationRequest {
            reason: "MAGIC".into(),
            initiator: "INDIVIDUAL".into(),
            other_reason: None,
        };
        assert!(validate_revocation(&bad_reason).is_err());
        let bad_initiator = RevocationRequest {
            reason: "USER_ACTION".into(),
            initiator: "AI".into(),
            other_reason: None,
        };
        assert!(validate_revocation(&bad_initiator).is_err());
        // All spec enums accepted.
        for reason in ["BUSINESS_RULE", "OTHER", "SECURITY_EVENT", "USER_ACTION"] {
            for initiator in [
                "DATA_ACCESS_PLATFORM",
                "DATA_PROVIDER",
                "DATA_RECIPIENT",
                "INDIVIDUAL",
                "MERCHANT",
                "TOKEN_ISSUER",
                "VENDOR",
            ] {
                let r = RevocationRequest {
                    reason: reason.into(),
                    initiator: initiator.into(),
                    other_reason: None,
                };
                assert!(
                    validate_revocation(&r).is_ok(),
                    "{reason}/{initiator} rejected"
                );
            }
        }
    }
}

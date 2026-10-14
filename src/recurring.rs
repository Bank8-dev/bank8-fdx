// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Bank8:FDX
// SPDX-License-Identifier: Apache-2.0

//! FDX v6.5 completion — recurring payments (backed by Bank8:Payments
//! `scheduled_payments`; Sentin8:Cron is the scheduler; design §5.1).

use axum::{
    extract::{Path, State},
    http::HeaderMap,
    response::Response,
    Json,
};
use serde::Deserialize;
use serde_json::Value as JsonValue;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::csdf;
use crate::errors::FdxErrorResponse;
use crate::handlers::{emit_event, AppState};
use crate::middleware;
use crate::money_movement::proxy_payments_get;

/// The fdx→payments proxy transport (CERTFREE-8V): the boot-built
/// `bank8-fdx-payments` certificate-presenting client, or a loud error —
/// the proxy NEVER degrades to an unauthenticated call.
fn payments_http(state: &AppState) -> Result<reqwest::Client, axum::response::Response> {
    state
        .config
        .payments_http()
        .cloned()
        .ok_or_else(|| FdxErrorResponse::internal("payments proxy transport absent (workload certificate not provisioned)".to_string()))
        .map_err(axum::response::IntoResponse::into_response)
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateRecurringPaymentRequest {
    #[serde(alias = "fromAccountId")] pub from_account_id: Uuid,
    pub to_payee_id: Option<Uuid>,
    pub amount: JsonValue,
    /// MONTHLY | WEEKLY | QUARTERLY | ANNUALLY
    pub frequency: String,
    /// NUMBEROFTIMES | UNTILDATE | NONE
    #[serde(default)] pub duration_type: Option<String>,
    #[serde(default)] pub number_of_times: Option<i32>,
    #[serde(default)] pub due_date: Option<String>,
}

/// `POST /fdx/v6/recurring-payments` — create a recurring payment
/// (; backed by Bank8:Payments `scheduled_payments`).
pub async fn create_recurring_payment(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<CreateRecurringPaymentRequest>,
) -> Result<Json<JsonValue>, Response> {
    let a = middleware::provider_authz(&state, &headers, Some(csdf::DataCluster::Payments)).await?;
    // Map the FDX frequency to an RFC 5545 RRULE (Sentin8:Cron is the
    // scheduler; payments `POST /v1beta/scheduled-payments` persists it).
    let rrule = frequency_to_rrule(&req.frequency)
        .ok_or_else(|| FdxErrorResponse::bad_request(format!("unsupported frequency {}", req.frequency)))?;
    let http = payments_http(&state)?;
    let payload = serde_json::json!({
        "account_id": req.from_account_id,
        "amount": req.amount,
        "currency": "CAD",
        "schedule_type": "standing_order",
        "recurrence_rule": rrule,
    });
    let resp = http
        .post(format!("{}/v1beta/scheduled-payments", state.config.payments_url))
        .json(&payload)
        .send()
        .await
        .map_err(|e| FdxErrorResponse::internal(format!("payments fetch: {e}")))?;
    let body: JsonValue = resp
        .json()
        .await
        .map_err(|e| FdxErrorResponse::internal(format!("payments decode: {e}")))?;
    let id = body.get("id").and_then(|v| v.as_str()).unwrap_or("").to_string();
    emit_event(&state.pool, a.env_id(), "bank8:fdx:recurringpayment:created", serde_json::json!({ "recurring_payment_id": id })).await;
    Ok(Json(serde_json::json!({
        "recurringPaymentId": id,
        "frequency": req.frequency,
        "status": "ACTIVE",
        "payments_service": body,
    })))
}

/// Map an FDX frequency enum to an RFC 5545 RRULE FREQ part (UTC-only;
/// Sentin8:Cron is the scheduler).
pub fn frequency_to_rrule(frequency: &str) -> Option<String> {
    match frequency.to_ascii_uppercase().as_str() {
        "WEEKLY" => Some("FREQ=WEEKLY".into()),
        "MONTHLY" => Some("FREQ=MONTHLY".into()),
        "QUARTERLY" => Some("FREQ=MONTHLY;INTERVAL=3".into()),
        "ANNUAL" | "ANNUALLY" | "YEARLY" => Some("FREQ=YEARLY".into()),
        _ => None,
    }
}

/// `GET /fdx/v6/recurring-payments` — search recurring payments (;
/// proxies the payments scheduled-payments list).
pub async fn list_recurring_payments(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<JsonValue>, Response> {
    let _a = middleware::provider_authz(&state, &headers, Some(csdf::DataCluster::Payments)).await?;
    proxy_payments_get(&state, "/v1beta/scheduled-payments").await
}

/// `GET /fdx/v6/recurring-payments/{recurringPaymentId}` — detail.
pub async fn get_recurring_payment(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(rp_id): Path<Uuid>,
) -> Result<Json<JsonValue>, Response> {
    let _a = middleware::provider_authz(&state, &headers, Some(csdf::DataCluster::Payments)).await?;
    proxy_payments_get(&state, &format!("/v1beta/scheduled-payments/{rp_id}")).await
}

/// `GET /fdx/v6/recurring-payments/{recurringPaymentId}/payments` — the
/// executed occurrences (; proxies payments for the source schedule).
pub async fn list_recurring_payment_occurrences(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(rp_id): Path<Uuid>,
) -> Result<Json<JsonValue>, Response> {
    let _a = middleware::provider_authz(&state, &headers, Some(csdf::DataCluster::Payments)).await?;
    proxy_payments_get(&state, &format!("/v1beta/scheduled-payments/{rp_id}")).await
}

#[cfg(test)]
mod tests {
    use super::frequency_to_rrule;

    #[test]
    fn frequency_rrule_mapping() {
        assert_eq!(frequency_to_rrule("MONTHLY"), Some("FREQ=MONTHLY".into()));
        assert_eq!(frequency_to_rrule("weekly"), Some("FREQ=WEEKLY".into()));
        assert_eq!(frequency_to_rrule("QUARTERLY"), Some("FREQ=MONTHLY;INTERVAL=3".into()));
        assert_eq!(frequency_to_rrule("ANNUAL"), Some("FREQ=YEARLY".into()));
        assert_eq!(frequency_to_rrule("YEARLY"), Some("FREQ=YEARLY".into()));
        assert_eq!(frequency_to_rrule("DAILY"), None, "FDX enum has no DAILY");
        assert_eq!(frequency_to_rrule(""), None);
    }
}
// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Bank8:FDX
// SPDX-License-Identifier: Apache-2.0

//! FDX v6.5 completion — money-movement reads + payees proxy (design §5.1).

use axum::{
    extract::{Path, State},
    http::HeaderMap,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::Value as JsonValue;
use uuid::Uuid;

use crate::csdf;
use crate::errors::FdxErrorResponse;

/// The fdx2192payments proxy transport (CERTFREE-8V): the boot-built
/// `bank8-fdx-payments` certificate-presenting client, or a loud error 2014
/// the proxy NEVER degrades to an unauthenticated call.
fn payments_http(state: &AppState) -> Result<reqwest::Client, Response> {
    state
        .config
        .payments_http()
        .cloned()
        .ok_or_else(|| FdxErrorResponse::internal("payments proxy transport absent (workload certificate not provisioned)".to_string()))
        .map_err(IntoResponse::into_response)
}
use crate::handlers::{emit_event, AppState};
use crate::middleware;

/// `GET /fdx/v6/payments/{paymentId}` — payment status read (proxy to
/// Bank8:Payments `GET /v1/payments/{id}`).
pub async fn get_payment(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(payment_id): Path<Uuid>,
) -> Result<Json<JsonValue>, Response> {
    let _a = middleware::provider_authz(&state, &headers, Some(csdf::DataCluster::Payments)).await?;
    proxy_payments_get(&state, &format!("/v1/payments/{payment_id}")).await
}

/// `GET /fdx/v6/transfers/{transferId}` — transfer status read (proxy to
/// Bank8:Payments).
pub async fn get_transfer(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(transfer_id): Path<Uuid>,
) -> Result<Json<JsonValue>, Response> {
    let _a = middleware::provider_authz(&state, &headers, Some(csdf::DataCluster::Transfers)).await?;
    proxy_payments_get(&state, &format!("/v1/transfers/{transfer_id}")).await
}

/// `PATCH /fdx/v6/transfers/{transferId}` — update a transfer (amount/due
/// date where the scheme allows; proxies Bank8:Payments).
pub async fn update_transfer(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(transfer_id): Path<Uuid>,
    Json(req): Json<JsonValue>,
) -> Result<Json<JsonValue>, Response> {
    let _a = middleware::provider_authz(&state, &headers, Some(csdf::DataCluster::Transfers)).await?;
    let http = payments_http(&state)?;
    let resp = http
        .patch(format!("{}/v1/transfers/{}", state.config.payments_url, transfer_id))
        .json(&req)
        .send()
        .await
        .map_err(|e| FdxErrorResponse::internal(format!("payments fetch: {e}")))?;
    let body: JsonValue = resp
        .json()
        .await
        .map_err(|e| FdxErrorResponse::internal(format!("payments decode: {e}")))?;
    Ok(Json(body))
}

/// `DELETE /fdx/v6/transfers/{transferId}` — cancel a transfer (spec
/// `cancelTransfer`; proxies Bank8:Payments cancel where the scheme allows).
pub async fn cancel_transfer(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(transfer_id): Path<Uuid>,
) -> Result<Json<JsonValue>, Response> {
    let a = middleware::provider_authz(&state, &headers, Some(csdf::DataCluster::Transfers)).await?;
    let http = payments_http(&state)?;
    let resp = http
        .delete(format!("{}/v1/transfers/{}", state.config.payments_url, transfer_id))
        .send()
        .await
        .map_err(|e| FdxErrorResponse::internal(format!("payments fetch: {e}")))?;
    let body: JsonValue = resp
        .json()
        .await
        .map_err(|e| FdxErrorResponse::internal(format!("payments decode: {e}")))?;
    emit_event(&state.pool, a.env_id(), "bank8:fdx:transfer:cancelled", body.clone()).await;
    Ok(Json(body))
}

/// Shared GET proxy into Bank8:Payments with the FDX 404 mapping .
pub(crate) async fn proxy_payments_get(state: &AppState, path: &str) -> Result<Json<JsonValue>, Response> {
    let http = payments_http(&state)?;
    let resp = http
        .get(format!("{}{}", state.config.payments_url, path))
        .send()
        .await
        .map_err(|e| FdxErrorResponse::internal(format!("payments fetch: {e}")))?;
    if resp.status() == 404 {
        return Err(FdxErrorResponse::new(404, "1107", "Data not found for request parameters").into_response());
    }
    let body: JsonValue = resp
        .json()
        .await
        .map_err(|e| FdxErrorResponse::internal(format!("payments decode: {e}")))?;
    Ok(Json(body))
}

/// `GET /fdx/v6/payees` — payee search/list (proxy to Bank8:Payments
/// `GET /v1/payees`).
pub async fn list_payees(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<JsonValue>, Response> {
    let _a = middleware::provider_authz(&state, &headers, Some(csdf::DataCluster::Payments)).await?;
    proxy_payments_get(&state, "/v1/payees").await
}

/// `POST /fdx/v6/payees` — create a payee (proxy to Bank8:Payments).
pub async fn create_payee(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<JsonValue>,
) -> Result<Json<JsonValue>, Response> {
    let _a = middleware::provider_authz(&state, &headers, Some(csdf::DataCluster::Payments)).await?;
    let http = payments_http(&state)?;
    let resp = http
        .post(format!("{}/v1/payees", state.config.payments_url))
        .json(&req)
        .send()
        .await
        .map_err(|e| FdxErrorResponse::internal(format!("payments fetch: {e}")))?;
    let body: JsonValue = resp
        .json()
        .await
        .map_err(|e| FdxErrorResponse::internal(format!("payments decode: {e}")))?;
    Ok(Json(body))
}

/// `PUT /fdx/v6/payees/{payeeId}` — update a payee (proxy to Bank8:Payments).
pub async fn update_payee(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(payee_id): Path<Uuid>,
    Json(req): Json<JsonValue>,
) -> Result<Json<JsonValue>, Response> {
    let _a = middleware::provider_authz(&state, &headers, Some(csdf::DataCluster::Payments)).await?;
    let http = payments_http(&state)?;
    let resp = http
        .put(format!("{}/v1/payees/{}", state.config.payments_url, payee_id))
        .json(&req)
        .send()
        .await
        .map_err(|e| FdxErrorResponse::internal(format!("payments fetch: {e}")))?;
    let body: JsonValue = resp
        .json()
        .await
        .map_err(|e| FdxErrorResponse::internal(format!("payments decode: {e}")))?;
    Ok(Json(body))
}
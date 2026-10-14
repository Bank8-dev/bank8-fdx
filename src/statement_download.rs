// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Bank8:FDX
// SPDX-License-Identifier: Apache-2.0

//! FDX v6.5 completion — statement download (design §5.1, storage §5.0a).

use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use serde_json::Value as JsonValue;
use uuid::Uuid;

use crate::csdf;
use crate::errors::FdxErrorResponse;
use crate::handlers::AppState;

/// The proxy transport accessor (CERTFREE-8V): the boot-built
/// certificate-presenting client, or a loud error — the proxy NEVER
/// degrades to an unauthenticated call.
fn ledger_http(state: &AppState) -> Result<reqwest::Client, Response> {
    state
        .config
        .ledger_http()
        .cloned()
        .ok_or_else(|| FdxErrorResponse::internal("ledger proxy transport absent (workload certificate not provisioned)".to_string()))
        .map_err(IntoResponse::into_response)
}
use crate::middleware;

/// `GET /fdx/v6/accounts/{accountId}/statements/{statementId}` — statement
/// download. The Ledger statement object lives in Sentin8:Storage at
/// `buckets/statements/objects/{envId}/{accountId}/{statementId}.pdf`;
/// this handler mints a short-lived read URL via the Storage link API and
/// answers 302 Found with the `Location` header (spec: statement image may
/// be served inline or via redirect; §5.0a signed URLs).
pub async fn download_statement(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((account_id, statement_id)): Path<(Uuid, String)>,
) -> Result<Response, Response> {
    let _a = middleware::provider_authz(&state, &headers, Some(csdf::DataCluster::Statements)).await?;
    // Ask Storage for a signed read URL for the statement object.
    let http = ledger_http(&state)?;
    let bucket = "statements";
    let object = format!("{}/{}/{}.pdf", _a.env_id(), account_id, statement_id);
    let link_req = serde_json::json!({ "object": object });
    let resp = http
        .post(format!("{}/v1/admin/buckets/{}/link", sentin8_storage_base(), bucket))
        .json(&link_req)
        .send()
        .await
        .map_err(|e| FdxErrorResponse::internal(format!("storage link: {e}")))?;
    if !resp.status().is_success() {
        // Statement not found in storage → FDX 404 (data not found 1107).
        let status = resp.status().as_u16();
        if status == 404 {
            return Err(FdxErrorResponse::new(404, "1107", "Data not found for request parameters").into_response());
        }
        return Err(FdxErrorResponse::internal(format!("storage link status {status}")).into_response());
    }
    let body: JsonValue = resp
        .json()
        .await
        .map_err(|e| FdxErrorResponse::internal(format!("storage decode: {e}")))?;
    let url = body
        .get("url")
        .and_then(|v| v.as_str())
        .ok_or_else(|| FdxErrorResponse::internal("storage link missing url"))?;
    let absolute = if url.starts_with('/') {
        format!("{}{}", sentin8_storage_base(), url)
    } else {
        url.to_string()
    };
    // 302 Found — URL returned via the Location header (spec §getAccountStatement).
    Ok((
        StatusCode::FOUND,
        [("Location", absolute)],
    )
        .into_response())
}

fn sentin8_storage_base() -> String {
    // Storage base URL from the shared platform config (single source of
    // truth for domain derivation, architecture-principles §4.9).
    sentin8::config::Sentin8Config::from_env().sentin8_storage_url()
}
// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Bank8:FDX
// SPDX-License-Identifier: Apache-2.0

//! FDX v6.5 completion - payment-initiation parties (PIP family, design §5.1).

use axum::{
    extract::{Path, State},
    http::HeaderMap,
    response::{IntoResponse, Response},
    Json,
};
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use sqlx::Row;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::dtos::*;
use crate::common::{db_err, set_tenant_context};
use crate::csdf;
use crate::errors::FdxErrorResponse;
use crate::handlers::{emit_event, AppState};
use crate::middleware;

#[derive(Debug, Deserialize, ToSchema)]
pub struct CreatePipPartyRequest {
    #[serde(alias = "partyName")]
    pub party_name: String,
    /// MERCHANT | INDIVIDUAL | VENDOR | DATA_RECIPIENT
    #[serde(default = "default_pip_type")]
    pub party_type: String,
    #[serde(default)]
    pub contact: JsonValue,
    #[serde(default)]
    pub registry: Option<String>,
    #[serde(default)]
    pub registered_id: Option<String>,
}
fn default_pip_type() -> String {
    "MERCHANT".into()
}

#[derive(Debug, Serialize, ToSchema)]
pub struct PipPartyResponse {
    pub payment_initiation_party_id: Uuid,
    pub party_name: String,
    pub party_type: String,
    pub status: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

/// `POST /fdx/v6/payment-initiation-parties` - register a payment
/// initiation party.
#[utoipa::path(
    post,
    path = "/fdx/v6/payment-initiation-parties",
    request_body = CreatePipPartyRequest,
    responses(
        (status = 200, description = "Created PIP party", body = PipPartyResponse),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Missing the FDX consent/scope gate"),
    ),
    security(),
    tag = "fdx",)]
pub async fn create_pip_party(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<CreatePipPartyRequest>,
) -> Result<Json<PipPartyResponse>, Response> {
    let a = middleware::provider_authz(&state, &headers, Some(csdf::DataCluster::Payments)).await?;
    // Same-transaction discipline (fdx DESIGN.md §5) - see start_consent.
    let mut conn = state.pool.begin().await.map_err(db_err)?;
    set_tenant_context(&mut conn, a.env_id()).await;
    let row = sqlx::query(
        r#"INSERT INTO payment_initiation_parties (env_id, party_name, party_type, contact, registry, registered_id)
           VALUES ($1, $2, $3, $4, $5, $6)
           RETURNING id, party_name, party_type, status, created_at"#,
    )
    .bind(a.env_id())
    .bind(&req.party_name)
    .bind(&req.party_type)
    .bind(&req.contact)
    .bind(req.registry.as_deref())
    .bind(req.registered_id.as_deref())
    .fetch_one(&mut *conn)
    .await
    .map_err(db_err)?;
    let id: Uuid = row.get("id");
    conn.commit().await.map_err(db_err)?;
    emit_event(
        &state.pool,
        a.env_id(),
        "bank8:fdx:paymentinitiationparty:created",
        serde_json::json!({ "party_id": id }),
    )
    .await;
    Ok(Json(PipPartyResponse {
        payment_initiation_party_id: id,
        party_name: row.get("party_name"),
        party_type: row.get("party_type"),
        status: row.get("status"),
        created_at: row.get("created_at"),
    }))
}

/// `GET /fdx/v6/payment-initiation-parties/{paymentInitiationPartyId}`
/// party detail.
#[utoipa::path(
    get,
    path = "/fdx/v6/payment-initiation-parties/{partyId}",
    responses(
        (status = 200, description = "OK", body = PipPartyDetail),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Missing the FDX consent/scope gate"),
    ),
    security(),
    tag = "fdx",
)]
pub async fn get_pip_party(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(party_id): Path<Uuid>,
) -> Result<Json<PipPartyDetail>, Response> {
    let _a =
        middleware::provider_authz(&state, &headers, Some(csdf::DataCluster::Payments)).await?;
    // Same-transaction discipline (fdx DESIGN.md §5) - see start_consent.
    let mut conn = state.pool.begin().await.map_err(db_err)?;
    set_tenant_context(&mut conn, _a.env_id()).await;
    let row = sqlx::query(
        r#"SELECT id, party_name, party_type, contact, registry, registered_id, status, created_at
             FROM payment_initiation_parties WHERE id = $1"#,
    )
    .bind(party_id)
    .fetch_optional(&mut *conn)
    .await
    .map_err(db_err)?
    .ok_or_else(|| FdxErrorResponse::new(404, "1107", "Data not found for request parameters"))?;
    Ok(Json(PipPartyDetail {
        payment_initiation_party_id: row.get::<Uuid, _>("id"),
        party_name: row.get::<String, _>("party_name"),
        party_type: row.get::<String, _>("party_type"),
        contact: row.get::<JsonValue, _>("contact"),
        registry: row.get::<Option<String>, _>("registry"),
        registered_id: row.get::<Option<String>, _>("registered_id"),
        status: row.get::<String, _>("status"),
        created_at: row.get::<chrono::DateTime<chrono::Utc>, _>("created_at"),
    }))
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct CreatePipPaymentMethodRequest {
    /// e.g. US_ACH | US_RTP | CARD
    #[serde(alias = "methodType")]
    pub method_type: String,
    #[serde(default)]
    pub instrument: JsonValue,
}

/// `POST /fdx/v6/payment-initiation-parties/{partyId}/payment-methods`
/// register a payment method for the party.
#[utoipa::path(
    post,
    path = "/fdx/v6/payment-initiation-parties/{partyId}/payment-methods",
    request_body = CreatePipPaymentMethodRequest,
    responses(
        (status = 200, description = "OK", body = PipPaymentMethodRegistered),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Missing the FDX consent/scope gate"),
    ),
    security(),
    tag = "fdx",)]
pub async fn create_pip_payment_method(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(party_id): Path<Uuid>,
    Json(req): Json<CreatePipPaymentMethodRequest>,
) -> Result<Json<PipPaymentMethodRegistered>, Response> {
    let a = middleware::provider_authz(&state, &headers, Some(csdf::DataCluster::Payments)).await?;
    // Same-transaction discipline (fdx DESIGN.md §5) - see start_consent.
    let mut conn = state.pool.begin().await.map_err(db_err)?;
    set_tenant_context(&mut conn, a.env_id()).await;
    let row = sqlx::query(
        r#"INSERT INTO pip_payment_methods (env_id, party_id, method_type, instrument)
           VALUES ($1, $2, $3, $4)
           RETURNING id"#,
    )
    .bind(a.env_id())
    .bind(party_id)
    .bind(&req.method_type)
    .bind(&req.instrument)
    .fetch_one(&mut *conn)
    .await
    .map_err(db_err)?;
    conn.commit().await.map_err(db_err)?;
    Ok(Json(PipPaymentMethodRegistered {
        payment_method_registration_id: row.get::<Uuid, _>("id"),
        method_type: req.method_type,
        status: "active".into(),
    }))
}

/// `DELETE /fdx/v6/payment-initiation-parties/{partyId}/payment-methods/{regId}`
/// - revoke a party payment method.
#[utoipa::path(
    delete,
    path = "/fdx/v6/payment-initiation-parties/{partyId}/payment-methods/{regId}",
    responses(
        (status = 200, description = "OK", body = PipPaymentMethodRevoked),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Missing the FDX consent/scope gate"),
    ),
    security(),
    tag = "fdx",
)]
pub async fn revoke_pip_payment_method(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((party_id, reg_id)): Path<(Uuid, Uuid)>,
) -> Result<Json<PipPaymentMethodRevoked>, Response> {
    let a = middleware::provider_authz(&state, &headers, Some(csdf::DataCluster::Payments)).await?;
    // Same-transaction discipline (fdx DESIGN.md §5) - see start_consent.
    let mut conn = state.pool.begin().await.map_err(db_err)?;
    set_tenant_context(&mut conn, a.env_id()).await;
    let updated = sqlx::query(
        "UPDATE pip_payment_methods SET status = 'revoked', updated_at = now() WHERE id = $1 AND party_id = $2 AND env_id = $3",
    )
    .bind(reg_id).bind(party_id).bind(a.env_id())
    .execute(&mut *conn)
    .await
    .map_err(db_err)?
    .rows_affected();
    if updated == 0 {
        return Err(
            FdxErrorResponse::new(404, "1107", "Data not found for request parameters")
                .into_response(),
        );
    }
    conn.commit().await.map_err(db_err)?;
    Ok(Json(PipPaymentMethodRevoked {
        payment_method_registration_id: reg_id,
        status: "revoked".into(),
    }))
}

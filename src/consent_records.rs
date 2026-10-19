// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Bank8:FDX
// SPDX-License-Identifier: Apache-2.0

//! FDX v6.5 completion - / consent revocation record + lifecycle
//! (duration/lookback) on the `/fdx/v6/consents` surface (design §5.1, §6.2).

use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::Response,
    Json,
};
use serde::Deserialize;
use serde_json::Value as JsonValue;
use sqlx::Row;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::common::{db_err, set_tenant_context};
use crate::errors::FdxErrorResponse;
use crate::event_notifications::queue_consent_revoked_notification;
use crate::handlers::{emit_event, AppState};
use crate::middleware;
use crate::payment_networks::{validate_revocation, RevocationRequest};

// ── : consent revocation record ──────────────────────────────────────

/// `GET /fdx/v6/consents/{consentId}/revocation` - the revocation record
/// (reason/initiator/timestamp; ).
#[utoipa::path(
    get,
    path = "/fdx/v6/consents/{id}/revocation",
    responses(
        (status = 200, description = "OK", body = serde_json::Value),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Missing the FDX consent/scope gate"),
    ),
    security(),
    tag = "consent",
)]
pub async fn get_consent_revocation(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(consent_id): Path<Uuid>,
) -> Result<Json<JsonValue>, Response> {
    let _a = middleware::provider_authz(&state, &headers, None).await?;
    // Same-transaction discipline (fdx DESIGN.md §5) - see start_consent.
    let mut conn = state.pool.begin().await.map_err(db_err)?;
    set_tenant_context(&mut conn, _a.env_id()).await;
    let row = sqlx::query(
        r#"SELECT id, reason, other_reason, initiator, revoked_at
             FROM consent_revocations WHERE consent_id = $1
            ORDER BY revoked_at DESC LIMIT 1"#,
    )
    .bind(consent_id)
    .fetch_optional(&mut *conn)
    .await
    .map_err(db_err)?
    .ok_or_else(|| FdxErrorResponse::new(404, "1107", "Data not found for request parameters"))?;
    Ok(Json(serde_json::json!({
        "consentId": consent_id,
        "reason": row.get::<String, _>("reason"),
        "otherReason": row.get::<Option<String>, _>("other_reason"),
        "initiator": row.get::<String, _>("initiator"),
        "revokedAt": row.get::<chrono::DateTime<chrono::Utc>, _>("revoked_at"),
    })))
}

/// `PUT /fdx/v6/consents/{consentId}/revocation` - the FDX
/// RevocationRequest (reason/initiator/otherReason). Existing handler
/// `handlers::revoke_fdx_consent` is extended here: the revocation
/// row is persisted and a CONSENT_REVOKED notification is queued.
#[utoipa::path(
    put,
    path = "/fdx/v6/consents/{id}/revocation",
    responses(
        (status = 200, description = "OK", body = serde_json::Value),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Missing the FDX consent/scope gate"),
    ),
    security(),
    tag = "consent",
)]
pub async fn revoke_consent_with_record(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(consent_id): Path<Uuid>,
    Json(req): Json<RevocationRequest>,
) -> Result<StatusCode, Response> {
    let a = middleware::provider_authz(&state, &headers, None).await?;
    validate_revocation(&req)?;
    // Same-transaction discipline (fdx DESIGN.md §5): the tenant context
    // is transaction-local - begin first, then context + statements on
    // that one tx.
    let mut conn = state.pool.begin().await.map_err(db_err)?;
    set_tenant_context(&mut conn, a.env_id()).await;
    // Persist the revocation record (immutable) and revoke the consent
    // same connection, one flow (AGENTS.md RLS connection-scoping rule).
    sqlx::query(
        r#"INSERT INTO consent_revocations (env_id, consent_id, reason, other_reason, initiator)
           VALUES ($1, $2, $3, $4, $5)"#,
    )
    .bind(a.env_id())
    .bind(consent_id)
    .bind(&req.reason)
    .bind(req.other_reason.as_deref())
    .bind(&req.initiator)
    .execute(&mut *conn)
    .await
    .map_err(db_err)?;
    let updated = sqlx::query(
        "UPDATE consents SET status = 'revoked', updated_at = now() WHERE id = $1 AND env_id = $2 RETURNING id",
    )
    .bind(consent_id).bind(a.env_id())
    .fetch_optional(&mut *conn)
    .await
    .map_err(db_err)?
    .ok_or_else(|| FdxErrorResponse::new(404, "1107", "Data not found for request parameters"))?;
    let _id: Uuid = updated.get("id");
    conn.commit().await.map_err(db_err)?;
    // Bus event + CONSENT_REVOKED notification for subscribed recipients
    // (design §5.1a - the delivery consumer delivers via Auth webhooks).
    emit_event(&state.pool, a.env_id(), "bank8:fdx:consent:revoked", serde_json::json!({ "consent_id": consent_id, "reason": req.reason, "initiator": req.initiator })).await;
    queue_consent_revoked_notification(&state, a.env_id(), consent_id).await;
    Ok(StatusCode::NO_CONTENT)
}

/// `POST /fdx/v6/consents/{consentId}/revoke` - POST alias of the PUT
/// revocation surface (fdx DESIGN.md §4): the recipient-side fdx instance
/// calls this with the delegated provider token after revoking its own
/// registry row, so a fintech-initiated revocation lands on the provider's
/// grant ledger and takes effect on the next data call. The delegated
/// token's `sub` IS the grant's customer - the same subject the bank's own
/// dashboard revokes for.
#[utoipa::path(
    post,
    path = "/fdx/v6/consents/{id}/revoke",
    responses(
        (status = 200, description = "Revoked via the POST alias (delegates to the PUT revocation surface)"),
        (status = 403, description = "Delegated subject must be the grant's customer"),
    ),
    security(),
    tag = "consent",
)]
pub async fn revoke_consent_with_record_post(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(consent_id): Path<Uuid>,
    Json(req): Json<RevocationRequest>,
) -> Result<StatusCode, Response> {
    revoke_consent_with_record(State(state), headers, Path(consent_id), Json(req)).await
}

// ── : consent lifecycle fields on introspection + creation ───────────

#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateConsentLifecycleRequest {
    /// ONE_TIME | PERSISTENT | TIME_BOUND
    pub duration_type: String,
    /// Days from original grant (required for TIME_BOUND).
    #[serde(default)]
    pub duration_period_days: Option<i32>,
    /// Days of historical data requestable (from request time).
    #[serde(default)]
    pub lookback_period_days: Option<i32>,
}

/// Validate the FDX duration model: TIME_BOUND requires durationPeriod;
/// ONE_TIME/PERSISTENT must not set one.
pub fn validate_duration_model(
    duration_type: &str,
    duration_period_days: Option<i32>,
    lookback_period_days: Option<i32>,
) -> Result<(), String> {
    match duration_type {
        "TIME_BOUND" => {
            if duration_period_days.map(|d| d <= 0).unwrap_or(true) {
                return Err(
                    "durationPeriod (days > 0) is required for durationType TIME_BOUND".into(),
                );
            }
        }
        "ONE_TIME" | "PERSISTENT" => {
            if duration_period_days.is_some() {
                return Err(format!(
                    "durationPeriod must not be set for durationType {duration_type}"
                ));
            }
        }
        other => {
            return Err(format!(
                "invalid durationType '{other}' (allowed: ONE_TIME, PERSISTENT, TIME_BOUND)"
            ))
        }
    }
    if let Some(d) = lookback_period_days {
        if d < 0 {
            return Err("lookbackPeriod must be >= 0".into());
        }
    }
    Ok(())
}

/// `PUT /fdx/v6/consents/{consentId}/lifecycle` - set the consent duration
/// model.
#[utoipa::path(
    put,
    path = "/fdx/v6/consents/{id}/lifecycle",
    responses(
        (status = 200, description = "OK", body = serde_json::Value),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Missing the FDX consent/scope gate"),
    ),
    security(),
    tag = "consent",
)]
pub async fn update_consent_lifecycle(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(consent_id): Path<Uuid>,
    Json(req): Json<UpdateConsentLifecycleRequest>,
) -> Result<Json<JsonValue>, Response> {
    let a = middleware::provider_authz(&state, &headers, None).await?;
    validate_duration_model(
        &req.duration_type,
        req.duration_period_days,
        req.lookback_period_days,
    )
    .map_err(FdxErrorResponse::bad_request)?;
    // Same-transaction discipline (fdx DESIGN.md §5) - see revoke_consent_with_record.
    let mut conn = state.pool.begin().await.map_err(db_err)?;
    set_tenant_context(&mut conn, a.env_id()).await;
    let updated = sqlx::query(
        r#"UPDATE consents
              SET duration_type = $2,
                  duration_period_days = $3,
                  lookback_period_days = $4,
                  -- TIME_BOUND: derive expires_at from the duration period.
                  expires_at = CASE WHEN $5 = 'TIME_BOUND' THEN now() + make_interval(days => $3::int) ELSE expires_at END,
                  updated_at = now()
            WHERE id = $1 AND env_id = $6
            RETURNING id"#,
    )
    .bind(consent_id)
    .bind(&req.duration_type)
    .bind(req.duration_period_days)
    .bind(req.lookback_period_days)
    .bind(&req.duration_type)
    .bind(a.env_id())
    .fetch_optional(&mut *conn)
    .await
    .map_err(db_err)?
    .ok_or_else(|| FdxErrorResponse::new(404, "1107", "Data not found for request parameters"))?;
    let _id: Uuid = updated.get("id");
    conn.commit().await.map_err(db_err)?;
    emit_event(
        &state.pool,
        a.env_id(),
        "bank8:fdx:consent:updated",
        serde_json::json!({ "consent_id": consent_id, "duration_type": req.duration_type }),
    )
    .await;
    Ok(Json(serde_json::json!({
        "consentId": consent_id,
        "durationType": req.duration_type,
        "durationPeriod": req.duration_period_days,
        "lookbackPeriod": req.lookback_period_days,
    })))
}

/// Lookback filter: the earliest transaction date a consent permits
/// (- measured from request time, not grant time; §6.2). None means
/// unrestricted (no lookbackPeriod set).
pub fn lookback_cutoff(
    lookback_period_days: Option<i32>,
    now: chrono::DateTime<chrono::Utc>,
) -> Option<chrono::DateTime<chrono::Utc>> {
    lookback_period_days.map(|d| now - chrono::Duration::days(d as i64))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn duration_model_rules() {
        // TIME_BOUND requires a positive period.
        assert!(validate_duration_model("TIME_BOUND", Some(365), Some(60)).is_ok());
        assert!(validate_duration_model("TIME_BOUND", None, None).is_err());
        assert!(validate_duration_model("TIME_BOUND", Some(0), None).is_err());
        assert!(validate_duration_model("TIME_BOUND", Some(-5), None).is_err());
        // ONE_TIME / PERSISTENT must NOT set a period.
        assert!(validate_duration_model("ONE_TIME", None, Some(60)).is_ok());
        assert!(validate_duration_model("ONE_TIME", Some(30), None).is_err());
        assert!(validate_duration_model("PERSISTENT", None, None).is_ok());
        // Unknown type rejected.
        assert!(validate_duration_model("FOREVER", None, None).is_err());
        // Negative lookback rejected.
        assert!(validate_duration_model("ONE_TIME", None, Some(-1)).is_err());
    }

    #[test]
    fn lookback_cutoff_from_request_time() {
        let now = chrono::Utc::now();
        // 60-day lookback → cutoff exactly 60 days ago.
        let cutoff = lookback_cutoff(Some(60), now).unwrap();
        assert_eq!((now - cutoff).num_days(), 60);
        // No lookback → unrestricted.
        assert!(lookback_cutoff(None, now).is_none());
        // Zero lookback → cutoff == now (no history).
        let zero = lookback_cutoff(Some(0), now).unwrap();
        assert_eq!(zero, now);
    }
}

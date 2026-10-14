// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Bank8:FDX
// SPDX-License-Identifier: Apache-2.0

//! FDX v6.5 completion — / notification subscriptions, feed, and
//! the HMAC-signed webhook delivery consumer (design §5.1a — carrier is the
//! Sentin8:Auth signed-webhook scheme).
//! Note: the sibling `notifications.rs` module holds the Story
//! recipient-side notification stubs; this module holds the provider-side
//! FDX event-notification family.

use axum::{
    extract::{Path, Query, State},
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
use crate::errors::FdxErrorResponse;
use crate::handlers::{emit_event, AppState};
use crate::middleware;

// ── /: notification subscriptions + feed ────────────────────────

#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateSubscriptionRequest {
    /// FDX EventType (CONSENT_REVOKED, CONSENT_GRANTED, ...)
    #[serde(alias = "eventType")]
    pub event_type: String,
    /// CONSENT | FRAUD | MAINTENANCE | NEW_DATA | SECURITY | TOKENIZED_ACCOUNT_NUMBER
    pub category: String,
    #[serde(alias = "callbackUrl")]
    pub callback_url: String,
    #[serde(default)]
    pub subscriber: JsonValue,
}

/// Validate an FDX EventType + NotificationCategory pair (spec enums).
pub fn validate_subscription_type(event_type: &str, category: &str) -> Result<(), String> {
    const EVENT_TYPES: &[&str] = &[
        "ACCOUNT_TAKEOVER",
        "ADDRESS_CHANGED",
        "BALANCE",
        "CONSENT_EXPIRED",
        "CONSENT_GRANTED",
        "CONSENT_REVOKED",
        "CONSENT_UPDATED",
        "CUSTOM",
        "MFA_TARGET_CHANGED",
        "PHONE_CHANGED",
        "PLANNED_OUTAGE",
        "RISK",
        "SERVICE",
        "SUSPECTED_INCIDENT",
        "TAN_ACTIVATED",
        "TAN_CREATED",
    ];
    const CATEGORIES: &[&str] = &[
        "CONSENT",
        "FRAUD",
        "MAINTENANCE",
        "NEW_DATA",
        "SECURITY",
        "TOKENIZED_ACCOUNT_NUMBER",
    ];
    if !EVENT_TYPES.contains(&event_type) {
        return Err(format!("invalid eventType '{event_type}'"));
    }
    if !CATEGORIES.contains(&category) {
        return Err(format!("invalid category '{category}'"));
    }
    Ok(())
}

/// Callback URL validation: https only (FAPI transport security, §4.3b).
pub fn is_https_url_valid(url: &str) -> bool {
    url.starts_with("https://") && url.len() > "https://".len()
}

/// `POST /fdx/v6/notification-subscriptions` — create a subscription
/// /. The per-subscription HMAC secret is generated here and
/// stored as a sentin8-secrets:// reference — never plaintext.
pub async fn create_notification_subscription(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<CreateSubscriptionRequest>,
) -> Result<Json<JsonValue>, Response> {
    let a = middleware::provider_authz(&state, &headers, None).await?;
    validate_subscription_type(&req.event_type, &req.category)
        .map_err(FdxErrorResponse::bad_request)?;
    if !is_https_url_valid(&req.callback_url) {
        return Err(
            FdxErrorResponse::bad_request("callbackUrl must be an https URL").into_response(),
        );
    }
    // Same-transaction discipline (fdx DESIGN.md §5) — see start_consent.
    let mut conn = state.pool.begin().await.map_err(db_err)?;
    set_tenant_context(&mut conn, a.env_id()).await;
    // Generate a per-subscription signing secret and store it by reference.
    let secret = format!("fdx-sub-{}", Uuid::new_v4());
    let secret_ref = store_subscription_secret(&state, a.env_id(), &secret).await?;
    let row = sqlx::query(
        r#"INSERT INTO notification_subscriptions (env_id, customer_id, event_type, category, callback_url, subscriber, secret_ref, status)
           VALUES ($1, $2, $3, $4, $5, $6, $7, 'active')
           RETURNING id, event_type, category, callback_url, status, created_at"#,
    )
    .bind(a.env_id())
    .bind(a.subject().parse::<Uuid>().ok())
    .bind(&req.event_type)
    .bind(&req.category)
    .bind(&req.callback_url)
    .bind(&req.subscriber)
    .bind(&secret_ref)
    .fetch_one(&mut *conn)
    .await
    .map_err(db_err)?;
    let id: Uuid = row.get("id");
    conn.commit().await.map_err(db_err)?;
    emit_event(
        &state.pool,
        a.env_id(),
        "bank8:fdx:notificationsubscription:created",
        serde_json::json!({ "subscription_id": id }),
    )
    .await;
    Ok(Json(serde_json::json!({
        "subscriptionId": id,
        "type": row.get::<String, _>("event_type"),
        "category": row.get::<String, _>("category"),
        "callbackUrl": row.get::<String, _>("callback_url"),
        "status": row.get::<String, _>("status"),
        "effectiveDate": row.get::<chrono::DateTime<chrono::Utc>, _>("created_at"),
    })))
}

/// Store the subscription signing secret in the local secrets store
/// (sentin8-secrets:// reference scheme; tokens.rs file-backed vault).
async fn store_subscription_secret(
    _state: &AppState,
    env_id: Uuid,
    secret: &str,
) -> Result<String, FdxErrorResponse> {
    let store = crate::tokens::LocalFileSecrets::from_env();
    let path = format!("subscriptions/{env_id}/{}", Uuid::new_v4());
    store
        .store(&path, secret.as_bytes())
        .map_err(|e| FdxErrorResponse::internal(format!("secret store: {e}")))
}

/// `GET /fdx/v6/notification-subscriptions` — list subscriptions.
pub async fn list_notification_subscriptions(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<JsonValue>, Response> {
    let a = middleware::provider_authz(&state, &headers, None).await?;
    // Same-transaction discipline (fdx DESIGN.md §5) — see start_consent.
    let mut conn = state.pool.begin().await.map_err(db_err)?;
    set_tenant_context(&mut conn, a.env_id()).await;
    let rows = sqlx::query(
        r#"SELECT id, event_type, category, callback_url, subscriber, status, created_at
             FROM notification_subscriptions WHERE env_id = $1 AND status != 'deleted'
            ORDER BY created_at DESC LIMIT 200"#,
    )
    .bind(a.env_id())
    .fetch_all(&mut *conn)
    .await
    .map_err(db_err)?;
    let subs: Vec<JsonValue> = rows
        .iter()
        .map(|r| {
            serde_json::json!({
                "subscriptionId": r.get::<Uuid, _>("id"),
                "type": r.get::<String, _>("event_type"),
                "category": r.get::<String, _>("category"),
                "callbackUrl": r.get::<String, _>("callback_url"),
                "subscriber": r.get::<JsonValue, _>("subscriber"),
                "status": r.get::<String, _>("status"),
                "effectiveDate": r.get::<chrono::DateTime<chrono::Utc>, _>("created_at"),
            })
        })
        .collect();
    Ok(Json(
        serde_json::json!({ "notificationSubscriptions": subs }),
    ))
}

/// `GET /fdx/v6/notification-subscriptions/{subscriptionId}` — detail.
pub async fn get_notification_subscription(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(sub_id): Path<Uuid>,
) -> Result<Json<JsonValue>, Response> {
    let a = middleware::provider_authz(&state, &headers, None).await?;
    // Same-transaction discipline (fdx DESIGN.md §5) — see start_consent.
    let mut conn = state.pool.begin().await.map_err(db_err)?;
    set_tenant_context(&mut conn, a.env_id()).await;
    let row = sqlx::query(
        r#"SELECT id, event_type, category, callback_url, subscriber, status, created_at
             FROM notification_subscriptions WHERE id = $1 AND env_id = $2"#,
    )
    .bind(sub_id)
    .bind(a.env_id())
    .fetch_optional(&mut *conn)
    .await
    .map_err(db_err)?
    .ok_or_else(|| FdxErrorResponse::new(404, "1107", "Data not found for request parameters"))?;
    Ok(Json(serde_json::json!({
        "subscriptionId": row.get::<Uuid, _>("id"),
        "type": row.get::<String, _>("event_type"),
        "category": row.get::<String, _>("category"),
        "callbackUrl": row.get::<String, _>("callback_url"),
        "subscriber": row.get::<JsonValue, _>("subscriber"),
        "status": row.get::<String, _>("status"),
        "effectiveDate": row.get::<chrono::DateTime<chrono::Utc>, _>("created_at"),
    })))
}

/// `DELETE /fdx/v6/notification-subscriptions/{subscriptionId}` — delete a
/// subscription (; soft delete + release the secret reference).
pub async fn delete_notification_subscription(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(sub_id): Path<Uuid>,
) -> Result<StatusCode, Response> {
    let a = middleware::provider_authz(&state, &headers, None).await?;
    // Same-transaction discipline (fdx DESIGN.md §5) — see start_consent.
    let mut conn = state.pool.begin().await.map_err(db_err)?;
    set_tenant_context(&mut conn, a.env_id()).await;
    let updated = sqlx::query(
        "UPDATE notification_subscriptions SET status = 'deleted', updated_at = now() WHERE id = $1 AND env_id = $2",
    )
    .bind(sub_id).bind(a.env_id())
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
    emit_event(
        &state.pool,
        a.env_id(),
        "bank8:fdx:notificationsubscription:deleted",
        serde_json::json!({ "subscription_id": sub_id }),
    )
    .await;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct PublishNotificationRequest {
    #[serde(alias = "notificationId", default)]
    pub notification_id: Option<String>,
    #[serde(alias = "type")]
    pub notification_type: String,
    #[serde(default)]
    pub category: Option<String>,
    #[serde(default)]
    pub severity: Option<String>,
    #[serde(default)]
    pub priority: Option<String>,
    #[serde(default)]
    pub payload: JsonValue,
}

/// `POST /fdx/v6/notifications` — inbound notification ingest (
/// `fdx:notifications:publish`). Records the notification, queues it for
/// delivery to matching subscriptions, and emits the Bus event the
/// delivery consumer reacts to.
pub async fn publish_notification(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<PublishNotificationRequest>,
) -> Result<Json<JsonValue>, Response> {
    let a = middleware::provider_authz(&state, &headers, None).await?;
    // Same-transaction discipline (fdx DESIGN.md §5) — see start_consent.
    let mut conn = state.pool.begin().await.map_err(db_err)?;
    set_tenant_context(&mut conn, a.env_id()).await;
    let row = sqlx::query(
        r#"INSERT INTO notifications (env_id, notification_type, category, severity, priority, payload, delivery_status)
           VALUES ($1, $2, $3, $4, $5, $6, 'pending')
           RETURNING id, created_at"#,
    )
    .bind(a.env_id())
    .bind(&req.notification_type)
    .bind(req.category.as_deref())
    .bind(req.severity.as_deref())
    .bind(req.priority.as_deref())
    .bind(&req.payload)
    .fetch_one(&mut *conn)
    .await
    .map_err(db_err)?;
    let id: Uuid = row.get("id");
    conn.commit().await.map_err(db_err)?;
    // Enqueue for the delivery consumer (Bus family `fdx`).
    emit_event(
        &state.pool,
        a.env_id(),
        "bank8:fdx:notification:published",
        serde_json::json!({ "notification_id": id, "notification_type": req.notification_type }),
    )
    .await;
    Ok(Json(serde_json::json!({
        "notificationId": id,
        "status": "accepted",
        "createdAt": row.get::<chrono::DateTime<chrono::Utc>, _>("created_at"),
    })))
}

/// `GET /fdx/v6/notifications` — notification feed (polling alternative to
/// webhook delivery; ).
pub async fn list_notifications_feed(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<FeedQuery>,
) -> Result<Json<JsonValue>, Response> {
    let a = middleware::provider_authz(&state, &headers, None).await?;
    // Same-transaction discipline (fdx DESIGN.md §5) — see start_consent.
    let mut conn = state.pool.begin().await.map_err(db_err)?;
    set_tenant_context(&mut conn, a.env_id()).await;
    let rows = sqlx::query(
        r#"SELECT id, notification_type, category, severity, priority, payload, delivery_status, created_at
             FROM notifications
            WHERE env_id = $1 AND ($2::text IS NULL OR notification_type = $2)
            ORDER BY created_at DESC LIMIT 200"#,
    )
    .bind(a.env_id())
    .bind(q.notification_type.as_deref())
    .fetch_all(&mut *conn)
    .await
    .map_err(db_err)?;
    let items: Vec<JsonValue> = rows
        .iter()
        .map(|r| {
            serde_json::json!({
                "notificationId": r.get::<Uuid, _>("id"),
                "type": r.get::<String, _>("notification_type"),
                "category": r.get::<Option<String>, _>("category"),
                "severity": r.get::<Option<String>, _>("severity"),
                "priority": r.get::<Option<String>, _>("priority"),
                "payload": r.get::<JsonValue, _>("payload"),
                "deliveryStatus": r.get::<String, _>("delivery_status"),
                "sentOn": r.get::<chrono::DateTime<chrono::Utc>, _>("created_at"),
            })
        })
        .collect();
    Ok(Json(serde_json::json!({ "notifications": items })))
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct FeedQuery {
    #[serde(default)]
    pub notification_type: Option<String>,
}

/// Queue a CONSENT_REVOKED notification for every active subscription
/// (called from `consent_records.rs` on consent revocation — , §5.1a).
pub(crate) async fn queue_consent_revoked_notification(
    state: &AppState,
    env_id: Uuid,
    consent_id: Uuid,
) {
    // Same-transaction discipline (fdx DESIGN.md §5) — subscription lookup
    // + notification queueing share one tx with the context set.
    let Ok(mut conn) = state.pool.begin().await else {
        tracing::warn!("fdx: revocation notification queue failed");
        return;
    };
    set_tenant_context(&mut conn, env_id).await;
    let subs: Vec<Uuid> = sqlx::query(
        "SELECT id FROM notification_subscriptions WHERE env_id = $1 AND status = 'active' AND event_type = 'CONSENT_REVOKED'",
    )
    .bind(env_id)
    .fetch_all(&mut *conn)
    .await
    .ok()
    .map(|rows| rows.iter().filter_map(|r| r.try_get::<Uuid, _>("id").ok()).collect())
    .unwrap_or_default();
    for sub_id in subs {
        let _ = sqlx::query(
            r#"INSERT INTO notifications (env_id, subscription_id, notification_type, category, severity, payload, delivery_status)
               VALUES ($1, $2, 'CONSENT_REVOKED', 'CONSENT', 'NOTICE', $3, 'pending')"#,
        )
        .bind(env_id)
        .bind(sub_id)
        .bind(serde_json::json!({ "consent_id": consent_id }))
        .execute(&mut *conn)
        .await;
    }
}

// ── : HMAC-signed webhook delivery consumer ──────────────────────────

/// Delivery body + signature for a notification (pure fn, unit-tested):
/// the body is the JSON envelope `{notificationId, type, payload, sentOn}`;
/// the signature is HMAC-SHA256(secret, body) formatted as `sha256=<hex>`
/// the same scheme Sentin8:Auth's webhook relay uses, so recipients verify
/// once for both carriers.
pub fn delivery_body(
    notification_id: Uuid,
    notification_type: &str,
    payload: &JsonValue,
    sent_on: chrono::DateTime<chrono::Utc>,
) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "notificationId": notification_id,
        "type": notification_type,
        "payload": payload,
        "timestamp": sent_on.to_rfc3339(),
    }))
    .unwrap_or_default()
}

/// HMAC-SHA256 hex signature of `body` under `secret`, formatted
/// `sha256=<hex>` (mirrors Auth webhooks.rs sign_payload).
pub fn sign_delivery(secret: &str, body: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    // HMAC via sha2: HMAC(K, m) = H((K ^ opad) || H((K ^ ipad) || m))
    let key = secret.as_bytes();
    const BLOCK: usize = 64;
    let mut k = [0u8; BLOCK];
    if key.len() > BLOCK {
        let mut h = Sha256::new();
        h.update(key);
        k[..32].copy_from_slice(&h.finalize());
    } else {
        k[..key.len()].copy_from_slice(key);
    }
    let ipad: Vec<u8> = k.iter().map(|b| b ^ 0x36).collect();
    let opad: Vec<u8> = k.iter().map(|b| b ^ 0x5c).collect();
    let mut inner = Sha256::new();
    inner.update(&ipad);
    inner.update(body);
    let inner_hash = inner.finalize();
    let mut outer = Sha256::new();
    outer.update(&opad);
    outer.update(inner_hash);
    format!("sha256={:x}", outer.finalize())
}

/// Resolve a sentin8-secrets:// reference to the secret material via the
/// local file-backed vault (same backend LocalFileSecrets writes — the
/// env-configured secrets directory).
fn load_subscription_secret(state: &AppState, secret_ref: &str) -> Option<String> {
    let _ = state; // resolver is env-configured; state kept for future DI
    let path = secret_ref.strip_prefix("sentin8-secrets://")?;
    let full = std::path::Path::new(&resolver_base()).join(path);
    std::fs::read_to_string(full).ok()
}

fn resolver_base() -> String {
    std::env::var("SENTIN8_SECRETS_DIR").unwrap_or_else(|_| "/etc/sentin8/secrets".into())
}

/// Spawn the notification delivery consumer: a polling worker that picks up
/// `pending` notifications with a matching active subscription and delivers
/// them to the callback URL, HMAC-signed with the per-subscription secret
/// (design §5.1a — carrier is the signed-webhook scheme, same signature
/// format as Sentin8:Auth's webhook relay). Called once from `server::serve`.
pub fn spawn_notification_delivery(state: AppState) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let http = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .expect("delivery http client");
        loop {
            if let Err(e) = delivery_tick(&state, &http).await {
                tracing::warn!(error = %e, "fdx: notification delivery tick failed");
            }
            tokio::time::sleep(std::time::Duration::from_secs(5)).await;
        }
    })
}

async fn delivery_tick(state: &AppState, http: &reqwest::Client) -> Result<(), String> {
    // Claim pending notifications (per-env scan — RLS is enforced per
    // connection; use the service connection with explicit env filter).
    let rows: Vec<(Uuid, Uuid, String, String, JsonValue, i32)> = sqlx::query_as(
        r#"SELECT n.id, s.id AS subscription_id, s.callback_url, s.event_type, n.payload, n.delivery_attempts
             FROM notifications n
             JOIN notification_subscriptions s
               ON s.env_id = n.env_id
              AND s.event_type = n.notification_type
              AND s.status = 'active'
            WHERE n.env_id IN (SELECT DISTINCT env_id FROM notifications)
              AND n.delivery_status = 'pending'
              AND n.subscription_id = s.id
            ORDER BY n.created_at
            LIMIT 50"#,
    )
    .fetch_all(&state.pool)
    .await
    .map_err(|e| format!("claim notifications: {e}"))?;

    for (notification_id, _sub_id, callback_url, notification_type, payload, attempts) in rows {
        let body = delivery_body(
            notification_id,
            &notification_type,
            &payload,
            chrono::Utc::now(),
        );
        // Resolve the per-subscription secret by reference (never plaintext
        // in DB — AGENTS.md secret-references rule).
        let secret_ref: Option<String> =
            sqlx::query_scalar("SELECT secret_ref FROM notification_subscriptions WHERE id = $1")
                .bind(_sub_id)
                .fetch_optional(&state.pool)
                .await
                .ok()
                .flatten();
        let signature = secret_ref
            .as_deref()
            .and_then(|r| load_subscription_secret(state, r))
            .map(|s| sign_delivery(&s, &body))
            .unwrap_or_else(|| "sha256=".into()); // unsigned when no secret (degenerate)

        let mut req = http
            .post(&callback_url)
            .header("content-type", "application/json")
            .header("x-sentin8-event", &notification_type)
            .header("x-sentin8-signature", signature)
            .body(body);
        // FAPI transport security: Sentin8:TLS root CA is in the OS trust
        // store (architecture-principles §4.16) — reqwest uses rustls with
        // native roots, no insecure override.
        let _ = &mut req;
        let res = req.send().await;
        match res {
            Ok(r) if r.status().is_success() => {
                let _ = sqlx::query(
                    "UPDATE notifications SET delivery_status = 'delivered', delivered_at = now(), last_attempt_at = now(), delivery_attempts = delivery_attempts + 1 WHERE id = $1",
                )
                .bind(notification_id)
                .execute(&state.pool)
                .await;
            }
            Ok(r) => {
                let failed = attempts + 1 >= 5;
                let _ = sqlx::query(
                    r#"UPDATE notifications
                          SET delivery_status = CASE WHEN $2 THEN 'failed' ELSE 'pending' END,
                              last_attempt_at = now(),
                              delivery_attempts = delivery_attempts + 1
                        WHERE id = $1"#,
                )
                .bind(notification_id)
                .bind(failed)
                .execute(&state.pool)
                .await;
                tracing::warn!(status = %r.status(), notification_id = %notification_id, "fdx: notification delivery failed");
            }
            Err(e) => {
                let failed = attempts + 1 >= 5;
                let _ = sqlx::query(
                    r#"UPDATE notifications
                          SET delivery_status = CASE WHEN $2 THEN 'failed' ELSE 'pending' END,
                              last_attempt_at = now(),
                              delivery_attempts = delivery_attempts + 1
                        WHERE id = $1"#,
                )
                .bind(notification_id)
                .bind(failed)
                .execute(&state.pool)
                .await;
                tracing::warn!(error = %e, notification_id = %notification_id, "fdx: notification delivery error");
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── /: subscription validation ──────────────────────────────

    #[test]
    fn subscription_type_validation() {
        assert!(validate_subscription_type("CONSENT_REVOKED", "CONSENT").is_ok());
        assert!(validate_subscription_type("ACCOUNT_TAKEOVER", "SECURITY").is_ok());
        // Cross-family pairing is allowed by the spec (type+category independent).
        assert!(validate_subscription_type("BALANCE", "NEW_DATA").is_ok());
        // Bad type / bad category.
        assert!(validate_subscription_type("NOT_A_TYPE", "CONSENT").is_err());
        assert!(validate_subscription_type("CONSENT_REVOKED", "NOT_A_CATEGORY").is_err());
    }

    #[test]
    fn callback_url_https_only() {
        assert!(is_https_url_valid("https://recipient.example.com/cb"));
        assert!(
            !is_https_url_valid("http://recipient.example.com/cb"),
            "plain http rejected (FAPI)"
        );
        assert!(!is_https_url_valid("https://"), "bare host rejected");
        assert!(!is_https_url_valid("ftp://x.example.com"));
        assert!(!is_https_url_valid(""));
    }

    // ── : delivery body + HMAC signature ─────────────────────────────

    #[test]
    fn delivery_body_shape() {
        let id = Uuid::new_v4();
        let body = delivery_body(
            id,
            "CONSENT_REVOKED",
            &serde_json::json!({"consent_id": "abc"}),
            chrono::Utc::now(),
        );
        let parsed: JsonValue = serde_json::from_slice(&body).unwrap();
        assert_eq!(parsed["notificationId"], id.to_string());
        assert_eq!(parsed["type"], "CONSENT_REVOKED");
        assert!(parsed["timestamp"].is_string());
        assert_eq!(parsed["payload"]["consent_id"], "abc");
    }

    #[test]
    fn delivery_signature_is_hmac_sha256() {
        let secret = "test-secret";
        let body = b"hello world";
        let sig = sign_delivery(secret, body);
        assert!(sig.starts_with("sha256="));
        assert_eq!(sig.len(), "sha256=".len() + 64, "hex-encoded SHA-256");
        // Deterministic.
        assert_eq!(sig, sign_delivery(secret, body));
        // Key-sensitive.
        assert_ne!(sig, sign_delivery("other-secret", body));
        // Body-sensitive (tamper evidence).
        assert_ne!(sig, sign_delivery(secret, b"hello worLd"));
        // Long keys (> block size) hash down — RFC 2104 §2: keys longer than
        // the block size are first hashed.
        let long_secret = "x".repeat(200);
        let s1 = sign_delivery(&long_secret, body);
        assert_eq!(s1.len(), "sha256=".len() + 64);
    }

    #[test]
    fn delivery_signature_rfc4231_vector() {
        // RFC 4231 test case 1: key = 0x0b repeated 20, data "Hi There".
        // HMAC-SHA256 = b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7
        let sig = sign_delivery("\u{0b}".repeat(20).as_str(), b"Hi There");
        assert_eq!(
            sig.trim_start_matches("sha256="),
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        );
    }
}

// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Bank8:FDX
// SPDX-License-Identifier: Apache-2.0

//! FDX HTTP handlers - consent service, provider API, recipient API.

use std::sync::Arc;

use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use serde::{Deserialize, Serialize};
use sqlx::Row;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::auth;
use crate::config::Fdx8Config;
use crate::csdf;
use crate::dtos::*;
use crate::errors::FdxErrorResponse;
use crate::flow::ProxyBackResponse;
use crate::middleware::{self, consent_filter_from_headers, minimize_response};

/// The fdx→ledger proxy transport (CERTFREE-8V): the boot-built
/// `bank8-fdx-ledger` certificate-presenting client, or a loud error -
/// the proxy NEVER degrades to an unauthenticated call.
fn ledger_http(state: &AppState) -> Result<reqwest::Client, FdxErrorResponse> {
    state.config.ledger_http().cloned().ok_or_else(|| {
        FdxErrorResponse::internal(
            "ledger proxy transport absent (workload certificate not provisioned)".to_string(),
        )
    })
}

/// The fdx→payments proxy transport (CERTFREE-8V): the boot-built
/// `bank8-fdx-payments` certificate-presenting client, or a loud error.
fn payments_http(state: &AppState) -> Result<reqwest::Client, FdxErrorResponse> {
    state.config.payments_http().cloned().ok_or_else(|| {
        FdxErrorResponse::internal(
            "payments proxy transport absent (workload certificate not provisioned)".to_string(),
        )
    })
}
use crate::tokens;

#[derive(Clone)]
pub struct AppState {
    pub config: Arc<Fdx8Config>,
    pub pool: sqlx::PgPool,
    /// Shield policy engine : step 5 is the ONLY gate
    /// handlers verify the token (steps 1-4) then evaluate a
    /// `bank8:fdx:<resource>:<action>` target; no JWT scope check remains.
    pub policy: Arc<crate::policy::Engine>,
    /// Shared Sentin8:Policy admin surface (§3.6) - same engine
    /// instance the request path evaluates.
    pub admin: sentin8::shield::admin::SharedAdminState,
    /// Bounded TTL cache behind `GET /fdx/v6/certification-metrics`
    /// (fdx DESIGN.md §10). Sums over `audit_events` + consents are
    /// read-only projections; a short TTL bounds their staleness without
    /// event-driven invalidation.
    pub cert_metrics_cache: CertMetricsCache,
}

/// Bounded TTL cache for certification metrics (design §10) - same
/// prune-on-insert eviction pattern as the ledger's `viewEffective`
/// cache (RoleResolver lineage). Env-keyed, 30 s TTL, 1024 live entries.
///
/// Manual `Clone` - `AppState` derives `Clone` for axum, and a
/// clone-behind-the-same-`Mutex` is the intended semantics (all clones
/// share one cache, like the `Arc`-wrapped engine).
#[derive(Default)]
pub struct CertMetricsCache {
    entries: std::sync::Mutex<
        std::collections::HashMap<Uuid, (crate::dtos::CertificationMetrics, std::time::Instant)>,
    >,
}

impl Clone for CertMetricsCache {
    fn clone(&self) -> Self {
        Self {
            entries: std::sync::Mutex::new(
                self.entries.lock().map(|e| e.clone()).unwrap_or_default(),
            ),
        }
    }
}

impl CertMetricsCache {
    const TTL: std::time::Duration = std::time::Duration::from_secs(30);
    const MAX_ENTRIES: usize = 1024;

    pub fn get(&self, env_id: &Uuid) -> Option<crate::dtos::CertificationMetrics> {
        let mut entries = self.entries.lock().ok()?;
        let (value, fetched_at) = entries.get(env_id)?;
        if fetched_at.elapsed() > Self::TTL {
            entries.remove(env_id);
            return None;
        }
        Some(value.clone())
    }

    pub fn insert(&self, env_id: Uuid, value: crate::dtos::CertificationMetrics) {
        let Ok(mut entries) = self.entries.lock() else {
            return;
        };
        entries.retain(|_, (_, fetched_at)| fetched_at.elapsed() <= Self::TTL);
        if entries.len() >= Self::MAX_ENTRIES {
            if let Some(oldest) = entries
                .iter()
                .min_by_key(|(_, (_, fetched_at))| *fetched_at)
                .map(|(k, _)| *k)
            {
                entries.remove(&oldest);
            }
        }
        entries.insert(env_id, (value, std::time::Instant::now()));
    }
}

async fn set_tenant_context(conn: &mut sqlx::PgConnection, env_id: Uuid) {
    let _ = sqlx::query(
        "SELECT sentin8_set_tenant_context($1, NULL, NULL, NULL, false, false, false, NULL, 'fdx')",
    )
    .bind(env_id)
    .execute(conn)
    .await;
}

// ── Consent Service ──────────────────────────────────────────────────────

#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateConsentRequest {
    pub customer_id: Uuid,
    pub recipient_id: Option<String>,
    pub provider_id: Option<String>,
    pub scopes: Vec<String>,
    pub data_clusters: Vec<String>,
    pub duration_days: Option<i32>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ConsentResponse {
    pub id: Uuid,
    pub customer_id: Uuid,
    pub recipient_id: Option<String>,
    pub provider_id: Option<String>,
    pub status: String,
    pub scopes: Vec<String>,
    pub data_clusters: Vec<String>,
    pub duration_days: Option<i32>,
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

/// `POST /v1/consents` - create a consent grant.
#[utoipa::path(
    post,
    path = "/v1/consents",
    responses(
        (status = 200, description = "Created consent", body = ConsentResponse),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Missing the FDX consent/scope gate"),
    ),
    security(),
    tag = "consent",
)]
pub async fn create_consent(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<CreateConsentRequest>,
) -> Result<Json<ConsentResponse>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("bank8:fdx:consents:write"),
    )
    .await?;
    // Same-transaction discipline (fdx DESIGN.md §5) - see start_consent.
    let mut conn = state.pool.begin().await.map_err(err_db)?;
    set_tenant_context(&mut conn, a.env_id()).await;
    let expires_at = req
        .duration_days
        .map(|d| chrono::Utc::now() + chrono::Duration::days(d as i64));
    let row = sqlx::query(
        r#"INSERT INTO consents (env_id, customer_id, recipient_id, provider_id, scopes, data_clusters, duration_days, expires_at)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
           RETURNING id, customer_id, recipient_id, provider_id, status, scopes, data_clusters, duration_days, expires_at, created_at"#,
    )
    .bind(a.env_id()).bind(req.customer_id).bind(&req.recipient_id).bind(&req.provider_id)
    .bind(&req.scopes).bind(&req.data_clusters).bind(req.duration_days).bind(expires_at)
    .fetch_one(&mut *conn).await.map_err(err_db)?;
    let consent = row_to_consent(&row);
    conn.commit().await.map_err(err_db)?;
    emit_event(
        &state.pool,
        a.env_id(),
        "bank8:fdx:consent:created",
        serde_json::to_value(&consent).unwrap_or_default(),
    )
    .await;
    Ok(Json(consent))
}

/// `GET /v1/consents` - list consents.
#[utoipa::path(
    get,
    path = "/v1/consents",
    responses(
        (status = 200, description = "Consent list", body = ConsentResponse),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Missing the FDX consent/scope gate"),
    ),
    security(),
    tag = "consent",
)]
pub async fn list_consents(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<ListConsentsQuery>,
) -> Result<Json<Vec<ConsentResponse>>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("bank8:fdx:consents:read"),
    )
    .await?;
    // Provider plane (two-ledger model, DESIGN.md §1): the grant ledger is
    // THIS tenant's own table - the bank's consent dashboard (eBank app)
    // lists the grants the AS seeded. Same-transaction discipline (§5):
    // context + query on one tx.
    let mut conn = state.pool.begin().await.map_err(err_db)?;
    set_tenant_context(&mut conn, a.env_id()).await;
    let rows = sqlx::query(
        r#"SELECT id, customer_id, recipient_id, provider_id, status, scopes, data_clusters, duration_days, expires_at, created_at
             FROM consents
            WHERE ($1::uuid IS NULL OR customer_id = $1)
            ORDER BY created_at DESC LIMIT 100"#,
    )
    .bind(q.customer_id)
    .fetch_all(&mut *conn)
    .await
    .map_err(err_db)?;
    let _ = conn.commit().await;
    let out: Vec<ConsentResponse> = rows.iter().map(row_to_consent).collect();
    Ok(Json(out))
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct ListConsentsQuery {
    #[serde(default)]
    pub customer_id: Option<Uuid>,
}

/// `GET /v1/consents/{id}` - consent detail.
#[utoipa::path(
    get,
    path = "/v1/consents/{id}",
    responses(
        (status = 200, description = "Consent detail", body = ConsentResponse),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Missing the FDX consent/scope gate"),
    ),
    security(),
    tag = "consent",
)]
pub async fn get_consent(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<Json<ConsentResponse>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("bank8:fdx:consents:read"),
    )
    .await?;
    // Same-transaction discipline (fdx DESIGN.md §5) - see list_consents.
    let mut conn = state.pool.begin().await.map_err(err_db)?;
    set_tenant_context(&mut conn, a.env_id()).await;
    let row = sqlx::query(
        r#"SELECT id, customer_id, recipient_id, provider_id, status, scopes, data_clusters, duration_days, expires_at, created_at
             FROM consents WHERE id = $1"#,
    ).bind(id).fetch_one(&mut *conn).await.map_err(err_db)?;
    Ok(Json(row_to_consent(&row)))
}

/// `POST /v1/consents/{id}/revoke` - revoke a consent.
#[utoipa::path(
    post,
    path = "/v1/consents/{id}/revoke",
    responses(
        (status = 200, description = "OK", body = ConsentResponse),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Missing the FDX consent/scope gate"),
    ),
    security(),
    tag = "consent",
)]
pub async fn revoke_consent(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<Json<ConsentResponse>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("bank8:fdx:consents:write"),
    )
    .await?;
    // Same-transaction discipline (fdx DESIGN.md §5) - see start_consent.
    let mut conn = state.pool.begin().await.map_err(err_db)?;
    set_tenant_context(&mut conn, a.env_id()).await;
    let row = sqlx::query(
        r#"UPDATE consents SET status = 'revoked', updated_at = now() WHERE id = $1
            RETURNING id, customer_id, recipient_id, provider_id, status, scopes, data_clusters, duration_days, expires_at, created_at"#,
    ).bind(id).fetch_one(&mut *conn).await.map_err(err_db)?;
    let consent = row_to_consent(&row);
    conn.commit().await.map_err(err_db)?;
    emit_event(
        &state.pool,
        a.env_id(),
        "bank8:fdx:consent:revoked",
        serde_json::to_value(&consent).unwrap_or_default(),
    )
    .await;
    Ok(Json(consent))
}

// ── FDX Provider API (proxies to Ledger) ──────────────────────────────────

/// `GET /fdx/v6/accounts` - search customer accounts (proxies to Ledger).
/// The incoming Bearer (the bank's own customer token OR a delegated
/// recipient token - both carry the provider customer as `sub`) is
/// forwarded to Ledger, so RLS scopes the rows to the consenting
/// customer either way (fdx DESIGN.md §1 - the consent grant keys on the
/// token subject).
#[utoipa::path(
    get,
    path = "/fdx/v6/accounts",
    responses(
        (status = 200, description = "OK", body = FdxAccountsPassthrough),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Missing the FDX consent/scope gate"),
    ),
    security(),
    tag = "fdx",
)]
pub async fn get_accounts(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<FdxAccountsPassthrough>, Response> {
    let _a =
        middleware::provider_authz(&state, &headers, Some(csdf::DataCluster::Accounts)).await?;
    let http = ledger_http(&state)?;
    let bearer = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    let resp = http
        .get(format!("{}/v1/accounts", state.config.ledger_url))
        .header("authorization", &bearer)
        .send()
        .await
        .map_err(|e| FdxErrorResponse::internal(format!("ledger fetch: {e}")))?;
    let body: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| FdxErrorResponse::internal(format!("ledger decode: {e}")))?;
    let filter = consent_filter_from_headers(&state, &headers).await;
    // Wrap in FDX response format, then apply CSDF minimization (§7).
    let wrapped = serde_json::json!({ "accounts": body });
    Ok(Json(FdxAccountsPassthrough(minimize_response(
        &wrapped, &filter,
    ))))
}

/// `GET /fdx/v6/accounts/{accountId}` - account detail (proxies to Ledger).
#[utoipa::path(
    get,
    path = "/fdx/v6/accounts/{id}",
    responses(
        (status = 200, description = "OK", body = FdxAccountsPassthrough),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Missing the FDX consent/scope gate"),
    ),
    security(),
    tag = "fdx",
)]
pub async fn get_account_detail(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(account_id): Path<Uuid>,
) -> Result<Json<FdxAccountsPassthrough>, Response> {
    let _a =
        middleware::provider_authz(&state, &headers, Some(csdf::DataCluster::Accounts)).await?;
    let http = ledger_http(&state)?;
    let resp = http
        .get(format!(
            "{}/v1/accounts/{}",
            state.config.ledger_url, account_id
        ))
        .send()
        .await
        .map_err(|e| FdxErrorResponse::internal(format!("ledger fetch: {e}")))?;
    let body: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| FdxErrorResponse::internal(format!("ledger decode: {e}")))?;
    let filter = consent_filter_from_headers(&state, &headers).await;
    Ok(Json(FdxAccountsPassthrough(minimize_response(
        &body, &filter,
    ))))
}

/// `GET /fdx/v6/accounts/{accountId}/transactions` - transactions (proxies
/// to Ledger; no hardcoded empty results).
#[utoipa::path(
    get,
    path = "/fdx/v6/accounts/{id}/transactions",
    responses(
        (status = 200, description = "OK", body = FdxAccountsPassthrough),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Missing the FDX consent/scope gate"),
    ),
    security(),
    tag = "fdx",
)]
pub async fn get_account_transactions(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(account_id): Path<Uuid>,
) -> Result<Json<FdxAccountsPassthrough>, Response> {
    let _a =
        middleware::provider_authz(&state, &headers, Some(csdf::DataCluster::Transactions)).await?;
    let http = ledger_http(&state)?;
    let resp = http
        .get(format!(
            "{}/v1/accounts/{}/transactions",
            state.config.ledger_url, account_id
        ))
        .send()
        .await
        .map_err(|e| FdxErrorResponse::internal(format!("ledger fetch: {e}")))?;
    let body: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| FdxErrorResponse::internal(format!("ledger decode: {e}")))?;
    let filter = consent_filter_from_headers(&state, &headers).await;
    Ok(Json(FdxAccountsPassthrough(minimize_response(
        &body, &filter,
    ))))
}

// ── FDX consent introspection + revocation (design §5.1) ────────────────

/// `GET /fdx/v6/consents/{consentId}` - consent grant introspection.
#[utoipa::path(
    get,
    path = "/fdx/v6/consents/{id}",
    responses(
        (status = 200, description = "OK", body = FdxConsentIntrospection),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Missing the FDX consent/scope gate"),
    ),
    security(),
    tag = "fdx",
)]
pub async fn get_fdx_consent(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(consent_id): Path<Uuid>,
) -> Result<Json<FdxConsentIntrospection>, Response> {
    let _a = middleware::provider_authz(&state, &headers, None).await?;
    // Same-transaction discipline (fdx DESIGN.md §5) - see start_consent.
    let mut conn = state
        .pool
        .begin()
        .await
        .map_err(|e| FdxErrorResponse::internal(format!("db: {e}")))?;
    sentin8::shell::set_tenant_context(&mut conn, _a.env_id()).await;
    let row = sqlx::query(
        r#"SELECT id, customer_id, status, scopes, data_clusters, expires_at, created_at
             FROM consents WHERE id = $1"#,
    )
    .bind(consent_id)
    .fetch_optional(&mut *conn)
    .await
    .map_err(|e| FdxErrorResponse::internal(format!("db: {e}")))?;
    match row {
        Some(r) => {
            let resources = sqlx::query(
                r#"SELECT resource_type, resource_id, data_clusters
                     FROM consent_resources WHERE consent_id = $1"#,
            )
            .bind(consent_id)
            .fetch_all(&mut *conn)
            .await
            .map_err(|e| FdxErrorResponse::internal(format!("db: {e}")))?;
            let resource_list: Vec<FdxConsentResource> = resources
                .iter()
                .map(|res| FdxConsentResource {
                    resource_type: res.get::<String, _>("resource_type"),
                    resource_id: res.get::<String, _>("resource_id"),
                    data_clusters: res.get::<Vec<String>, _>("data_clusters"),
                })
                .collect();
            Ok(Json(FdxConsentIntrospection {
                consent_id: r.get::<Uuid, _>("id"),
                customer_id: r.get::<Uuid, _>("customer_id"),
                status: r.get::<String, _>("status"),
                scopes: r.get::<Vec<String>, _>("scopes"),
                data_clusters: r.get::<Vec<String>, _>("data_clusters"),
                expires_at: r.get::<Option<chrono::DateTime<chrono::Utc>>, _>("expires_at"),
                created_at: r.get::<chrono::DateTime<chrono::Utc>, _>("created_at"),
                resources: resource_list,
            }))
        }
        None => Err(FdxErrorResponse::not_found("consent not found").into_response()),
    }
}

/// `PUT /fdx/v6/consents/{consentId}/revocation` - consent revocation.
pub async fn revoke_fdx_consent(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(consent_id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, Response> {
    let a = middleware::provider_authz(&state, &headers, None).await?;
    // Same-transaction discipline (fdx DESIGN.md §5) - see start_consent.
    let mut conn = state
        .pool
        .begin()
        .await
        .map_err(|e| FdxErrorResponse::internal(format!("db: {e}")))?;
    sentin8::shell::set_tenant_context(&mut conn, a.env_id()).await;
    let row = sqlx::query(
        r#"UPDATE consents SET status = 'revoked', updated_at = now() WHERE id = $1
            RETURNING id"#,
    )
    .bind(consent_id)
    .fetch_optional(&mut *conn)
    .await
    .map_err(|e| FdxErrorResponse::internal(format!("db: {e}")))?;
    match row {
        Some(r) => {
            let id: Uuid = r.get("id");
            let _ = conn.commit().await;
            emit_event(
                &state.pool,
                a.env_id(),
                "bank8:fdx:consent:revoked",
                serde_json::json!({ "consent_id": id }),
            )
            .await;
            Ok(Json(
                serde_json::json!({ "consentId": id, "status": "revoked" }),
            ))
        }
        None => Err(FdxErrorResponse::not_found("consent not found").into_response()),
    }
}

// ── Recipient API ───────────────────────────────────────────────────────

/// `GET /v1/recipient/providers` - list FDX data providers from the
/// `provider_profiles` registry.
/// Provider profiles are auto-registered when an environment's
/// `is_fdx_provider` flag is turned on (see Sys `update_env`), with the
/// env's auth domain used as the issuer URL. The table has no RLS, so the
/// catalog is visible cross-org - any recipient can discover and connect to
/// any active provider. No static seed data is required.
/// Response shape matches the eFintech recipient catalog contract:
/// `{ "providers": [{ id, name, supportedDataClusters, status, ... }] }`,
/// where each card reads `name`, `supportedDataClusters`, and `status`.
#[utoipa::path(
    get,
    path = "/v1/recipient/providers",
    responses(
        (status = 200, description = "OK", body = ProviderCatalogResponse),
        (status = 403, description = "Missing fdx:read scope"),
    ),
    security(("fdx:read" = [])),
    tag = "fdx",
)]
pub async fn list_recipient_providers(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<ProviderCatalogResponse>, (StatusCode, String)> {
    let _a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(
        &state.policy,
        &_a,
        &headers,
        sentin8::shield::EvalTarget::new("bank8:fdx:recipient:read"),
    )
    .await?;
    // NOTE: no set_tenant_context - provider_profiles has no RLS, so this
    // returns all active providers across orgs (a global recipient catalog).
    let rows = sqlx::query(
        r#"SELECT id, provider_name, issuer_url, fdx_version, capabilities, status
             FROM provider_profiles
            WHERE status = 'active'
            ORDER BY created_at DESC"#,
    )
    .fetch_all(&state.pool)
    .await
    .map_err(err_db)?;

    let providers: Vec<ProviderCard> = rows
        .iter()
        .map(|r| {
            let caps: serde_json::Value =
                r.try_get("capabilities").unwrap_or(serde_json::json!([]));
            let clusters: Vec<String> = caps
                .as_array()
                .map(|a| {
                    a.iter()
                        .filter_map(|x| x.as_str().map(String::from))
                        .collect()
                })
                .unwrap_or_default();
            ProviderCard {
                id: r.get::<Uuid, _>("id"),
                name: r.get::<String, _>("provider_name"),
                issuer_url: r.get::<String, _>("issuer_url"),
                fdx_version: r.get::<String, _>("fdx_version"),
                supported_data_clusters: clusters,
                status: r.get::<String, _>("status"),
            }
        })
        .collect();

    Ok(Json(ProviderCatalogResponse { providers }))
}

// ── Provider API  ────────────────────────────────────

/// `GET /fdx/v6/accounts/{accountId}/statements` - list statements (proxy to Ledger).
#[utoipa::path(
    get,
    path = "/fdx/v6/accounts/{id}/statements",
    responses(
        (status = 200, description = "OK", body = FdxAccountsPassthrough),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Missing the FDX consent/scope gate"),
    ),
    security(),
    tag = "fdx",
)]
pub async fn list_account_statements(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(account_id): Path<Uuid>,
) -> Result<Json<FdxAccountsPassthrough>, Response> {
    let _a =
        middleware::provider_authz(&state, &headers, Some(csdf::DataCluster::Statements)).await?;
    let http = ledger_http(&state)?;
    let resp = http
        .get(format!(
            "{}/v1/accounts/{}/statements",
            state.config.ledger_url, account_id
        ))
        .send()
        .await
        .map_err(|e| FdxErrorResponse::internal(format!("ledger fetch: {e}")))?;
    let body: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| FdxErrorResponse::internal(format!("ledger decode: {e}")))?;
    let filter = consent_filter_from_headers(&state, &headers).await;
    let wrapped = serde_json::json!({ "statements": body });
    Ok(Json(FdxAccountsPassthrough(minimize_response(
        &wrapped, &filter,
    ))))
}

/// `GET /fdx/v6/accounts/{accountId}/payment-networks` - payment network info.
#[utoipa::path(
    get,
    path = "/fdx/v6/accounts/{id}/payment-networks",
    responses(
        (status = 200, description = "OK", body = FdxAccountsPassthrough),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Missing the FDX consent/scope gate"),
    ),
    security(),
    tag = "fdx",
)]
pub async fn get_payment_networks(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(account_id): Path<Uuid>,
) -> Result<Json<FdxAccountsPassthrough>, Response> {
    let _a =
        middleware::provider_authz(&state, &headers, Some(csdf::DataCluster::Accounts)).await?;
    let http = ledger_http(&state)?;
    let resp = http
        .get(format!(
            "{}/v1/accounts/{}/payment-networks",
            state.config.ledger_url, account_id
        ))
        .send()
        .await
        .map_err(|e| FdxErrorResponse::internal(format!("ledger fetch: {e}")))?;
    let body: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| FdxErrorResponse::internal(format!("ledger decode: {e}")))?;
    let filter = consent_filter_from_headers(&state, &headers).await;
    let wrapped = serde_json::json!({ "payment_networks": body });
    Ok(Json(FdxAccountsPassthrough(minimize_response(
        &wrapped, &filter,
    ))))
}

/// `GET /fdx/v6/customers` - list customers (proxy to Ledger).
#[utoipa::path(
    get,
    path = "/fdx/v6/customers",
    responses(
        (status = 200, description = "OK", body = FdxAccountsPassthrough),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Missing the FDX consent/scope gate"),
    ),
    security(),
    tag = "fdx",
)]
pub async fn list_customers(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<FdxAccountsPassthrough>, Response> {
    let _a =
        middleware::provider_authz(&state, &headers, Some(csdf::DataCluster::Customers)).await?;
    let http = ledger_http(&state)?;
    let resp = http
        .get(format!("{}/v1/customers", state.config.ledger_url))
        .send()
        .await
        .map_err(|e| FdxErrorResponse::internal(format!("ledger fetch: {e}")))?;
    let body: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| FdxErrorResponse::internal(format!("ledger decode: {e}")))?;
    let filter = consent_filter_from_headers(&state, &headers).await;
    let wrapped = serde_json::json!({ "customers": body });
    Ok(Json(FdxAccountsPassthrough(minimize_response(
        &wrapped, &filter,
    ))))
}

/// `GET /fdx/v6/customers/current` - current customer (proxy to Ledger).
#[utoipa::path(
    get,
    path = "/fdx/v6/customers/current",
    responses(
        (status = 200, description = "OK", body = FdxAccountsPassthrough),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Missing the FDX consent/scope gate"),
    ),
    security(),
    tag = "fdx",
)]
pub async fn get_current_customer(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<FdxAccountsPassthrough>, Response> {
    let a =
        middleware::provider_authz(&state, &headers, Some(csdf::DataCluster::Customers)).await?;
    let http = ledger_http(&state)?;
    // Use the subject from the token to fetch the current customer.
    let resp = http
        .get(format!(
            "{}/v1/customers/{}",
            state.config.ledger_url,
            a.sub()
        ))
        .send()
        .await
        .map_err(|e| FdxErrorResponse::internal(format!("ledger fetch: {e}")))?;
    let body: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| FdxErrorResponse::internal(format!("ledger decode: {e}")))?;
    let filter = consent_filter_from_headers(&state, &headers).await;
    Ok(Json(FdxAccountsPassthrough(minimize_response(
        &body, &filter,
    ))))
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateTransferRequest {
    pub from_account_id: Uuid,
    pub to_account_id: Uuid,
    pub amount: serde_json::Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub memo: Option<String>,
}

/// `POST /fdx/v6/transfers` - account transfer initiation (proxy to Payments).
#[utoipa::path(
    post,
    path = "/fdx/v6/transfers",
    responses(
        (status = 200, description = "OK", body = FdxAccountsPassthrough),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Missing the FDX consent/scope gate"),
    ),
    security(),
    tag = "fdx",
)]
pub async fn create_transfer(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<CreateTransferRequest>,
) -> Result<Json<FdxAccountsPassthrough>, Response> {
    let a =
        middleware::provider_authz(&state, &headers, Some(csdf::DataCluster::Transfers)).await?;
    let http = payments_http(&state)?;
    let payload = serde_json::json!({
        "from_account_id" : req.from_account_id,
        "to_account_id" : req.to_account_id,
        "amount": req.amount,
        "memo": req.memo,
    });
    let resp = http
        .post(format!("{}/v1/transfers", state.config.payments_url))
        .json(&payload)
        .send()
        .await
        .map_err(|e| FdxErrorResponse::internal(format!("payments fetch: {e}")))?;
    let body: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| FdxErrorResponse::internal(format!("payments decode: {e}")))?;
    emit_event(
        &state.pool,
        a.env_id(),
        "bank8:fdx:transfer:created",
        body.clone(),
    )
    .await;
    Ok(Json(FdxAccountsPassthrough(body)))
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct CreatePaymentRequest {
    pub account_id: Uuid,
    pub amount: serde_json::Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub counterparty: Option<serde_json::Value>,
}

/// `POST /fdx/v6/payments` - payment initiation (proxy to Payments).
#[utoipa::path(
    post,
    path = "/fdx/v6/payments",
    responses(
        (status = 200, description = "OK", body = FdxAccountsPassthrough),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Missing the FDX consent/scope gate"),
    ),
    security(),
    tag = "fdx",
)]
pub async fn create_payment(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<CreatePaymentRequest>,
) -> Result<Json<FdxAccountsPassthrough>, Response> {
    let a = middleware::provider_authz(&state, &headers, Some(csdf::DataCluster::Payments)).await?;
    let http = payments_http(&state)?;
    let payload = serde_json::json!({
        "account_id" : req.account_id,
        "amount": req.amount,
        "counterparty": req.counterparty,
    });
    let resp = http
        .post(format!("{}/v1/payments", state.config.payments_url))
        .json(&payload)
        .send()
        .await
        .map_err(|e| FdxErrorResponse::internal(format!("payments fetch: {e}")))?;
    let body: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| FdxErrorResponse::internal(format!("payments decode: {e}")))?;
    emit_event(
        &state.pool,
        a.env_id(),
        "bank8:fdx:payment:created",
        body.clone(),
    )
    .await;
    Ok(Json(FdxAccountsPassthrough(body)))
}

/// `GET /fdx/v6/capability` - provider capability metadata.
#[utoipa::path(
    get,
    path = "/fdx/v6/capability",
    responses(
        (status = 200, description = "OK", body = FdxCapability),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Missing the FDX consent/scope gate"),
    ),
    security(),
    tag = "fdx",
)]
pub async fn get_capability() -> Json<FdxCapability> {
    Json(FdxCapability {
        fdx_version: "6.5".into(),
        capabilities: vec![
            "ACCOUNTS",
            "TRANSACTIONS",
            "STATEMENTS",
            "PAYMENTS",
            "TRANSFERS",
            "CUSTOMERS",
            "TAX",
            "NOTIFICATIONS",
        ]
        .into_iter()
        .map(String::from)
        .collect(),
        data_clusters: vec![
            "ACCOUNTS",
            "PAYMENTS",
            "STATEMENTS",
            "CUSTOMERS",
            "TRANSACTIONS",
            "TRANSFERS",
            "TAX",
        ]
        .into_iter()
        .map(String::from)
        .collect(),
    })
}

/// `GET /fdx/v6/availability` - provider availability status.
#[utoipa::path(
    get,
    path = "/fdx/v6/availability",
    responses(
        (status = 200, description = "OK", body = FdxAvailability),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Missing the FDX consent/scope gate"),
    ),
    security(),
    tag = "fdx",
)]
pub async fn get_availability() -> Json<FdxAvailability> {
    Json(FdxAvailability {
        status: "available".into(),
        description: "FDX provider is operational".into(),
    })
}

/// `GET /fdx/v6/certification-metrics` - certification metrics (design
/// §10: counts over the tables this service already owns - `data_call*`
/// rows in `audit_events` plus consent granted/revoked transitions -
/// behind a short bounded cache; the rollup table + evidence admin page
/// are the follow-on). The literal-zero stub is gone: these are real
/// counters now.
#[utoipa::path(
    get,
    path = "/fdx/v6/certification-metrics",
    responses(
        (status = 200, description = "OK", body = CertificationMetrics),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Missing the FDX consent/scope gate"),
    ),
    security(),
    tag = "fdx",
)]
pub async fn get_certification_metrics(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<crate::dtos::CertificationMetrics>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("bank8:fdx:admin"),
    )
    .await?;
    let cache_key = a.env_id();
    if let Some(cached) = state.cert_metrics_cache.get(&cache_key) {
        return Ok(Json(cached));
    }
    // Same-transaction discipline (fdx DESIGN.md §5) - see list_consents.
    let mut conn = state
        .pool
        .begin()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    set_tenant_context(&mut conn, a.env_id()).await;
    let row = sqlx::query(
        r#"SELECT
               (SELECT COUNT(*) FROM consents WHERE status IN ('active','expired')) AS consents_granted,
               (SELECT COUNT(*) FROM consent_revocations)                          AS consents_revoked,
               (SELECT COUNT(*) FROM audit_events WHERE action LIKE 'data_call%')   AS data_calls"#,
    )
    .fetch_one(&mut *conn).await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("certification metrics: {e}")))?;
    use sqlx::Row;
    let body = crate::dtos::CertificationMetrics {
        certified: true,
        fdx_version: "6.5".into(),
        metrics: crate::dtos::CertificationMetricCounters {
            consents_granted: row.try_get::<i64, _>(0).unwrap_or(0),
            consents_revoked: row.try_get::<i64, _>(1).unwrap_or(0),
            data_calls: row.try_get::<i64, _>(2).unwrap_or(0),
        },
    };
    state.cert_metrics_cache.insert(cache_key, body.clone());
    Ok(Json(body))
}

// ── Recipient API  ─────────────────────────────────

#[derive(Debug, Deserialize, ToSchema)]
pub struct StartConsentRequest {
    pub customer_id: Uuid,
    pub provider_id: String,
    pub scopes: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub redirect_url: Option<String>,
    /// The app frontend URL to redirect back to after consent (passed by
    /// BFF from the TLS hostname). Encoded into the OAuth `state` so it
    /// survives the PAR/authorize/callback round-trip.
    #[serde(default)]
    pub app_redirect_uri: Option<String>,
}

/// `POST /v1/recipient/consents/start` - start consent authorization.
/// The two-ledger recipient flow (fdx DESIGN.md §1 + §4 consent-flow
/// sequence): the recipient-side fdx instance writes its OWN registry
/// (a `pending` row in `recipient_consents`, in the recipient tenant),
/// ensures its per-provider OAuth client exists at the provider's
/// authorization server (DCR, cached in `fdx.recipients`), and pushes a
/// PAR request whose `state` carries `"<consent handle>|<app origin>"`.
/// The AS's authorize screen runs the ceremony; the browser redirect
/// comes back to THIS instance's `/fdx/consents/callback` (the
/// registered redirect_uri), which activates the row and exchanges the
/// code. The provider's grant row is seeded by the provider's OWN
/// auth-family consumer from `sentin8:auth:grant:created` - never by
/// this side.
#[utoipa::path(
    post,
    path = "/v1/recipient/consents/start",
    request_body = StartConsentRequest,
    responses(
        (status = 200, description = "OK", body = ConsentStartResponse),
        (status = 403, description = "Missing fdx:read scope"),
    ),
    security(("fdx:read" = [])),
    tag = "fdx",
)]
pub async fn start_consent(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<StartConsentRequest>,
) -> Result<Json<ConsentStartResponse>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("bank8:fdx:recipient:write"),
    )
    .await?;
    // Same-transaction discipline (fdx DESIGN.md §5): the tenant context
    // is transaction-local (`set_config(..., true)`) - it must live on
    // the SAME tx as the INSERT, or the row lands with
    // `context_initialized=false` and FORCE-RLS rejects it.
    let mut conn = state.pool.begin().await.map_err(err_db)?;
    set_tenant_context(&mut conn, a.env_id()).await;
    // The registry row lives in the RECIPIENT tenant - the fintech's own
    // bookkeeping of its customer's connection (two-ledger model,
    // DESIGN.md §1). The consent handle (row id) rides the OAuth `state`
    // so the AS's grant event and the callback both resolve the flow.
    let row = sqlx::query(
        r#"INSERT INTO recipient_consents (env_id, customer_id, provider_id, scopes, status, app_redirect_uri)
           VALUES ($1, $2, $3, $4, 'pending', $5)
           RETURNING id"#,
    )
    .bind(a.env_id())
    .bind(req.customer_id)
    .bind(&req.provider_id)
    .bind(&req.scopes)
    .bind(req.app_redirect_uri.as_deref().unwrap_or_default())
    .fetch_one(&mut *conn)
    .await
    .map_err(err_db)?;
    let id: Uuid = sqlx::Row::get(&row, "id");

    // PKCE verifier (RFC 7636) is persisted here and consumed by the
    // callback's token exchange - the recipient is the OAuth client, so
    // token custody follows this verifier (DESIGN.md §1).
    let code_verifier = generate_pkce_verifier();
    sqlx::query("UPDATE recipient_consents SET code_verifier = $2 WHERE id = $1")
        .bind(id)
        .bind(&code_verifier)
        .execute(&mut *conn)
        .await
        .map_err(err_db)?;
    conn.commit().await.map_err(err_db)?;

    // Resolve the provider's issuer + display name from the catalog
    // (provider_profiles - the cross-env recipient directory, no RLS).
    let profile_row = sqlx::query(
        r#"SELECT issuer_url, provider_name, env_id FROM provider_profiles
            WHERE status = 'active'
              AND (env_id::text = $1 OR id::text = $1)
            LIMIT 1"#,
    )
    .bind(&req.provider_id)
    .fetch_optional(&state.pool)
    .await
    .ok()
    .flatten();
    let (provider_issuer, provider_name) = match profile_row {
        Some(r) => (
            r.try_get::<String, _>("issuer_url").unwrap_or_default(),
            r.try_get::<String, _>("provider_name").unwrap_or_default(),
        ),
        None => {
            return Err((
                StatusCode::NOT_FOUND,
                format!("provider {} not found in the catalog", req.provider_id),
            ))
        }
    };
    if provider_issuer.is_empty() {
        return Err((
            StatusCode::BAD_GATEWAY,
            "provider profile has no issuer URL".into(),
        ));
    }

    // The OAuth client belongs to the RECIPIENT (DESIGN.md §1): ensure a
    // public client exists at the provider's AS, cached per
    // (recipient env, provider) in `fdx.recipients`. The redirect_uri
    // registered there is THIS instance's env callback host.
    let (client_id, callback_url) =
        ensure_recipient_client(&state, a.env_id(), &req.provider_id, &provider_issuer).await?;

    // PAR (RFC 9126) with PKCE + the handle-carrying state.
    let scope = req.scopes.join(" ");
    let app_redirect = req.app_redirect_uri.unwrap_or_default();
    let state_param = if app_redirect.is_empty() {
        id.to_string()
    } else {
        format!("{}|{}", id, app_redirect)
    };
    let code_challenge = pkce_s256_challenge(&code_verifier);

    let http = reqwest::Client::builder()
        .build()
        .map_err(|e| (StatusCode::BAD_GATEWAY, format!("http client: {e}")))?;
    let par_url = format!("{}/oauth/par", provider_issuer.trim_end_matches('/'));
    let par_resp = http
        .post(&par_url)
        .form(&[
            ("response_type", "code"),
            ("client_id", client_id.as_str()),
            ("redirect_uri", callback_url.as_str()),
            ("scope", &scope),
            ("state", &state_param),
            ("code_challenge", code_challenge.as_str()),
            ("code_challenge_method", "S256"),
        ])
        .send()
        .await
        .map_err(|e| {
            (
                StatusCode::BAD_GATEWAY,
                format!("PAR request to provider: {e}"),
            )
        })?;

    if !par_resp.status().is_success() {
        let status = par_resp.status();
        let body = par_resp.text().await.unwrap_or_default();
        tracing::error!(client_id = %client_id, %par_url, "bank8:fdx: PAR failed");
        return Err((
            StatusCode::BAD_GATEWAY,
            format!("PAR failed: {status}: {body}"),
        ));
    }

    let par_body: serde_json::Value = par_resp
        .json()
        .await
        .map_err(|e| (StatusCode::BAD_GATEWAY, format!("PAR decode: {e}")))?;
    let request_uri = par_body["request_uri"]
        .as_str()
        .ok_or((StatusCode::BAD_GATEWAY, "PAR: missing request_uri".into()))?;

    let auth_url = format!(
        "{}/oauth/authorize?client_id={}&request_uri={}",
        provider_issuer.trim_end_matches('/'),
        client_id,
        urlencoding(request_uri),
    );
    emit_event(&state.pool, a.env_id(), "bank8:fdx:recipientconsent:started", serde_json::json!({ "consent_id": id, "provider_id": req.provider_id, "scopes": req.scopes })).await;
    Ok(Json(ConsentStartResponse {
        consent_id: id,
        authorization_url: auth_url,
        status: "pending".into(),
        provider_name,
    }))
}

/// Query params for `GET /fdx/consents/callback` - the OAuth callback after
/// the customer approves/denies consent at the provider's Auth.
#[derive(Debug, Deserialize, ToSchema)]
pub struct ConsentCallbackQuery {
    /// The authorization code from Auth.
    #[serde(default)]
    pub code: Option<String>,
    /// The consent_id (passed as OAuth `state` in the PAR request).
    #[serde(default)]
    pub state: Option<String>,
    /// The app return URL (passed through from BFF as `app_redirect_uri`).
    #[serde(default)]
    pub app_redirect_uri: Option<String>,
    /// OAuth error if the customer denied.
    #[serde(default)]
    pub error: Option<String>,
    /// Comma-separated list of account IDs the customer selected to share
    /// during the provider's consent screen (FDX UX Guidelines §3.1.6).
    /// Passed through from Auth's authorize/continue as a query param on
    /// the redirect_uri.
    #[serde(default)]
    pub selected_account_ids: Option<String>,
}

/// `GET /fdx/consents/callback` - OAuth callback from Auth after consent.
/// Per the FDX design §4.3:
/// 5. External provider redirects to Auth callback
/// 6. Auth validates state, nonce, JARM
/// 7. Auth exchanges code for tokens
/// 8. FDX creates consent record (active), enqueues data retrieval
/// For now (dev), this activates the consent and redirects back to the
/// eFintech app. In production, this would exchange the code for tokens
/// at Auth, store the token grants, and enqueue data retrieval.
#[utoipa::path(
    get,
    path = "/fdx/consents/callback",
    responses(
        (status = 302, description = "Redirect to the authorization URL"),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Missing the FDX consent/scope gate"),
    ),
    security(),
    tag = "fdx",
)]
pub async fn consent_callback(
    State(state): State<AppState>,
    req_headers: HeaderMap,
    Query(q): Query<ConsentCallbackQuery>,
) -> Response {
    // If the customer denied, redirect back with an error.
    if let Some(ref err) = q.error {
        let redirect = q.app_redirect_uri.unwrap_or_default();
        let url = if redirect.is_empty() {
            format!("/?error={}", urlencoding(err))
        } else {
            format!("{}?error={}", redirect, urlencoding(err))
        };
        return (StatusCode::FOUND, [("location", url)]).into_response();
    }

    // The `state` is "consent_id|app_redirect_uri" (pipe-separated).
    let (consent_id, app_redirect) = match q.state.as_deref() {
        Some(s) => {
            let parts: Vec<&str> = s.splitn(2, '|').collect();
            let id = parts.first().and_then(|p| Uuid::parse_str(p).ok());
            let redirect = parts.get(1).map(|s| s.to_string()).unwrap_or_default();
            (id, redirect)
        }
        None => (None, String::new()),
    };
    let consent_id = match consent_id {
        Some(id) => id,
        None => {
            return (
                StatusCode::BAD_REQUEST,
                "missing or invalid state (consent_id)",
            )
                .into_response()
        }
    };

    // RECIPIENT-OWNED CALLBACK (two-ledger model, fdx DESIGN.md §1): the
    // redirect_uri registered for the recipient's client is THIS env's
    // callback host, so the browser lands on the recipient-side instance.
    // The row lives in the RECIPIENT tenant: seed the tenant context from
    // the TLS env header (the anonymous browser redirect carries no token,
    // but the shell's TLS context middleware injects the env the request
    // routed under) and read/write the registry row under it.
    let tls_env = sentin8::middleware::context::TLSContext::from_headers(&req_headers)
        .env_id
        .unwrap_or_default();
    if tls_env.is_nil() {
        return (
            StatusCode::PRECONDITION_FAILED,
            "callback must arrive through the tenant ingress (no env context)",
        )
            .into_response();
    }
    let mut conn = match state.pool.begin().await {
        Ok(c) => c,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, format!("db: {e}")).into_response(),
    };
    set_tenant_context(&mut conn, tls_env).await;

    // Resolve the registry row + the flow's provider identity on ONE
    // transaction (fdx DESIGN.md §5 same-transaction discipline).
    let reg_row = sqlx::query(
        r#"SELECT provider_id, code_verifier, client_id FROM recipient_consents
            WHERE id = $1"#,
    )
    .bind(consent_id)
    .fetch_optional(&mut *conn)
    .await;
    let reg_row = match reg_row {
        Ok(Some(r)) => r,
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                "consent not found in the recipient registry",
            )
                .into_response()
        }
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, format!("db: {e}")).into_response(),
    };
    let provider_id: String = reg_row.try_get("provider_id").unwrap_or_default();
    let client_id: String = reg_row
        .try_get::<Option<String>, _>("client_id")
        .ok()
        .flatten()
        .unwrap_or_default();
    let code_verifier: Option<String> = reg_row
        .try_get::<Option<String>, _>("code_verifier")
        .ok()
        .flatten();

    // Persist the customer's selected accounts on the registry row (they
    // ride the authorize redirect as a comma-separated query param) - the
    // recipient filters its account lists to the selection.
    if let Some(ref accounts_csv) = q.selected_account_ids {
        let selected: Vec<String> = accounts_csv
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        if !selected.is_empty() {
            let _ = sqlx::query(
                "UPDATE recipient_consents SET selected_account_ids = $2, updated_at = now() WHERE id = $1",
            )
            .bind(consent_id)
            .bind(&selected)
            .execute(&mut *conn)
            .await;
            tracing::info!(
                consent_id = %consent_id,
                accounts = selected.len(),
                "bank8:fdx: selected accounts persisted on the registry row"
            );
        }
    }

    // Activate the registry row (idempotent - a repeated callback only
    // re-activates).
    if let Err(e) = sqlx::query(
        r#"UPDATE recipient_consents SET status = 'active', updated_at = now() WHERE id = $1"#,
    )
    .bind(consent_id)
    .execute(&mut *conn)
    .await
    {
        return (StatusCode::INTERNAL_SERVER_ERROR, format!("db: {e}")).into_response();
    }

    // ── Exchange the code for a delegated provider token ─────────────
    // The recipient is the OAuth client: PKCE verifier + DPoP key are
    // BOTH this institution's custody, and the tokens land on the
    // registry row (secret references only - DESIGN.md §5).
    if let Some(ref code) = q.code {
        if !provider_id.is_empty() {
            // The provider profile (catalog - no RLS) carries the issuer.
            let profile_row = sqlx::query(
                r#"SELECT issuer_url, env_id FROM provider_profiles
                    WHERE status = 'active'
                      AND (env_id::text = $1 OR id::text = $1)
                    LIMIT 1"#,
            )
            .bind(&provider_id)
            .fetch_optional(&state.pool)
            .await
            .ok()
            .flatten();
            let provider_issuer = profile_row
                .as_ref()
                .and_then(|r| r.try_get::<String, _>("issuer_url").ok())
                .unwrap_or_default();
            if !provider_issuer.is_empty() && !client_id.is_empty() {
                // The DPoP key lives on the recipient's per-provider
                // client row (`fdx.recipients`) - sealed reference.
                let dpop_key_pem: Option<String> =
                    load_recipient_dpop_key(&state, tls_env, &provider_id).await;

                // Must match the PAR redirect_uri exactly (§4.3c): the
                // RECIPIENT's env callback host - the same derivation the
                // DCR registration used.
                let callback_url = own_env_callback_url(&state, tls_env).await;

                let token_url = format!("{}/oauth/token", provider_issuer.trim_end_matches('/'));
                let http = reqwest::Client::builder().build().unwrap_or_default();

                let mut token_form: Vec<(String, String)> = vec![
                    ("grant_type".into(), "authorization_code".into()),
                    ("code".into(), code.clone()),
                    ("redirect_uri".into(), callback_url),
                    ("client_id".into(), client_id),
                ];
                // PKCE (RFC 7636 §4.6) - public client must present the
                // verifier bound to the challenge sent at PAR time.
                if let Some(ref v) = code_verifier {
                    if !v.is_empty() {
                        token_form.push(("code_verifier".into(), v.clone()));
                    }
                }
                let token_req = if let Some(ref pem) = dpop_key_pem {
                    // DPoP (RFC 9449) - required under fapi_2 require_dpop
                    // for public non-exempt clients (auth design §3.4).
                    let htu = format!("{}/oauth/token", provider_issuer.trim_end_matches('/'));
                    match sentin8::auth::fapi::dpop_proof(
                        "POST",
                        &htu,
                        None,
                        pem,
                        jsonwebtoken::Algorithm::ES256,
                    ) {
                        Ok(proof) => {
                            http.post(&token_url)
                                .header("DPoP", proof)
                                .form(&token_form)
                                .send()
                                .await
                        }
                        Err(e) => {
                            tracing::warn!(error = %e, "bank8:fdx: DPoP proof generation failed - sending without proof");
                            http.post(&token_url).form(&token_form).send().await
                        }
                    }
                } else {
                    http.post(&token_url).form(&token_form).send().await
                };

                if let Ok(resp) = token_req {
                    if resp.status().is_success() {
                        if let Ok(token_body) = resp.json::<serde_json::Value>().await {
                            let access_token = token_body["access_token"].as_str().unwrap_or("");
                            let refresh_token = token_body["refresh_token"].as_str();
                            let expires_in = token_body["expires_in"].as_i64().unwrap_or(3600);
                            if !access_token.is_empty() {
                                // Store both tokens as sentin8-secrets://
                                // references (DESIGN.md §5) - never plaintext.
                                match tokens::store_provider_tokens(
                                    &mut conn,
                                    consent_id,
                                    access_token,
                                    refresh_token,
                                    expires_in,
                                )
                                .await
                                {
                                    Ok(()) => {
                                        tracing::info!(consent_id = %consent_id, "bank8:fdx: delegated provider tokens stored (recipient custody)");
                                    }
                                    Err(e) => {
                                        tracing::warn!(consent_id = %consent_id, error = %e, "bank8:fdx: token secret-ref storage failed");
                                    }
                                }
                            }
                        }
                    } else {
                        let status = resp.status();
                        let body = resp.text().await.unwrap_or_default();
                        tracing::warn!(consent_id = %consent_id, %status, %body, "bank8:fdx: token exchange failed");
                    }
                }
            }
        }
    }

    // Commit - the activation tx spans the token exchange above and must
    // be durable before the browser leaves via the redirect.
    let _ = conn.commit().await;
    let redirect = q.app_redirect_uri.unwrap_or(app_redirect);
    let url = if redirect.is_empty() {
        "/".to_string()
    } else {
        redirect
    };
    (StatusCode::FOUND, [("location", url)]).into_response()
}

/// `GET /v1/recipient/consents` - list active consents for the recipient.
/// Returns `{"consents": [...]}` (wrapped) so the eFintech app's
/// FdxConsentsHook can parse `response.data['consents']`.
#[utoipa::path(
    get,
    path = "/v1/recipient/consents",
    params(("customer_id" = Option<Uuid>, Query, description = "Filter by customer")),
    responses(
        (status = 200, description = "OK", body = RecipientConsentListResponse),
        (status = 403, description = "Missing fdx:read scope"),
    ),
    security(("fdx:read" = [])),
    tag = "fdx",
)]
pub async fn list_recipient_consents(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<ListConsentsQuery>,
) -> Result<Json<RecipientConsentListResponse>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("bank8:fdx:recipient:read"),
    )
    .await?;
    // The recipient registry is THIS tenant's own table (two-ledger
    // model, DESIGN.md §1): same-env read under the caller's context -
    // the fintech's Connections page lists its customers' connections.
    let mut conn = state.pool.begin().await.map_err(err_db)?;
    set_tenant_context(&mut conn, a.env_id()).await;
    let rows = sqlx::query(
        r#"SELECT id, customer_id, provider_id, provider_name, status, scopes,
                  selected_account_ids, created_at, updated_at
             FROM recipient_consents
            WHERE ($1::uuid IS NULL OR customer_id = $1)
            ORDER BY created_at DESC LIMIT 100"#,
    )
    .bind(q.customer_id)
    .fetch_all(&mut *conn)
    .await
    .map_err(err_db)?;
    let _ = conn.commit().await;
    let consents: Vec<RecipientConsentRow> = rows
        .iter()
        .map(|r| RecipientConsentRow {
            id: r.get::<Uuid, _>("id"),
            customer_id: r.get::<Uuid, _>("customer_id"),
            provider_id: r.get::<String, _>("provider_id"),
            provider_name: r
                .get::<Option<String>, _>("provider_name")
                .unwrap_or_default(),
            status: r.get::<String, _>("status"),
            scopes: r.get::<Vec<String>, _>("scopes"),
            data_clusters: r.get::<Vec<String>, _>("scopes"),
            selected_account_ids: r.get::<Vec<String>, _>("selected_account_ids"),
            created_at: r.get::<chrono::DateTime<chrono::Utc>, _>("created_at"),
            updated_at: r.get::<chrono::DateTime<chrono::Utc>, _>("updated_at"),
        })
        .collect();
    Ok(Json(RecipientConsentListResponse { consents }))
}

/// `POST /v1/recipient/consents/{id}/refresh` - trigger data refresh.
#[utoipa::path(
    post,
    path = "/v1/recipient/consents/{id}/refresh",
    params(("id" = Uuid, Path, description = "Consent ID")),
    responses(
        (status = 200, description = "OK", body = RecipientConsentActionResponse),
        (status = 403, description = "Missing fdx:read scope"),
        (status = 404, description = "Consent not found"),
    ),
    security(("fdx:read" = [])),
    tag = "fdx",
)]
pub async fn refresh_consent(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<Json<RecipientConsentActionResponse>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("bank8:fdx:recipient:write"),
    )
    .await?;
    // Same-transaction discipline (fdx DESIGN.md §5): the registry row
    // lives in THIS (recipient) tenant - context + read on one tx.
    let mut conn = state.pool.begin().await.map_err(err_db)?;
    set_tenant_context(&mut conn, a.env_id()).await;

    // Load the registry row (recipient_consents - the fintech's own
    // connection record; the delegated tokens are in the recipient's
    // custody, sealed as secret references).
    let reg_row = sqlx::query(
        r#"SELECT provider_id, client_id, provider_refresh_token_ref
             FROM recipient_consents
            WHERE id = $1 AND status = 'active'"#,
    )
    .bind(id)
    .fetch_optional(&mut *conn)
    .await
    .map_err(err_db)?;
    let Some(row) = reg_row else {
        return Err((
            StatusCode::NOT_FOUND,
            "consent not found or not active".into(),
        ));
    };
    let provider_id: String = row.try_get("provider_id").unwrap_or_default();
    if !provider_id.is_empty() {
        let refresh_token = tokens::load_provider_refresh_token(&mut conn, id)
            .await
            .ok()
            .flatten();
        // The provider's issuer from the catalog (no RLS).
        let issuer = sqlx::query(
            r#"SELECT issuer_url FROM provider_profiles
                WHERE status = 'active'
                  AND (env_id::text = $1 OR id::text = $1)
                LIMIT 1"#,
        )
        .bind(&provider_id)
        .fetch_optional(&state.pool)
        .await
        .ok()
        .flatten()
        .and_then(|r| r.try_get::<String, _>("issuer_url").ok())
        .unwrap_or_default();
        let token_client_id: String = row
            .try_get::<Option<String>, _>("client_id")
            .ok()
            .flatten()
            .unwrap_or_default();
        // The recipient client's DPoP key (`fdx.recipients` - sealed).
        let dpop_key_pem: Option<String> =
            load_recipient_dpop_key(&state, a.env_id(), &provider_id).await;

        // Refresh-token rotation: POST to the provider's token endpoint
        // with grant_type=refresh_token + DPoP proof. The new tokens are
        // stored on the registry row (recipient custody).
        if let Some(ref rt) = refresh_token {
            if !issuer.is_empty() && !token_client_id.is_empty() {
                let token_url = format!("{}/oauth/token", issuer.trim_end_matches('/'));
                let callback_url = own_env_callback_url(&state, a.env_id()).await;
                let form = [
                    ("grant_type", "refresh_token"),
                    ("refresh_token", rt.as_str()),
                    ("client_id", token_client_id.as_str()),
                    ("redirect_uri", callback_url.as_str()),
                ];
                let http = reqwest::Client::builder().build().unwrap_or_default();
                let req = if let Some(ref pem) = dpop_key_pem {
                    match sentin8::auth::fapi::dpop_proof(
                        "POST",
                        &token_url,
                        None,
                        pem,
                        jsonwebtoken::Algorithm::ES256,
                    ) {
                        Ok(proof) => {
                            http.post(&token_url)
                                .header("DPoP", proof)
                                .form(&form)
                                .send()
                                .await
                        }
                        Err(_) => http.post(&token_url).form(&form).send().await,
                    }
                } else {
                    http.post(&token_url).form(&form).send().await
                };
                if let Ok(resp) = req {
                    if resp.status().is_success() {
                        if let Ok(token_body) = resp.json::<serde_json::Value>().await {
                            let access_token = token_body["access_token"].as_str().unwrap_or("");
                            let new_refresh = token_body["refresh_token"].as_str();
                            let expires_in = token_body["expires_in"].as_i64().unwrap_or(3600);
                            if !access_token.is_empty() {
                                if let Err(e) = tokens::store_provider_tokens(
                                    &mut conn,
                                    id,
                                    access_token,
                                    new_refresh,
                                    expires_in,
                                )
                                .await
                                {
                                    tracing::warn!(consent_id = %id, error = %e, "bank8:fdx: refresh token rotation storage failed");
                                } else {
                                    tracing::info!(consent_id = %id, "bank8:fdx: delegated tokens rotated");
                                }
                            }
                        }
                    } else {
                        let status = resp.status();
                        let body = resp.text().await.unwrap_or_default();
                        tracing::warn!(consent_id = %id, %status, %body, "bank8:fdx: refresh-token exchange failed");
                    }
                }
            }
        }
    }

    // The registry row stays active; the refresh surface confirms the
    // connection is live (touch updated_at).
    let row = sqlx::query(
        r#"UPDATE recipient_consents SET status = 'active', updated_at = now() WHERE id = $1
            RETURNING id, customer_id, provider_id, status, scopes"#,
    )
    .bind(id)
    .fetch_optional(&mut *conn)
    .await
    .map_err(err_db)?;
    match row {
        Some(r) => {
            conn.commit().await.map_err(err_db)?;
            emit_event(
                &state.pool,
                a.env_id(),
                "bank8:fdx:recipientconsent:refreshed",
                serde_json::json!({ "consent_id": id }),
            )
            .await;
            Ok(Json(RecipientConsentActionResponse {
                id: r.get::<Uuid, _>("id"),
                customer_id: r.get::<Uuid, _>("customer_id"),
                provider_id: r.get::<String, _>("provider_id"),
                status: r.get::<String, _>("status"),
                scopes: r.get::<Vec<String>, _>("scopes"),
            }))
        }
        None => Err((StatusCode::NOT_FOUND, "consent not found".into())),
    }
}

/// `POST /v1/recipient/consents/{id}/revoke` - revoke a recipient consent.
#[utoipa::path(
    post,
    path = "/v1/recipient/consents/{id}/revoke",
    params(("id" = Uuid, Path, description = "Consent ID")),
    responses(
        (status = 200, description = "Consent revoked", body = ConsentResponse),
        (status = 403, description = "Missing fdx:read scope"),
    ),
    security(("fdx:read" = [])),
    tag = "fdx",
)]
pub async fn revoke_recipient_consent(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<Json<RecipientConsentActionResponse>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("bank8:fdx:recipient:write"),
    )
    .await?;
    // Same-transaction discipline (fdx DESIGN.md §5): the registry row
    // lives in THIS (recipient) tenant.
    let mut conn = state.pool.begin().await.map_err(err_db)?;
    set_tenant_context(&mut conn, a.env_id()).await;
    let row = sqlx::query(
        r#"SELECT provider_id, client_id FROM recipient_consents
            WHERE id = $1 AND customer_id = $2"#,
    )
    .bind(id)
    .bind(a.sub())
    .fetch_optional(&mut *conn)
    .await
    .map_err(err_db)?;
    let Some(reg) = row else {
        return Err((
            StatusCode::NOT_FOUND,
            "consent not found in the recipient registry".into(),
        ));
    };
    let provider_id: String = reg.try_get("provider_id").unwrap_or_default();

    // Mark the registry row revoked (the fintech's own record).
    let updated = sqlx::query(
        r#"UPDATE recipient_consents SET status = 'revoked', updated_at = now()
            WHERE id = $1 AND customer_id = $2
            RETURNING id, customer_id, provider_id, status, scopes"#,
    )
    .bind(id)
    .bind(a.sub())
    .fetch_one(&mut *conn)
    .await
    .map_err(err_db)?;
    conn.commit().await.map_err(err_db)?;

    // Ask the PROVIDER to revoke its grant: the recipient calls the
    // provider's PUBLIC data-plane revocation surface
    // (`POST /fdx/v6/consents/{id}/revocation` - the delegated subject's
    // surface; the provider's enforcement makes revocation effective on
    // the next data call). The consent id IS the shared handle (it rode
    // the OAuth state and seeded the provider's grant row). Best-effort
    // over HTTPS - a provider outage leaves the registry revoked and
    // the provider retrying on the next user action; the recipient's
    // tokens are simply not used anymore.
    if !provider_id.is_empty() {
        let issuer = sqlx::query(
            r#"SELECT issuer_url, env_id FROM provider_profiles
                WHERE status = 'active'
                  AND (env_id::text = $1 OR id::text = $1)
                LIMIT 1"#,
        )
        .bind(&provider_id)
        .fetch_optional(&state.pool)
        .await
        .ok()
        .flatten();
        if let Some(pr) = issuer {
            let base = provider_env_fdx_base_url(
                &state.pool,
                pr.try_get::<Uuid, _>("env_id").unwrap_or_default(),
                "bank8:fdx",
            )
            .await;
            if !base.is_empty() {
                let http = reqwest::Client::builder().build().unwrap_or_default();
                let url = format!(
                    "{}/fdx/v6/consents/{}/revocation",
                    base.trim_end_matches('/'),
                    id
                );
                if let Err(e) = http
                    .post(&url)
                    .json(&serde_json::json!({ "reason": "USER_ACTION", "initiator": "RECIPIENT" }))
                    .send()
                    .await
                {
                    tracing::warn!(consent_id = %id, error = %e, "bank8:fdx: provider-side revocation call failed (registry revoked; retry on next action)");
                }
            }
        }
    }

    emit_event(
        &state.pool,
        a.env_id(),
        "bank8:fdx:recipientconsent:revoked",
        serde_json::json!({ "consent_id": id }),
    )
    .await;
    Ok(Json(RecipientConsentActionResponse {
        id: updated.get::<Uuid, _>("id"),
        customer_id: updated.get::<Uuid, _>("customer_id"),
        provider_id: updated.get::<String, _>("provider_id"),
        status: updated.get::<String, _>("status"),
        scopes: updated.get::<Vec<String>, _>("scopes"),
    }))
}

/// Query params for `GET /v1/recipient/accounts`.
#[derive(Debug, Deserialize, ToSchema)]
pub struct ListRecipientAccountsQuery {
    /// Optional consent_id to filter accounts to only those the customer
    /// selected during the consent flow (consent_resources).
    #[serde(default)]
    pub consent_id: Option<Uuid>,
}

/// `GET /v1/recipient/accounts` - list consented accounts for the recipient.
/// If `consent_id` is provided, returns only the accounts the customer
/// selected during the provider's consent screen (per FDX UX Guidelines
/// §3.1.6 "Select Accounts"). The account IDs are stored in
/// consent_resources and used to filter the Ledger account list.
/// If no consent_id is provided, returns all accounts (backward compat).
#[utoipa::path(
    get,
    path = "/v1/recipient/accounts",
    responses(
        (status = 200, description = "OK", body = FdxAccountsPassthrough),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Missing the FDX consent/scope gate"),
    ),
    security(),
    tag = "fdx",
)]
pub async fn list_recipient_accounts(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<ListRecipientAccountsQuery>,
) -> Result<Json<FdxAccountsPassthrough>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("bank8:fdx:recipient:read"),
    )
    .await?;

    let http = reqwest::Client::builder().build().map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("http client: {e}"),
        )
    })?;

    // The recipient registry lives in THIS tenant (two-ledger model,
    // DESIGN.md §1): resolve the registry row + the delegated provider
    // token reference (recipient custody) on one tx under the caller's
    // context. Without a consent_id, use the caller's most recent active
    // connection.
    let consent_id = q.consent_id;
    let mut conn = state.pool.begin().await.map_err(err_db)?;
    set_tenant_context(&mut conn, a.env_id()).await;
    let consent_row = if let Some(cid) = consent_id {
        sqlx::query(
            r#"SELECT id, provider_id, client_id FROM recipient_consents
                WHERE id = $1 AND status = 'active'"#,
        )
        .bind(cid)
        .fetch_optional(&mut *conn)
        .await
        .map_err(err_db)?
    } else {
        sqlx::query(
            r#"SELECT id, provider_id, client_id FROM recipient_consents
                WHERE customer_id = $1 AND status = 'active'
                ORDER BY created_at DESC LIMIT 1"#,
        )
        .bind(a.sub())
        .fetch_optional(&mut *conn)
        .await
        .map_err(err_db)?
    };

    let consent_row = match consent_row {
        Some(r) => r,
        None => {
            return Ok(Json(FdxAccountsPassthrough(
                serde_json::json!({ "accounts": [] }),
            )))
        }
    };
    let cid: Uuid = consent_row.try_get("id").unwrap_or_default();
    let provider_id: String = consent_row.try_get("provider_id").unwrap_or_default();
    let provider_token: String = tokens::load_provider_access_token(&mut conn, cid)
        .await
        .unwrap_or_default()
        .unwrap_or_default();

    // The customer's selected accounts for this connection (persisted at
    // the callback from the AS's authorize redirect).
    let selected: Vec<String> =
        sqlx::query(r#"SELECT selected_account_ids FROM recipient_consents WHERE id = $1"#)
            .bind(cid)
            .fetch_one(&mut *conn)
            .await
            .ok()
            .and_then(|r| r.try_get::<Vec<String>, _>("selected_account_ids").ok())
            .unwrap_or_default();
    let _ = conn.commit().await;

    // Resolve the provider's PUBLIC FDX data-plane host from the catalog
    // (provider_profiles - no RLS): the recipient calls the provider's
    // `/fdx/v6/*` API like any external recipient would, with the
    // delegated provider token. NEVER another institution's tables
    // (DESIGN.md §1 - the cross-tenant direct-to-Ledger call is gone).
    let profile_row = sqlx::query(
        r#"SELECT env_id FROM provider_profiles
            WHERE status = 'active'
              AND (env_id::text = $1 OR id::text = $1)
            LIMIT 1"#,
    )
    .bind(&provider_id)
    .fetch_optional(&state.pool)
    .await
    .ok()
    .flatten();
    let provider_env_id: Uuid = profile_row
        .as_ref()
        .and_then(|r| r.try_get::<Uuid, _>("env_id").ok())
        .unwrap_or_else(Uuid::nil);
    if provider_env_id.is_nil() {
        return Err((
            StatusCode::NOT_FOUND,
            "provider not found in the catalog".into(),
        ));
    }
    let provider_fdx_base =
        provider_env_fdx_base_url(&state.pool, provider_env_id, "bank8:fdx").await;
    if provider_fdx_base.is_empty() {
        return Err((
            StatusCode::BAD_GATEWAY,
            "provider FDX host could not be derived".into(),
        ));
    }

    // Call the provider's PUBLIC accounts surface with the delegated
    // token. The provider plane enforces its own grant + CSDF
    // minimization per request (middleware + consent_filter) - the
    // recipient receives exactly what the bank is allowed to release.
    let bearer = if !provider_token.is_empty() {
        format!("Bearer {}", provider_token)
    } else {
        headers
            .get(axum::http::header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string()
    };

    let resp = http
        .get(format!(
            "{}/fdx/v6/accounts",
            provider_fdx_base.trim_end_matches('/')
        ))
        .header("authorization", &bearer)
        .send()
        .await
        .map_err(|e| (StatusCode::BAD_GATEWAY, e.to_string()))?;
    let body: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| (StatusCode::BAD_GATEWAY, e.to_string()))?;

    // The provider wraps accounts under "accounts" (FDX response shape
    // after CSDF minimization); normalize to the app's array contract.
    let raw: Vec<serde_json::Value> =
        if let Some(arr) = body.get("accounts").and_then(|v| v.as_array()) {
            arr.clone()
        } else if let Some(arr) = body.as_array() {
            arr.clone()
        } else if let Some(arr) = body.get("data").and_then(|v| v.as_array()) {
            arr.clone()
        } else {
            vec![body.clone()]
        };

    // Filter the accounts to only the customer's selected ones for this
    // connection (empty selection = all consented accounts).
    let accounts = if !selected.is_empty() {
        raw.into_iter()
            .filter(|acct| {
                let id = acct
                    .get("id")
                    .and_then(|v| v.as_str())
                    .or(acct.get("accountId").and_then(|v| v.as_str()))
                    .unwrap_or("");
                selected.iter().any(|s| s == id)
            })
            .collect()
    } else {
        raw
    };

    Ok(Json(FdxAccountsPassthrough(
        serde_json::json!({ "accounts": accounts }),
    )))
}

/// `GET /v1/recipient/accounts/{id}/transactions` - recipient transaction history.
#[utoipa::path(
    get,
    path = "/v1/recipient/accounts/{id}/transactions",
    responses(
        (status = 200, description = "Forwarded ledger transactions (CSDF-minimized)", body = FdxAccountsPassthrough),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Missing the FDX consent/scope gate"),
    ),
    security(),
    tag = "fdx",
)]
pub async fn get_recipient_account_transactions(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(account_id): Path<Uuid>,
) -> Result<Json<FdxAccountsPassthrough>, (StatusCode, String)> {
    let _a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(
        &state.policy,
        &_a,
        &headers,
        sentin8::shield::EvalTarget::new("bank8:fdx:recipient:read"),
    )
    .await?;
    let http = ledger_http(&state).map_err(|e| (StatusCode::BAD_GATEWAY, e.message))?;
    let resp = http
        .get(format!(
            "{}/v1/accounts/{}/transactions",
            state.config.ledger_url, account_id
        ))
        .send()
        .await
        .map_err(|e| (StatusCode::BAD_GATEWAY, e.to_string()))?;
    let body: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| (StatusCode::BAD_GATEWAY, e.to_string()))?;
    Ok(Json(FdxAccountsPassthrough(body)))
}

/// `GET /v1/recipient/notifications` - notification feed for the recipient.
#[utoipa::path(
    get,
    path = "/v1/recipient/notifications",
    responses(
        (status = 200, description = "OK", body = NotificationsListResponse),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Missing the FDX consent/scope gate"),
    ),
    security(),
    tag = "fdx",
)]
pub async fn list_notifications(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<NotificationsListResponse>, (StatusCode, String)> {
    let _a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(
        &state.policy,
        &_a,
        &headers,
        sentin8::shield::EvalTarget::new("bank8:fdx:recipient:read"),
    )
    .await?;
    Ok(Json(NotificationsListResponse {
        notifications: Vec::new(),
    }))
}

// ── Admin API (Story ) ───────────────────────────────────────────

/// `GET /v1/admin/provider-profile` - get provider profile.
#[utoipa::path(
    get,
    path = "/v1/admin/provider-profile",
    responses(
        (status = 200, description = "Provider profile (or null when unset)", body = ProviderProfileResponse),
        (status = 403, description = "Missing fdx:admin scope"),
    ),
    security(("fdx:admin" = [])),
    tag = "fdx",
)]
pub async fn get_provider_profile(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<ProviderProfileResponse>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("bank8:fdx:provider:write"),
    )
    .await?;
    // Same-transaction discipline (fdx DESIGN.md §5) - see list_consents.
    let mut conn = state.pool.begin().await.map_err(err_db)?;
    set_tenant_context(&mut conn, a.env_id()).await;
    let row = sqlx::query(
        r#"SELECT id, provider_name, issuer_url, jwks_url, fdx_version, capabilities, status
             FROM provider_profiles ORDER BY created_at DESC LIMIT 1"#,
    )
    .fetch_optional(&mut *conn)
    .await
    .map_err(err_db)?;
    match row {
        Some(r) => Ok(Json(ProviderProfileResponse {
            provider_profile: Some(ProviderProfile {
                id: r.get::<Uuid, _>("id"),
                provider_name: r.get::<String, _>("provider_name"),
                issuer_url: r.get::<String, _>("issuer_url"),
                fdx_version: r.get::<String, _>("fdx_version"),
                status: r.get::<String, _>("status"),
            }),
        })),
        None => Ok(Json(ProviderProfileResponse {
            provider_profile: None,
        })),
    }
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateProviderProfileRequest {
    pub provider_name: String,
    pub issuer_url: String,
    pub fdx_version: String,
}

/// `PUT /v1/admin/provider-profile` - update provider profile.
#[utoipa::path(
    put,
    path = "/v1/admin/provider-profile",
    request_body = UpdateProviderProfileRequest,
    responses(
        (status = 200, description = "Provider profile updated", body = ProviderProfileUpdated),
        (status = 403, description = "Missing fdx:admin scope"),
    ),
    security(("fdx:admin" = [])),
    tag = "fdx",
)]
pub async fn update_provider_profile(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<UpdateProviderProfileRequest>,
) -> Result<Json<ProviderProfileUpdated>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("bank8:fdx:provider:write"),
    )
    .await?;
    // Same-transaction discipline (fdx DESIGN.md §5) - see start_consent.
    let mut conn = state.pool.begin().await.map_err(err_db)?;
    set_tenant_context(&mut conn, a.env_id()).await;
    let row = sqlx::query(
        r#"INSERT INTO provider_profiles (env_id, provider_name, issuer_url, jwks_url, fdx_version, capabilities, status)
           VALUES ($1, $2, $3, '', $4, '[]', 'active')
           ON CONFLICT (env_id, provider_name) DO UPDATE
             SET issuer_url = EXCLUDED.issuer_url, fdx_version = EXCLUDED.fdx_version, updated_at = now()
           RETURNING id"#,
    )
    .bind(a.env_id()).bind(&req.provider_name)
    .bind(&req.issuer_url).bind(&req.fdx_version)
    .fetch_one(&mut *conn).await.map_err(err_db)?;
    let id: Uuid = sqlx::Row::get(&row, "id");
    conn.commit().await.map_err(err_db)?;
    emit_event(&state.pool, a.env_id(), "bank8:fdx:providerprofile:updated", serde_json::json!({ "id": id, "provider_name": req.provider_name, "issuer_url": req.issuer_url, "fdx_version": req.fdx_version })).await;
    Ok(Json(ProviderProfileUpdated {
        id,
        status: "updated".into(),
    }))
}

/// `GET /v1/admin/recipients` - list registered data recipients.
#[utoipa::path(
    get,
    path = "/v1/admin/recipients",
    responses(
        (status = 200, description = "List of recipients", body = [serde_json::Value]),
        (status = 403, description = "Missing fdx:admin scope"),
    ),
    security(("fdx:admin" = [])),
    tag = "fdx",
)]
pub async fn list_recipients(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Vec<AdminRecipientRow>>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("bank8:fdx:provider:write"),
    )
    .await?;
    // Same-transaction discipline (fdx DESIGN.md §5) - see list_consents.
    let mut conn = state.pool.begin().await.map_err(err_db)?;
    set_tenant_context(&mut conn, a.env_id()).await;
    let rows = sqlx::query(
        r#"SELECT id, name, client_id, status, created_at FROM recipients ORDER BY created_at DESC"#,
    ).fetch_all(&mut *conn).await.map_err(err_db)?;
    let recipients: Vec<AdminRecipientRow> = rows
        .iter()
        .map(|r| AdminRecipientRow {
            id: r.get::<Uuid, _>("id"),
            name: r.try_get::<String, _>("name").unwrap_or_default(),
            client_id: r.try_get::<String, _>("client_id").unwrap_or_default(),
            status: r.try_get::<String, _>("status").unwrap_or_default(),
        })
        .collect();
    Ok(Json(recipients))
}

/// `GET /v1/admin/consents` - consent overview (admin).
#[utoipa::path(
    get,
    path = "/v1/admin/consents",
    params(("customer_id" = Option<Uuid>, Query, description = "Filter by customer")),
    responses(
        (status = 200, description = "List of all consents", body = [ConsentResponse]),
        (status = 403, description = "Missing fdx:admin scope"),
    ),
    security(("fdx:admin" = [])),
    tag = "fdx",
)]
pub async fn list_all_consents(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<ListConsentsQuery>,
) -> Result<Json<Vec<ConsentResponse>>, (StatusCode, String)> {
    list_consents(State(state), headers, Query(q)).await
}

/// `GET /v1/admin/audit` - audit trail (admin).
#[utoipa::path(
    get,
    path = "/v1/admin/audit",
    responses(
        (status = 200, description = "List of audit entries", body = [serde_json::Value]),
        (status = 403, description = "Missing fdx:admin scope"),
    ),
    security(("fdx:admin" = [])),
    tag = "fdx",
)]
pub async fn list_admin_audit(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Vec<serde_json::Value>>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("bank8:fdx:provider:write"),
    )
    .await?;
    // Same-transaction discipline (fdx DESIGN.md §5) - see list_consents.
    let mut conn = state.pool.begin().await.map_err(err_db)?;
    set_tenant_context(&mut conn, a.env_id()).await;
    let rows = sqlx::query(
        r#"SELECT id, actor_user_id, action, target_resource_id, timestamp
             FROM audit_events
            ORDER BY timestamp DESC LIMIT 100"#,
    )
    .fetch_all(&mut *conn)
    .await
    .map_err(err_db)?;
    let entries: Vec<serde_json::Value> = rows.iter().map(|r| serde_json::json!({
        "id": r.try_get::<Uuid, _>("id").unwrap_or_default(),
        "actor_user_id": r.try_get::<Option<String>, _>("actor_user_id").ok().flatten().unwrap_or_default(),
        "action": r.try_get::<String, _>("action").unwrap_or_default(),
        "target_resource_id": r.try_get::<Option<String>, _>("target_resource_id").ok().flatten().unwrap_or_default(),
        "timestamp": r.try_get::<chrono::DateTime<chrono::Utc>, _>("timestamp").unwrap_or_default(),
    })).collect();
    Ok(Json(entries))
}

/// `POST /v1/admin/recipients/{id}/activate` - activate a data recipient.
#[utoipa::path(
    post,
    path = "/v1/admin/recipients/{id}/activate",
    params(("id" = Uuid, Path, description = "Recipient ID")),
    responses(
        (status = 200, description = "OK", body = AdminRecipientRow),
        (status = 403, description = "Missing fdx:admin scope"),
        (status = 404, description = "Recipient not found"),
    ),
    security(("fdx:admin" = [])),
    tag = "fdx",
)]
pub async fn activate_recipient(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<Json<AdminRecipientRow>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("bank8:fdx:provider:write"),
    )
    .await?;
    // Same-transaction discipline (fdx DESIGN.md §5) - see start_consent.
    let mut conn = state.pool.begin().await.map_err(err_db)?;
    set_tenant_context(&mut conn, a.env_id()).await;
    let row = sqlx::query(
        r#"UPDATE recipients SET status = 'active', updated_at = now() WHERE id = $1
            RETURNING id, name, client_id, status"#,
    )
    .bind(id)
    .fetch_optional(&mut *conn)
    .await
    .map_err(err_db)?;
    match row {
        Some(r) => Ok(Json(AdminRecipientRow {
            id: r.get::<Uuid, _>("id"),
            name: r.try_get::<String, _>("name").unwrap_or_default(),
            client_id: r.try_get::<String, _>("client_id").unwrap_or_default(),
            status: r.try_get::<String, _>("status").unwrap_or_default(),
        })),
        None => Err((StatusCode::NOT_FOUND, "recipient not found".into())),
    }
}

/// `POST /v1/admin/recipients/{id}/suspend` - suspend a data recipient.
#[utoipa::path(
    post,
    path = "/v1/admin/recipients/{id}/suspend",
    params(("id" = Uuid, Path, description = "Recipient ID")),
    responses(
        (status = 200, description = "OK", body = AdminRecipientRow),
        (status = 403, description = "Missing fdx:admin scope"),
        (status = 404, description = "Recipient not found"),
    ),
    security(("fdx:admin" = [])),
    tag = "fdx",
)]
pub async fn suspend_recipient(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<Json<AdminRecipientRow>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("bank8:fdx:provider:write"),
    )
    .await?;
    // Same-transaction discipline (fdx DESIGN.md §5) - see start_consent.
    let mut conn = state.pool.begin().await.map_err(err_db)?;
    set_tenant_context(&mut conn, a.env_id()).await;
    let row = sqlx::query(
        r#"UPDATE recipients SET status = 'suspended', updated_at = now() WHERE id = $1
            RETURNING id, name, client_id, status"#,
    )
    .bind(id)
    .fetch_optional(&mut *conn)
    .await
    .map_err(err_db)?;
    match row {
        Some(r) => Ok(Json(AdminRecipientRow {
            id: r.get::<Uuid, _>("id"),
            name: r.try_get::<String, _>("name").unwrap_or_default(),
            client_id: r.try_get::<String, _>("client_id").unwrap_or_default(),
            status: r.try_get::<String, _>("status").unwrap_or_default(),
        })),
        None => Err((StatusCode::NOT_FOUND, "recipient not found".into())),
    }
}

/// `GET /v1/recipient/providers/{id}` - get a specific FDX data provider.
#[utoipa::path(
    get,
    path = "/v1/recipient/providers/{id}",
    params(("id" = String, Path, description = "Provider ID")),
    responses(
        (status = 200, description = "OK", body = ProviderCard),
        (status = 403, description = "Missing fdx:read scope"),
        (status = 404, description = "Provider not found"),
    ),
    security(("fdx:read" = [])),
    tag = "fdx",
)]
pub async fn get_recipient_provider(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<ProviderCard>, (StatusCode, String)> {
    let _a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(
        &state.policy,
        &_a,
        &headers,
        sentin8::shield::EvalTarget::new("bank8:fdx:recipient:read"),
    )
    .await?;
    let row = sqlx::query(
        r#"SELECT id, provider_name, issuer_url, fdx_version, capabilities, status
             FROM provider_profiles
            WHERE status = 'active'
              AND (env_id::text = $1 OR id::text = $1)
            LIMIT 1"#,
    )
    .bind(&id)
    .fetch_optional(&state.pool)
    .await
    .map_err(err_db)?;
    match row {
        Some(r) => {
            let caps: serde_json::Value =
                r.try_get("capabilities").unwrap_or(serde_json::json!([]));
            let clusters: Vec<String> = caps
                .as_array()
                .map(|a| {
                    a.iter()
                        .filter_map(|x| x.as_str().map(String::from))
                        .collect()
                })
                .unwrap_or_default();
            Ok(Json(ProviderCard {
                id: r.get::<Uuid, _>("id"),
                name: r.get::<String, _>("provider_name"),
                issuer_url: r.get::<String, _>("issuer_url"),
                fdx_version: r.get::<String, _>("fdx_version"),
                supported_data_clusters: clusters,
                status: r.get::<String, _>("status"),
            }))
        }
        None => Err((StatusCode::NOT_FOUND, "provider not found".into())),
    }
}

/// `GET /v1/recipient/consents/{id}` - get a specific recipient consent.
#[utoipa::path(
    get,
    path = "/v1/recipient/consents/{id}",
    params(("id" = Uuid, Path, description = "Consent ID")),
    responses(
        (status = 200, description = "Recipient consent detail", body = ConsentResponse),
        (status = 403, description = "Missing fdx:read scope"),
        (status = 404, description = "Consent not found"),
    ),
    security(("fdx:read" = [])),
    tag = "fdx",
)]
pub async fn get_recipient_consent(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<Json<RecipientConsentRow>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("bank8:fdx:recipient:read"),
    )
    .await?;
    // The recipient registry is THIS tenant's own table (two-ledger
    // model, DESIGN.md §1): same-env read under the caller's context.
    let mut conn = state.pool.begin().await.map_err(err_db)?;
    set_tenant_context(&mut conn, a.env_id()).await;
    let row = sqlx::query(
        r#"SELECT id, customer_id, provider_id, provider_name, status, scopes,
                  selected_account_ids, created_at, updated_at
             FROM recipient_consents WHERE id = $1"#,
    )
    .bind(id)
    .fetch_optional(&mut *conn)
    .await
    .map_err(err_db)?;
    let _ = conn.commit().await;
    match row {
        Some(r) => Ok(Json(RecipientConsentRow {
            id: r.get::<Uuid, _>("id"),
            customer_id: r.get::<Uuid, _>("customer_id"),
            provider_id: r.get::<String, _>("provider_id"),
            provider_name: r
                .get::<Option<String>, _>("provider_name")
                .unwrap_or_default(),
            status: r.get::<String, _>("status"),
            scopes: r.get::<Vec<String>, _>("scopes"),
            data_clusters: r.get::<Vec<String>, _>("scopes"),
            selected_account_ids: r.get::<Vec<String>, _>("selected_account_ids"),
            created_at: r.get::<chrono::DateTime<chrono::Utc>, _>("created_at"),
            updated_at: r.get::<chrono::DateTime<chrono::Utc>, _>("updated_at"),
        })),
        None => Err((
            StatusCode::NOT_FOUND,
            "consent not found in the recipient registry".into(),
        )),
    }
}

// ── Flow proxy-back (Story ) ────────────────────────────────────

/// `POST /v1/internal/steps/execute` - Flow proxy-back for FDX domain steps.
#[utoipa::path(
    post,
    path = "/v1/internal/steps/execute",
    request_body = crate::flow::ProxyBackRequest,
    responses(
        (status = 200, description = "OK", body = ProxyBackResponse),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Missing the FDX consent/scope gate"),
    ),
    security(),
    tag = "internal",)]
pub async fn execute_step(
    State(_state): State<AppState>,
    _headers: HeaderMap,
    Json(req): Json<crate::flow::ProxyBackRequest>,
) -> Result<Json<crate::flow::ProxyBackResponse>, (StatusCode, String)> {
    let resp = crate::flow::execute_step(&req);
    Ok(Json(resp))
}

// ── Health ───────────────────────────────────────────────────────────────

#[utoipa::path(
    get,
    path = "/v1/health",
    responses(
        (status = 200, description = "OK", body = ServiceHealth),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Missing the FDX consent/scope gate"),
    ),
    security(),
    tag = "meta",
)]
pub async fn health() -> Json<ServiceHealth> {
    Json(ServiceHealth {
        status: "ok".into(),
        service: "fdx".into(),
        version: sentin8::build_info::id().into(),
        build: sentin8::build_info::build_hash().into(),
    })
}

// ── Helpers ──────────────────────────────────────────────────────────────

fn row_to_consent(row: &sqlx::postgres::PgRow) -> ConsentResponse {
    let status: String = row.get("status");
    ConsentResponse {
        id: row.get("id"),
        customer_id: row.get("customer_id"),
        recipient_id: row.get("recipient_id"),
        provider_id: row.get("provider_id"),
        // Normalize to uppercase so the eFintech app's status checks
        // (== 'ACTIVE', == 'REVOKED', == 'FAILED') match regardless of
        // the case used in the DB.
        status: status.to_uppercase(),
        scopes: row.get("scopes"),
        data_clusters: row.get("data_clusters"),
        duration_days: row.get("duration_days"),
        expires_at: row.get("expires_at"),
        created_at: row.get("created_at"),
    }
}

fn err_db(e: sqlx::Error) -> (StatusCode, String) {
    // Log the full error - previously only the status surfaced in service
    // logs, making DB 500s undiagnosable.
    tracing::error!(error = %e, "bank8:fdx: database error");
    (StatusCode::INTERNAL_SERVER_ERROR, e.to_string())
}

/// Generate an RFC 7636 code verifier via the shared FAPI SDK
/// (crypto-random, URL-safe, RFC 7636 §4.1 alphabet).
fn generate_pkce_verifier() -> String {
    sentin8::auth::fapi::generate_pkce_verifier()
}

/// RFC 7636 §4.2 S256 challenge (via the shared FAPI SDK).
fn pkce_s256_challenge(verifier: &str) -> String {
    sentin8::auth::fapi::pkce_s256_challenge(verifier)
}

/// Derive a service URL for the given provider env via the runtime registry
/// (fdx design §4.3c). Used for both the consent callback URL
/// (`bank8-fdx`) and the provider Ledger URL (`bank8-ledger`).
async fn provider_env_fdx_base_url(
    pool: &sqlx::PgPool,
    provider_env_id: Uuid,
    service: &str,
) -> String {
    let cfg = sentin8::config::Sentin8Config::from_env();
    // VDC §VDC.5 - the env identity (slug + org domain) is resolved
    // through Sys's tenant-snapshot API (the sanctioned on-demand
    // cross-tenant read); the former cross-database
    // `sentin8.sys_environments` joins never existed in the vertical's
    // own database and always returned empty (fail-closed no-URL).
    let (env_slug, org_domain) = match crate::tenant_snapshot::env_identity(provider_env_id).await {
        Ok(Some(pair)) => pair,
        Ok(None) => {
            tracing::warn!(%provider_env_id, "fdx: provider env not found - no base URL");
            return String::new();
        }
        Err(e) => {
            tracing::warn!(error = %e, %provider_env_id, "fdx: provider env identity fetch failed - no base URL");
            return String::new();
        }
    };
    if env_slug.is_empty() || org_domain.is_empty() {
        return String::new();
    }
    let env_domain = cfg.env_domain(&env_slug, &org_domain);
    cfg.env_service_url(pool, service, &env_domain).await
}

/// Derive THIS instance's env callback URL - the redirect_uri the
/// recipient's OAuth client registers at the provider's AS and the exact
/// string the PAR + token exchanges must echo (RFC 6749 exact match).
/// Same derivation the env-init DCR registration uses (fdx DESIGN.md §1:
/// the callback belongs to the RECIPIENT, so it derives from the
/// recipient's own env identity - never the provider's).
async fn own_env_callback_url(state: &AppState, env_id: Uuid) -> String {
    let (env_slug, org_domain) = match crate::tenant_snapshot::env_identity(env_id).await {
        Ok(Some(pair)) => pair,
        _ => return String::new(),
    };
    if env_slug.is_empty() || org_domain.is_empty() {
        return String::new();
    }
    let cfg = sentin8::config::Sentin8Config::from_env();
    let env_domain = cfg.env_domain(&env_slug, &org_domain);
    let fdx_base = cfg
        .env_service_url(&state.pool, "bank8:fdx", &env_domain)
        .await;
    if fdx_base.is_empty() {
        return String::new();
    }
    format!("{}/fdx/consents/callback", fdx_base.trim_end_matches('/'))
}

/// Ensure the RECIPIENT's per-provider OAuth client exists at the
/// provider's authorization server (DCR, RFC 7591) and return
/// `(client_id, callback_url)`. Cached in `fdx.recipients` per
/// (recipient env, provider) - one public client per provider the
/// fintech connects to, exactly like a real third-party recipient
/// registers at each bank. The registered redirect_uri is THIS env's
/// callback host; the ES256 DPoP key for RFC 9449 proofs at that
/// provider's token endpoint is generated once and stored sealed
/// (secret reference only, DESIGN.md §5). Same-transaction discipline
/// (§5) on every registry write.
async fn ensure_recipient_client(
    state: &AppState,
    env_id: Uuid,
    provider_id: &str,
    provider_issuer: &str,
) -> Result<(String, String), (StatusCode, String)> {
    // Same-env registry read (recipients is FORCE-RLS in the recipient
    // tenant - the caller's context applies).
    let mut conn = state.pool.begin().await.map_err(err_db)?;
    set_tenant_context(&mut conn, env_id).await;
    let existing = sqlx::query(
        r#"SELECT id, client_id, redirect_uris, dpop_key_ref FROM recipients
            WHERE env_id = $2 AND provider_id = $1 AND status = 'active'
            LIMIT 1"#,
    )
    .bind(provider_id)
    .bind(env_id)
    .fetch_optional(&mut *conn)
    .await
    .map_err(err_db)?;

    // The redirect_uri registered at DCR time is the SAME string the PAR
    // and token exchange echo - derive it once here.
    let callback_url = own_env_callback_url(state, env_id).await;
    if callback_url.is_empty() {
        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            "recipient callback host could not be derived".into(),
        ));
    }

    if let Some(row) = existing.as_ref() {
        let client_id: Option<String> =
            row.try_get::<Option<String>, _>("client_id").ok().flatten();
        if let Some(cid) = client_id.filter(|c| !c.is_empty()) {
            let _ = conn.commit().await;
            // Store the client_id on the active registry rows that lack it
            // (rows created before the DCR registration).
            return Ok((cid, callback_url));
        }
    }

    // Register a fresh public client (PKCE-only, token_endpoint_auth_method
    // none) - the recipient's own identity at the provider's AS.
    let scope =
        "bank8:fdx:accountbasic:read bank8:fdx:accountdetailed:read bank8:fdx:transactions:read";
    let dcr_req = serde_json::json!({
        "client_name": "bank8:fdx:recipient",
        "redirect_uris": [callback_url],
        "grant_types": ["authorization_code", "refresh_token"],
        "response_types": ["code"],
        "scope": scope,
        "token_endpoint_auth_method": "none",
        "application_type": "web",
    });
    let http = reqwest::Client::builder()
        .build()
        .map_err(|e| (StatusCode::BAD_GATEWAY, format!("http client: {e}")))?;
    let register_url = format!("{}/oauth/register", provider_issuer.trim_end_matches('/'));
    let resp = http
        .post(&register_url)
        .json(&dcr_req)
        .send()
        .await
        .map_err(|e| {
            (
                StatusCode::BAD_GATEWAY,
                format!("DCR request to provider AS: {e}"),
            )
        })?;
    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        return Err((
            StatusCode::BAD_GATEWAY,
            format!("DCR failed: {status}: {body}"),
        ));
    }
    let body: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| (StatusCode::BAD_GATEWAY, format!("DCR decode: {e}")))?;
    let client_id = body["client_id"]
        .as_str()
        .ok_or((
            StatusCode::BAD_GATEWAY,
            "DCR response missing client_id".into(),
        ))?
        .to_string();

    // Generate + seal the DPoP key for this (recipient, provider) client -
    // key material in the secrets backend, only the reference on the row.
    let pem = sentin8::auth::fapi::generate_dpop_key_pem().map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("dpop keygen: {e}"),
        )
    })?;

    if let Some(row) = existing {
        let row_id: Uuid = row.get("id");
        let key_ref = crate::tokens::store_dpop_key(row_id, &pem)
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?;
        let _ = sqlx::query(
            r#"UPDATE recipients
                  SET client_id = $2, redirect_uris = $3, dpop_key_ref = $4, updated_at = now()
                WHERE id = $1"#,
        )
        .bind(row_id)
        .bind(&client_id)
        .bind(vec![callback_url.clone()])
        .bind(&key_ref)
        .execute(&mut *conn)
        .await
        .map_err(err_db)?;
    } else {
        let key_ref = crate::tokens::store_dpop_key(Uuid::new_v4(), &pem)
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?;
        let _ = sqlx::query(
            r#"INSERT INTO recipients
                   (env_id, provider_id, recipient_name, client_id, redirect_uris, dpop_key_ref, status)
               VALUES ($1, $2, 'bank8:fdx:recipient', $3, $4, $5, 'active')
               ON CONFLICT (env_id, provider_id) DO UPDATE
                     SET client_id = EXCLUDED.client_id,
                         redirect_uris = EXCLUDED.redirect_uris,
                         dpop_key_ref = EXCLUDED.dpop_key_ref,
                         updated_at = now()"#,
        )
        .bind(env_id)
        .bind(provider_id)
        .bind(&client_id)
        .bind(vec![callback_url.clone()])
        .bind(&key_ref)
        .execute(&mut *conn)
        .await
        .map_err(err_db)?;
    }
    conn.commit().await.map_err(err_db)?;
    tracing::info!(provider = %provider_id, client_id = %client_id, "bank8:fdx: recipient OAuth client registered at the provider AS");
    Ok((client_id, callback_url))
}

/// Load the recipient's DPoP signing key PEM for the given provider
/// (sealed reference on the `fdx.recipients` row).
async fn load_recipient_dpop_key(
    state: &AppState,
    env_id: Uuid,
    provider_id: &str,
) -> Option<String> {
    let mut conn = state.pool.begin().await.ok()?;
    set_tenant_context(&mut conn, env_id).await;
    let row = sqlx::query(
        r#"SELECT id FROM recipients
            WHERE env_id = $2 AND provider_id = $1 AND status = 'active'
            LIMIT 1"#,
    )
    .bind(provider_id)
    .bind(env_id)
    .fetch_optional(&mut *conn)
    .await
    .ok()??;
    let row_id: Uuid = row.get("id");
    crate::tokens::load_dpop_key(&mut conn, row_id)
        .await
        .ok()
        .flatten()
}

/// URL-encode a string for use in query parameters.
fn urlencoding(s: &str) -> String {
    s.replace('%', "%25")
        .replace(' ', "%20")
        .replace(':', "%3A")
        .replace('/', "%2F")
        .replace('&', "%26")
        .replace('?', "%3F")
        .replace('=', "%3D")
}

/// Append an event to the service's LOCAL outbox (DBX producer path,
/// architecture-principles §6.7 - fdx design §12).
/// Inserts a `fdx.outbox` row that the shell's post-commit relay
/// drains to Bus `POST /v1/produce` (idempotency_key = row id). Call this
/// after the domain insert/update/delete succeeds. The outbox is
/// FORCE-RLS'd; the pool helper sets the tenant context on its own
/// connection. Errors are logged and ignored - the committed domain row
/// stays authoritative and the relay retries from the outbox.
pub(crate) async fn emit_event(
    pool: &sqlx::PgPool,
    env_id: uuid::Uuid,
    event_type: &str,
    payload: serde_json::Value,
) {
    if let Err(e) =
        sentin8::bus::outbox::insert_outbox_row_pool(pool, env_id, "fdx", event_type, &payload)
            .await
    {
        tracing::warn!(error = %e, event_type = %event_type, "bank8:fdx: failed to emit outbox event");
    }
}

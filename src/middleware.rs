// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Bank8:FDX
// SPDX-License-Identifier: Apache-2.0

//! Provider pipeline middleware for `/fdx/v6/*` routes (design §4.2).
//! Enforces the FDX contract-validation → header-handling → audit steps that
//! every provider request must pass through. Consent scope enforcement and
//! CSDF minimization live in `consent.rs`/`csdf.rs` and are applied per
//! handler after the upstream Ledger/Payments payload is available.

use axum::{
    body::Body,
    extract::State,
    http::{HeaderMap, Request, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
    Json,
};
use sqlx::Row;
use uuid::Uuid;

use crate::auth;
use crate::csdf::{self, CsdfFilter};
use crate::errors::FdxErrorResponse;
use crate::handlers::AppState;
use crate::headers::inject_interaction_id;
use crate::validation::validate_fdx_request;

/// Provider routes and the data cluster each one touches. The scope the
/// caller must hold per cluster is derived from `csdf::scope_to_clusters`
/// (design §6.1).
#[allow(dead_code)]
pub fn route_cluster(method: &str, path: &str) -> Option<(String, Option<csdf::DataCluster>)> {
    let _ = method;
    let base = "/fdx/v6";
    let rest = path.strip_prefix(base)?;
    match rest {
        "/accounts" => Some(("/accounts".to_string(), Some(csdf::DataCluster::Accounts))),
        "/capability" | "/availability" | "/certification-metrics" => {
            Some((rest.to_string(), None))
        }
        _ => None,
    }
}

/// Strip `{accountId}` placeholders from a concrete path for audit action
/// naming (`data_call:accounts/{id}` style is avoided; the route shape is
/// used instead).
pub fn audit_route_name(path: &str) -> String {
    let parts: Vec<&str> = path.split('/').collect();
    // parts[0]="" parts[1]="fdx" parts[2]="v6" parts[3]=resource parts[4]=id
    if parts.len() >= 5 && parts[1] == "fdx" && parts[2] == "v6" {
        let mut shape = String::from("/fdx/v6");
        for (i, part) in parts.iter().skip(3).enumerate() {
            let shaped = if i == 1 && uuid::Uuid::parse_str(part).is_ok() {
                "{accountId}"
            } else if i >= 1 && uuid::Uuid::parse_str(part).is_ok() {
                "{id}"
            } else {
                *part
            };
            shape.push('/');
            shape.push_str(shaped);
        }
        shape
    } else {
        path.to_string()
    }
}

/// Append an audit row for a provider data call. Best-effort: audit failure
/// never fails the API response.
pub async fn audit_data_call(pool: &sqlx::PgPool, env_id: Uuid, actor: &str, route: &str) {
    let _ = sqlx::query(
        r#"INSERT INTO audit_events (env_id, actor_user_id, action, target_resource_type, target_resource_id, correlation_id)
           VALUES ($1, $2, $3, 'FDX_PROVIDER_ROUTE', $4, $4)"#,
    )
    .bind(env_id)
    .bind(actor)
    .bind(format!("data_call:{route}"))
    .bind(route)
    .execute(pool)
    .await;
}

/// Map a route to the OAuth scope that grants its data cluster (design §6.1).
fn scope_for_cluster(cluster: csdf::DataCluster) -> &'static str {
    match cluster {
        csdf::DataCluster::Accounts => "bank8:fdx:accountbasic:read",
        csdf::DataCluster::Transactions => "bank8:fdx:transactions:read",
        csdf::DataCluster::Statements => "bank8:fdx:statements:read",
        csdf::DataCluster::Customers => "bank8:fdx:customerpersonal:read",
        csdf::DataCluster::Payments | csdf::DataCluster::Transfers => "bank8:fdx:transfers:write",
        csdf::DataCluster::Tax => "bank8:fdx:tax:read",
    }
}

/// Resolve the caller's consent scopes for CSDF minimization. Reads the
/// latest active grant for the (caller env, token subject) pair (design
/// §1/§4.2) and maps its scopes to a `CsdfFilter`. The grant ledger's
/// `customer_id` IS the token `sub` — both are the provider's user id at
/// code issuance (the AS event seeds the row from the authorized user), so
/// a delegated recipient token and the bank's own customer token resolve
/// the SAME grant row: the customer's grant governs what data may leave,
/// regardless of which client presents a token for it.
pub async fn consent_filter(state: &AppState, _a: &auth::AuthContext) -> CsdfFilter {
    // Same-transaction discipline (fdx DESIGN.md §5): context + lookup on
    // one tx — a bare autocommit connection loses the transaction-local
    // context and RLS answers with zero consent rows (→ 403 for every
    // provider data call).
    let Ok(mut conn) = state.pool.begin().await else {
        return CsdfFilter::new(Vec::new());
    };
    sentin8::shell::set_tenant_context(&mut conn, _a.env_id()).await;
    let scopes: Vec<String> = sqlx::query(
        r#"SELECT scopes FROM consents
            WHERE env_id = $1 AND customer_id = $2 AND status = 'active'
            ORDER BY created_at DESC LIMIT 1"#,
    )
    .bind(_a.env_id())
    .bind(_a.sub())
    .fetch_optional(&mut *conn)
    .await
    .ok()
    .flatten()
    .and_then(|row| row.try_get::<Vec<String>, _>("scopes").ok())
    .unwrap_or_default();
    let _ = conn.commit().await;
    // Platform admins are not exempt from consent enforcement — the FDX
    // provider API is consent-driven by design (§4.2).
    CsdfFilter::new(scopes)
}

/// Header-only convenience overload used by handlers that need the CSDF
/// filter after `provider_authz` already verified the token. Verifies again
/// (cheap — cached JWKS/discovery) so the helper is self-contained.
pub async fn consent_filter_from_headers(
    state: &AppState,
    headers: &axum::http::HeaderMap,
) -> CsdfFilter {
    match auth::verify_token(&state.config, headers).await {
        Ok(a) => consent_filter(state, &a).await,
        Err(_) => CsdfFilter::new(Vec::new()),
    }
}

/// Enforce the consent scope for a provider route. `Err` carries the FDX
/// error response to return (403 INSUFFICIENT_SCOPE).
pub fn enforce_consent(
    filter: &CsdfFilter,
    cluster: Option<csdf::DataCluster>,
) -> Result<(), FdxErrorResponse> {
    match cluster {
        None => Ok(()),
        Some(c) => {
            if filter.has_cluster(c) {
                Ok(())
            } else {
                Err(FdxErrorResponse::new(
                    403,
                    "INSUFFICIENT_SCOPE",
                    format!("consent does not grant {}", scope_for_cluster(c)),
                ))
            }
        }
    }
}

/// Apply CSDF minimization to a provider response payload (design §7).
pub fn minimize_response(payload: &serde_json::Value, filter: &CsdfFilter) -> serde_json::Value {
    csdf::minimize_csdf(payload, filter)
}

/// The provider middleware itself. Runs for every `/fdx/v6/*` request:
/// FDX contract validation → header extraction → response header injection
/// (`x-fapi-interaction-id`) → audit append.
pub async fn provider_middleware(
    State(state): State<AppState>,
    req: Request<Body>,
    next: Next,
) -> Response {
    let (parts, body) = req.into_parts();
    let method = parts.method.to_string();
    let path = parts.uri.path().to_string();
    let req_headers = parts.headers.clone();

    // 0. families declared out of scope (design §3.1) return the
    // FDX-standard unsupported-operation response — never a silent stub.
    if crate::operations::is_out_of_scope_path(&path) {
        let mut r = crate::operations::unsupported_operation_response(&path);
        inject_interaction_id(&req_headers, r.headers_mut());
        return r;
    }

    // 1. FDX contract validation (route/method/body shape).
    let body_bytes = match axum::body::to_bytes(body, 1024 * 1024).await {
        Ok(b) => b,
        Err(e) => {
            return FdxErrorResponse::bad_request(format!("body read: {e}")).into_response();
        }
    };
    let body_str = String::from_utf8_lossy(&body_bytes).to_string();
    if let Err(err) = validate_fdx_request(&method, &path, &body_str) {
        let mut r = (
            StatusCode::from_u16(err.status_code).unwrap_or(StatusCode::BAD_REQUEST),
            Json(err),
        )
            .into_response();
        inject_interaction_id(&req_headers, r.headers_mut());
        return r;
    }

    // 2. Token verification (the standard pipeline entry).
    let auth_result = auth::verify_token(&state.config, &req_headers).await;

    // 3. Header extraction — echo/generate x-fapi-interaction-id on the
    // response (design §8).
    let rebuilt = Request::from_parts(parts, Body::from(body_bytes));

    let mut resp = match auth_result {
        Ok(_) => next.run(rebuilt).await,
        Err((status, msg)) => {
            let mut r = (status, msg).into_response();
            inject_interaction_id(&req_headers, r.headers_mut());
            return r;
        }
    };

    inject_interaction_id(&req_headers, resp.headers_mut());

    // 4. Audit append (best-effort) — design §9.
    if let Ok(a) = auth::verify_token(&state.config, &req_headers).await {
        let route = audit_route_name(&path);
        audit_data_call(&state.pool, a.env_id(), a.sub(), &route).await;
    }

    resp
}

/// Handler-facing helper: verify token + enforce the consent cluster for a
/// provider route, returning the auth context or an FDX error response.
pub async fn provider_authz(
    state: &AppState,
    headers: &HeaderMap,
    cluster: Option<csdf::DataCluster>,
) -> Result<auth::AuthContext, Response> {
    let a = match auth::verify_token(&state.config, headers).await {
        Ok(a) => a,
        Err((status, msg)) => return Err((status, msg).into_response()),
    };
    let filter = consent_filter(state, &a).await;
    match enforce_consent(&filter, cluster) {
        Ok(()) => Ok(a),
        Err(e) => Err(e.into_response()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_route_cluster_known_routes() {
        assert_eq!(
            route_cluster("GET", "/fdx/v6/accounts"),
            Some(("/accounts".to_string(), Some(csdf::DataCluster::Accounts)))
        );
        assert_eq!(
            route_cluster("GET", "/fdx/v6/capability"),
            Some(("/capability".to_string(), None))
        );
        assert_eq!(
            route_cluster("GET", "/fdx/v6/availability"),
            Some(("/availability".to_string(), None))
        );
        assert_eq!(
            route_cluster("GET", "/fdx/v6/certification-metrics"),
            Some(("/certification-metrics".to_string(), None))
        );
    }

    #[test]
    fn test_route_cluster_unknown_route() {
        assert!(route_cluster("GET", "/fdx/v6/widgets").is_none());
        assert!(route_cluster("GET", "/other/accounts").is_none());
    }

    #[test]
    fn test_audit_route_name_shapes_ids() {
        assert_eq!(audit_route_name("/fdx/v6/accounts"), "/fdx/v6/accounts");
        let id = Uuid::new_v4();
        assert_eq!(
            audit_route_name(&format!("/fdx/v6/accounts/{id}")),
            "/fdx/v6/accounts/{accountId}"
        );
        assert_eq!(
            audit_route_name(&format!("/fdx/v6/accounts/{id}/transactions")),
            "/fdx/v6/accounts/{accountId}/transactions"
        );
        assert_eq!(audit_route_name("/other"), "/other");
    }

    #[test]
    fn test_enforce_consent_allows_in_scope() {
        let filter = CsdfFilter::new(vec!["bank8:fdx:accountbasic:read".into()]);
        assert!(enforce_consent(&filter, Some(csdf::DataCluster::Accounts)).is_ok());
        assert!(enforce_consent(&filter, None).is_ok());
    }

    #[test]
    fn test_enforce_consent_rejects_out_of_scope() {
        let filter = CsdfFilter::new(vec!["bank8:fdx:accountbasic:read".into()]);
        let err = enforce_consent(&filter, Some(csdf::DataCluster::Transactions)).unwrap_err();
        assert_eq!(err.status_code, 403);
        assert_eq!(err.error_code, "INSUFFICIENT_SCOPE");
    }

    #[test]
    fn test_enforce_consent_rejects_empty_consent() {
        let filter = CsdfFilter::new(vec![]);
        assert!(enforce_consent(&filter, Some(csdf::DataCluster::Accounts)).is_err());
    }

    #[test]
    fn test_minimize_response_applies_csdf() {
        let filter = CsdfFilter::new(vec!["bank8:fdx:accountbasic:read".into()]);
        let payload = serde_json::json!({
            "accounts": [{"id": "a1"}],
            "transactions": [{"id": "t1"}],
        });
        let out = minimize_response(&payload, &filter);
        assert!(out.get("accounts").is_some());
        assert!(out.get("transactions").is_none());
    }

    #[test]
    fn test_scope_for_cluster_maps_all() {
        assert_eq!(
            scope_for_cluster(csdf::DataCluster::Accounts),
            "bank8:fdx:accountbasic:read"
        );
        assert_eq!(
            scope_for_cluster(csdf::DataCluster::Tax),
            "bank8:fdx:tax:read"
        );
    }
}

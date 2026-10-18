// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Bank8:FDX
// SPDX-License-Identifier: Apache-2.0

//! FDX v6.5 completion — out-of-scope family classification +
//! machine-readable operation-support statement (design §3.1, §5.1).

use axum::{
    extract::State,
    http::HeaderMap,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::Value as JsonValue;

use crate::errors::FdxErrorResponse;
use crate::handlers::AppState;
use crate::middleware;

/// Precise out-of-scope path check: whole families (tax, payroll, fraud,
/// rewards, registry, images) plus the two account-scoped out-of-scope
/// sub-resources. Returns true only for §3.1 families — implemented routes
/// must never hit this.
pub fn is_out_of_scope_path(path: &str) -> bool {
    const WHOLE_FAMILIES: &[&str] = &[
        "/fdx/v6/reward-programs",
        "/fdx/v6/tax-forms",
        "/fdx/v6/tax",
        "/fdx/v6/payroll",
        "/fdx/v6/fraud",
        "/fdx/v6/data-providers",
        "/fdx/v6/recipients",
        "/fdx/v6/terms-and-conditions",
        "/fdx/v6/contacts",
    ];
    const ACCOUNT_SCOPED: &[&str] = &["/reward-transactions", "/transaction-images/"];
    if WHOLE_FAMILIES.iter().any(|p| path.starts_with(p)) {
        return true;
    }
    for suffix in ACCOUNT_SCOPED {
        if let Some(rest) = path.strip_prefix("/fdx/v6/accounts/") {
            // /accounts/{id}<suffix>
            if let Some(pos) = rest.find(suffix) {
                let _ = pos;
                return true;
            }
        }
    }
    false
}

/// The FDX-standard unsupported-operation error (501 / code 1106).
pub fn unsupported_operation_response(path: &str) -> Response {
    FdxErrorResponse::new(
        501,
        "1106",
        format!("Operation not supported or not implemented: {path}"),
    )
    .into_response()
}

/// `GET /fdx/v6/operation-support` — explicit machine-readable statement of
/// which FDX families this provider implements vs reserves (§3.1); pairs
/// with the middleware 501s so clients can preflight.
#[utoipa::path(
    get,
    path = "/fdx/v6/operation-support",
    responses(
        (status = 200, description = "OK", body = serde_json::Value),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Missing the FDX consent/scope gate"),
    ),
    security(),
    tag = "fdx",
)]
pub async fn get_operation_support(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<JsonValue>, Response> {
    let _a = middleware::provider_authz(&state, &headers, None).await?;
    let _ = state;
    Ok(Json(serde_json::json!({
        "implemented": [
            "accounts", "transactions", "statements", "customers", "consents",
            "transfers", "payments", "payees", "payment-initiation-parties",
            "recurring-payments", "payment-networks", "notification-subscriptions",
            "notifications", "register", "capability", "availability",
            "certification-metrics",
        ],
        "outOfScope": [
            "reward-programs", "transaction-images", "tax-forms", "payroll",
            "fraud", "data-providers", "recipients-registry",
            "terms-and-conditions", "contacts", "bills", "investments",
            "social-security", "digital-wallet",
        ],
    })))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::StatusCode;

    #[test]
    fn out_of_scope_whole_families() {
        assert!(is_out_of_scope_path("/fdx/v6/reward-programs"));
        assert!(is_out_of_scope_path("/fdx/v6/reward-programs/123"));
        assert!(is_out_of_scope_path("/fdx/v6/tax-forms"));
        assert!(is_out_of_scope_path("/fdx/v6/tax/2024/1099-INT"));
        assert!(is_out_of_scope_path("/fdx/v6/payroll/employers"));
        assert!(is_out_of_scope_path("/fdx/v6/fraud/suspected-incident"));
        assert!(is_out_of_scope_path("/fdx/v6/data-providers"));
        assert!(is_out_of_scope_path("/fdx/v6/recipients"));
        assert!(is_out_of_scope_path("/fdx/v6/terms-and-conditions"));
        assert!(is_out_of_scope_path("/fdx/v6/contacts"));
    }

    #[test]
    fn out_of_scope_account_scoped() {
        assert!(is_out_of_scope_path(
            "/fdx/v6/accounts/abc/reward-transactions"
        ));
        assert!(is_out_of_scope_path(
            "/fdx/v6/accounts/abc/transaction-images/img1"
        ));
    }

    #[test]
    fn implemented_routes_never_out_of_scope() {
        // Implemented §5.1 routes must NOT be classified out of scope.
        let ok = [
            "/fdx/v6/accounts",
            "/fdx/v6/accounts/abc",
            "/fdx/v6/accounts/abc/transactions",
            "/fdx/v6/accounts/abc/statements",
            "/fdx/v6/accounts/abc/statements/st1",
            "/fdx/v6/accounts/abc/payment-networks",
            "/fdx/v6/accounts/abc/payment-networks/pn1",
            "/fdx/v6/accounts/abc/payment-networks/pn1/revocation",
            "/fdx/v6/customers",
            "/fdx/v6/consents/c1",
            "/fdx/v6/consents/c1/revocation",
            "/fdx/v6/consents/c1/lifecycle",
            "/fdx/v6/transfers",
            "/fdx/v6/transfers/t1",
            "/fdx/v6/payments/p1",
            "/fdx/v6/payees",
            "/fdx/v6/payment-initiation-parties",
            "/fdx/v6/payment-initiation-parties/p1/payment-methods",
            "/fdx/v6/recurring-payments",
            "/fdx/v6/notification-subscriptions",
            "/fdx/v6/notifications",
            "/fdx/v6/register",
            "/fdx/v6/register/client-1",
            "/fdx/v6/capability",
            "/fdx/v6/availability",
            "/fdx/v6/certification-metrics",
            "/fdx/v6/operation-support",
        ];
        for p in ok {
            assert!(
                !is_out_of_scope_path(p),
                "{p} wrongly classified out of scope"
            );
        }
    }

    #[test]
    fn unsupported_operation_error_shape() {
        let resp = unsupported_operation_response("/fdx/v6/tax-forms");
        assert_eq!(resp.status(), StatusCode::NOT_IMPLEMENTED);
    }
}

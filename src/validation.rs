// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Bank8:FDX
// SPDX-License-Identifier: Apache-2.0

//! Story — FDX v6.5 contract validation.
//! Validates inbound requests against the FDX v6.5 API contract: required
//! fields, content-type, accept headers, and path/method combinations.

use serde::{Deserialize, Serialize};

/// FDX error returned by the validation layer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FdxError {
    pub status_code: u16,
    pub error_code: String,
    pub message: String,
}

impl FdxError {
    pub fn new(status_code: u16, error_code: impl Into<String>, message: impl Into<String>) -> Self {
        Self { status_code, error_code: error_code.into(), message: message.into() }
    }
}

impl std::fmt::Display for FdxError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[{}] {}: {}", self.status_code, self.error_code, self.message)
    }
}

impl std::error::Error for FdxError {}

/// Categorised validation error types.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FdxValidationError {
    /// Missing or invalid Content-Type header.
    InvalidContentType,
    /// Missing or unacceptable Accept header.
    InvalidAccept,
    /// HTTP method not allowed for the path.
    MethodNotAllowed,
    /// Required path or body field missing.
    MissingRequiredField(String),
    /// Unknown FDX v6.5 route.
    UnknownRoute,
    /// Malformed JSON body.
    MalformedBody,
    /// Field value failed validation.
    InvalidFieldValue(String),
}

impl FdxValidationError {
    /// Map a validation error to an FDX error response.
    pub fn to_fdx_error(&self) -> FdxError {
        match self {
            Self::InvalidContentType => FdxError::new(415, "UNSUPPORTED_MEDIA_TYPE", "Content-Type must be application/json"),
            Self::InvalidAccept => FdxError::new(406, "NOT_ACCEPTABLE", "Accept header must include application/json"),
            Self::MethodNotAllowed => FdxError::new(405, "METHOD_NOT_ALLOWED", "HTTP method not allowed for this route"),
            Self::MissingRequiredField(f) => FdxError::new(400, "MISSING_FIELD", format!("required field missing: {f}")),
            Self::UnknownRoute => FdxError::new(404, "NOT_FOUND", "unknown FDX v6.5 route"),
            Self::MalformedBody => FdxError::new(400, "MALFORMED_JSON", "request body is not valid JSON"),
            Self::InvalidFieldValue(f) => FdxError::new(400, "INVALID_FIELD", format!("invalid field value: {f}")),
        }
    }
}

/// Validate an inbound FDX request against the v6.5 contract.
/// `method` is the HTTP method (GET, POST, PUT, DELETE).
/// `path` is the request path (e.g. `/fdx/v6/accounts`).
/// `body` is the raw JSON body string (may be empty for GET).
pub fn validate_fdx_request(method: &str, path: &str, body: &str) -> Result<(), FdxError> {
    let method = method.to_uppercase();
    // Route table: (method prefix, path pattern, requires_body, required_body_fields)
    let routes: &[(&str, &str, bool, &[&str])] = &[
        ("GET", "/fdx/v6/accounts", false, &[]),
        ("GET", "/fdx/v6/accounts/{accountId}", false, &[]),
        ("GET", "/fdx/v6/accounts/{accountId}/transactions", false, &[]),
        ("GET", "/fdx/v6/accounts/{accountId}/statements", false, &[]),
        ("GET", "/fdx/v6/accounts/{accountId}/payment-networks", false, &[]),
        ("GET", "/fdx/v6/customers", false, &[]),
        ("GET", "/fdx/v6/customers/current", false, &[]),
        ("GET", "/fdx/v6/consents/{consentId}", false, &[]),
        ("PUT", "/fdx/v6/consents/{consentId}/revocation", false, &[]),
        ("POST", "/fdx/v6/transfers", true, &["fromAccountId", "toAccountId", "amount"]),
        ("POST", "/fdx/v6/payments", true, &["accountId", "amount"]),
        ("GET", "/fdx/v6/capability", false, &[]),
        ("GET", "/fdx/v6/availability", false, &[]),
        ("GET", "/fdx/v6/certification-metrics", false, &[]),
        // Statement download.
        ("GET", "/fdx/v6/accounts/{accountId}/statements/{statementId}", false, &[]),
        // : money-movement reads + update/cancel + payees.
        ("GET", "/fdx/v6/payments/{paymentId}", false, &[]),
        ("GET", "/fdx/v6/transfers/{transferId}", false, &[]),
        ("PATCH", "/fdx/v6/transfers/{transferId}", true, &[]),
        ("DELETE", "/fdx/v6/transfers/{transferId}", false, &[]),
        ("GET", "/fdx/v6/payees", false, &[]),
        ("POST", "/fdx/v6/payees", true, &[]),
        ("PUT", "/fdx/v6/payees/{payeeId}", true, &[]),
        // : PIP + recurring.
        ("POST", "/fdx/v6/payment-initiation-parties", true, &["partyName"]),
        ("GET", "/fdx/v6/payment-initiation-parties/{partyId}", false, &[]),
        ("POST", "/fdx/v6/payment-initiation-parties/{partyId}/payment-methods", true, &["methodType"]),
        ("DELETE", "/fdx/v6/payment-initiation-parties/{partyId}/payment-methods/{regId}", false, &[]),
        ("POST", "/fdx/v6/recurring-payments", true, &["fromAccountId", "amount", "frequency"]),
        ("GET", "/fdx/v6/recurring-payments", false, &[]),
        ("GET", "/fdx/v6/recurring-payments/{recurringPaymentId}", false, &[]),
        ("GET", "/fdx/v6/recurring-payments/{recurringPaymentId}/payments", false, &[]),
        // : recipient registration (DCR proxy).
        ("POST", "/fdx/v6/register", true, &[]),
        ("GET", "/fdx/v6/register/{clientId}", false, &[]),
        ("PUT", "/fdx/v6/register/{clientId}", true, &[]),
        // : payment network detail + revocation.
        ("GET", "/fdx/v6/accounts/{accountId}/payment-networks/{paymentNetworkId}", false, &[]),
        ("PUT", "/fdx/v6/accounts/{accountId}/payment-networks/{paymentNetworkId}/revocation", true, &["reason", "initiator"]),
        ("GET", "/fdx/v6/accounts/{accountId}/payment-networks/{paymentNetworkId}/revocation", false, &[]),
        // /: notification subscriptions + feed.
        ("POST", "/fdx/v6/notification-subscriptions", true, &["eventType", "category", "callbackUrl"]),
        ("GET", "/fdx/v6/notification-subscriptions", false, &[]),
        ("GET", "/fdx/v6/notification-subscriptions/{subscriptionId}", false, &[]),
        ("DELETE", "/fdx/v6/notification-subscriptions/{subscriptionId}", false, &[]),
        ("POST", "/fdx/v6/notifications", true, &["notificationType"]),
        ("GET", "/fdx/v6/notifications", false, &[]),
        // : revocation record GET.
        ("GET", "/fdx/v6/consents/{consentId}/revocation", false, &[]),
        // : consent lifecycle.
        ("PUT", "/fdx/v6/consents/{consentId}/lifecycle", true, &["durationType"]),
        // : operation support statement.
        ("GET", "/fdx/v6/operation-support", false, &[]),
    ];
    let matched = routes.iter().find(|(_, pat, _, _)| route_matches(pat, path));
    let route = match matched {
        Some(r) => r,
        None => return Err(FdxValidationError::UnknownRoute.to_fdx_error()),
    };
    if route.0 != method {
        return Err(FdxValidationError::MethodNotAllowed.to_fdx_error());
    }
    if route.2 {
        // Body required — parse and check required fields.
        let parsed: serde_json::Value = if body.is_empty() {
            return Err(FdxValidationError::MissingRequiredField("(body)".into()).to_fdx_error());
        } else {
            serde_json::from_str(body).map_err(|_| FdxValidationError::MalformedBody.to_fdx_error())?
        };
        let obj = parsed.as_object().ok_or_else(|| FdxValidationError::MalformedBody.to_fdx_error())?;
        for field in route.3 {
            if !obj.contains_key(*field) {
                return Err(FdxValidationError::MissingRequiredField((*field).into()).to_fdx_error());
            }
        }
    }
    Ok(())
}

/// Match a route pattern with `{placeholder}` segments against a concrete path.
fn route_matches(pattern: &str, path: &str) -> bool {
    let pat_parts: Vec<&str> = pattern.split('/').collect();
    let path_parts: Vec<&str> = path.split('/').collect();
    if pat_parts.len() != path_parts.len() {
        return false;
    }
    for (pp, ap) in pat_parts.iter().zip(path_parts.iter()) {
        if pp.starts_with('{') && pp.ends_with('}') {
            // Placeholder — accept any non-empty segment.
            if ap.is_empty() {
                return false;
            }
        } else if pp != ap {
            return false;
        }
    }
    true
}

/// Validate the Content-Type and Accept headers for FDX v6.5.
pub fn validate_headers(content_type: Option<&str>, accept: Option<&str>) -> Result<(), FdxError> {
    if let Some(ct) = content_type {
        if !ct.starts_with("application/json") {
            return Err(FdxValidationError::InvalidContentType.to_fdx_error());
        }
    }
    if let Some(acc) = accept {
        // Accept must include application/json or */*.
        if !acc.contains("application/json") && !acc.contains("*/*") {
            return Err(FdxValidationError::InvalidAccept.to_fdx_error());
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_known_route_get_accounts() {
        assert!(validate_fdx_request("GET", "/fdx/v6/accounts", "").is_ok());
    }

    #[test]
    fn test_known_route_get_account_detail() {
        assert!(validate_fdx_request("GET", "/fdx/v6/accounts/550e8400-e29b-41d4-a716-446655440000", "").is_ok());
    }

    #[test]
    fn test_unknown_route() {
        let err = validate_fdx_request("GET", "/fdx/v6/unknown", "").unwrap_err();
        assert_eq!(err.status_code, 404);
        assert_eq!(err.error_code, "NOT_FOUND");
    }

    #[test]
    fn test_method_not_allowed() {
        let err = validate_fdx_request("DELETE", "/fdx/v6/accounts", "").unwrap_err();
        assert_eq!(err.status_code, 405);
    }

    #[test]
    fn test_transfers_missing_body() {
        let err = validate_fdx_request("POST", "/fdx/v6/transfers", "").unwrap_err();
        assert_eq!(err.status_code, 400);
        assert_eq!(err.error_code, "MISSING_FIELD");
    }

    #[test]
    fn test_transfers_missing_required_field() {
        let body = r#"{"fromAccountId" :"a","toAccountId" :"b"}"#; // missing amount
        let err = validate_fdx_request("POST", "/fdx/v6/transfers", body).unwrap_err();
        assert_eq!(err.error_code, "MISSING_FIELD");
        assert!(err.message.contains("amount"));
    }

    #[test]
    fn test_transfers_valid() {
        let body = r#"{"fromAccountId" :"a","toAccountId" :"b","amount":{"value":"10.00","currency":"USD"}}"#;
        assert!(validate_fdx_request("POST", "/fdx/v6/transfers", body).is_ok());
    }

    #[test]
    fn test_malformed_body() {
        let err = validate_fdx_request("POST", "/fdx/v6/transfers", "{not json").unwrap_err();
        assert_eq!(err.error_code, "MALFORMED_JSON");
    }

    #[test]
    fn test_validate_headers_ok() {
        assert!(validate_headers(Some("application/json"), Some("application/json")).is_ok());
        assert!(validate_headers(Some("application/json; charset=utf-8"), Some("*/*")).is_ok());
    }

    #[test]
    fn test_validate_headers_bad_content_type() {
        let err = validate_headers(Some("text/plain"), Some("application/json")).unwrap_err();
        assert_eq!(err.status_code, 415);
    }

    #[test]
    fn test_validate_headers_bad_accept() {
        let err = validate_headers(Some("application/json"), Some("text/html")).unwrap_err();
        assert_eq!(err.status_code, 406);
    }

    #[test]
    fn test_route_matches_placeholder() {
        assert!(route_matches("/fdx/v6/accounts/{accountId}", "/fdx/v6/accounts/abc-123"));
        assert!(!route_matches("/fdx/v6/accounts/{accountId}", "/fdx/v6/accounts"));
        assert!(!route_matches("/fdx/v6/accounts", "/fdx/v6/accounts/abc/extra"));
    }

    #[test]
    fn test_validation_error_to_fdx_error() {
        let e = FdxValidationError::MissingRequiredField("amount".into()).to_fdx_error();
        assert_eq!(e.status_code, 400);
        assert!(e.message.contains("amount"));
    }
}
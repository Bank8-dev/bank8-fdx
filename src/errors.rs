// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Bank8:FDX
// SPDX-License-Identifier: Apache-2.0

//! Story — FDX error responses.
//! Standard FDX error format with error codes and HTTP status mappings.
//! Integrates with Axum via `into_response `.

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::{Deserialize, Serialize};

/// Standard FDX error response body.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FdxErrorResponse {
    /// HTTP status code.
    pub status_code: u16,
    /// Machine-readable error code.
    pub error_code: String,
    /// Human-readable error message.
    pub message: String,
    /// Optional additional details.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<serde_json::Value>,
}

impl FdxErrorResponse {
    pub fn new(status: u16, code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            status_code: status,
            error_code: code.into(),
            message: message.into(),
            details: None,
        }
    }

    pub fn with_details(mut self, details: serde_json::Value) -> Self {
        self.details = Some(details);
        self
    }

    /// Build a response from a known FDX error code.
    pub fn from_code(code: &str, message: impl Into<String>) -> Self {
        let (status, code) = error_code_mapping(code);
        Self::new(status, code, message)
    }
}

/// Map an FDX error code to its (HTTP status, canonical code).
pub fn error_code_mapping(code: &str) -> (u16, String) {
    let (status, c): (u16, String) = match code {
        "INVALID_REQUEST" | "MALFORMED_JSON" | "MISSING_FIELD" | "INVALID_FIELD" => {
            (400, code.to_string())
        }
        "UNAUTHORIZED" | "INVALID_TOKEN" => (401, code.to_string()),
        "FORBIDDEN" | "INSUFFICIENT_SCOPE" => (403, code.to_string()),
        "NOT_FOUND" => (404, code.to_string()),
        "NOT_ACCEPTABLE" => (406, code.to_string()),
        "CONFLICT" | "DUPLICATE" => (409, code.to_string()),
        "INTERNAL_ERROR" => (500, code.to_string()),
        "NOT_IMPLEMENTED" => (501, code.to_string()),
        "SERVICE_UNAVAILABLE" => (503, code.to_string()),
        // Status-first lookup: numeric code → default
        other => (400, other.to_string()),
    };
    (status, c)
}

impl IntoResponse for FdxErrorResponse {
    fn into_response(self) -> Response {
        let status =
            StatusCode::from_u16(self.status_code).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
        (status, Json(self)).into_response()
    }
}

impl From<FdxErrorResponse> for Response {
    fn from(e: FdxErrorResponse) -> Self {
        e.into_response()
    }
}

/// Convenience constructors for common FDX error codes.
impl FdxErrorResponse {
    pub fn bad_request(msg: impl Into<String>) -> Self {
        Self::new(400, "INVALID_REQUEST", msg)
    }
    pub fn unauthorized(msg: impl Into<String>) -> Self {
        Self::new(401, "UNAUTHORIZED", msg)
    }
    pub fn forbidden(msg: impl Into<String>) -> Self {
        Self::new(403, "FORBIDDEN", msg)
    }
    pub fn not_found(msg: impl Into<String>) -> Self {
        Self::new(404, "NOT_FOUND", msg)
    }
    pub fn not_acceptable(msg: impl Into<String>) -> Self {
        Self::new(406, "NOT_ACCEPTABLE", msg)
    }
    pub fn conflict(msg: impl Into<String>) -> Self {
        Self::new(409, "CONFLICT", msg)
    }
    pub fn internal(msg: impl Into<String>) -> Self {
        Self::new(500, "INTERNAL_ERROR", msg)
    }
    pub fn not_implemented(msg: impl Into<String>) -> Self {
        Self::new(501, "NOT_IMPLEMENTED", msg)
    }
    pub fn service_unavailable(msg: impl Into<String>) -> Self {
        Self::new(503, "SERVICE_UNAVAILABLE", msg)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_code_mapping_all_statuses() {
        assert_eq!(error_code_mapping("INVALID_REQUEST").0, 400);
        assert_eq!(error_code_mapping("UNAUTHORIZED").0, 401);
        assert_eq!(error_code_mapping("FORBIDDEN").0, 403);
        assert_eq!(error_code_mapping("NOT_FOUND").0, 404);
        assert_eq!(error_code_mapping("NOT_ACCEPTABLE").0, 406);
        assert_eq!(error_code_mapping("CONFLICT").0, 409);
        assert_eq!(error_code_mapping("INTERNAL_ERROR").0, 500);
        assert_eq!(error_code_mapping("NOT_IMPLEMENTED").0, 501);
        assert_eq!(error_code_mapping("SERVICE_UNAVAILABLE").0, 503);
    }

    #[test]
    fn test_from_code() {
        let e = FdxErrorResponse::from_code("NOT_FOUND", "account not found");
        assert_eq!(e.status_code, 404);
        assert_eq!(e.error_code, "NOT_FOUND");
    }

    #[test]
    fn test_with_details() {
        let e = FdxErrorResponse::bad_request("invalid")
            .with_details(serde_json::json!({"field": "amount"}));
        assert_eq!(e.details.as_ref().unwrap()["field"], "amount");
    }

    #[test]
    fn test_into_response_status() {
        let resp = FdxErrorResponse::not_found("gone").into_response();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[test]
    fn test_into_response_body() {
        let resp = FdxErrorResponse::conflict("dup").into_response();
        assert_eq!(resp.status(), StatusCode::CONFLICT);
    }

    #[test]
    fn test_unknown_code_defaults_400() {
        let (status, _) = error_code_mapping("SOMETHING_NEW");
        assert_eq!(status, 400);
    }

    #[test]
    fn test_convenience_constructors() {
        assert_eq!(FdxErrorResponse::unauthorized("x").status_code, 401);
        assert_eq!(FdxErrorResponse::forbidden("x").status_code, 403);
        assert_eq!(FdxErrorResponse::internal("x").status_code, 500);
    }

    #[test]
    fn test_serialize_excludes_none_details() {
        let e = FdxErrorResponse::bad_request("err");
        let json = serde_json::to_value(&e).unwrap();
        assert!(json.get("details").is_none());
    }
}

// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Bank8:FDX
// SPDX-License-Identifier: Apache-2.0

//! Story - FDX header handling.
//! Extracts FDX-specific headers (`x-fapi-interaction-id`,
//! `FDX-API-Actor-Type`, `Idempotency-Key`) and generates interaction IDs
//! for responses.

use axum::http::{HeaderMap, HeaderName, HeaderValue};

/// Standard FDX / FAPI header names.
pub const X_FAPI_INTERACTION_ID: HeaderName = HeaderName::from_static("x-fapi-interaction-id");
pub const BANK8_FDX_API_ACTOR_TYPE: HeaderName = HeaderName::from_static("fdx-api-actor-type");
pub const IDEMPOTENCY_KEY: HeaderName = HeaderName::from_static("idempotency-key");

/// Parsed FDX headers extracted from a request.
#[derive(Debug, Clone)]
pub struct FdxHeaders {
    pub interaction_id: Option<String>,
    pub actor_type: Option<String>,
    pub idempotency_key: Option<String>,
}

impl FdxHeaders {
    /// Returns the interaction ID or generates a new one if absent.
    pub fn interaction_id_or_new(&self) -> String {
        self.interaction_id
            .clone()
            .unwrap_or_else(generate_interaction_id)
    }
}

/// Extract FDX headers from an Axum `HeaderMap`.
pub fn extract_fdx_headers(headers: &HeaderMap) -> FdxHeaders {
    FdxHeaders {
        interaction_id: headers
            .get(&X_FAPI_INTERACTION_ID)
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string()),
        actor_type: headers
            .get(&BANK8_FDX_API_ACTOR_TYPE)
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string()),
        idempotency_key: headers
            .get(&IDEMPOTENCY_KEY)
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string()),
    }
}

/// Generate a new UUIDv4 interaction ID for `x-fapi-interaction-id`.
pub fn generate_interaction_id() -> String {
    uuid::Uuid::new_v4().to_string()
}

// ── : FDX party headers (§8) ────────────────────────────────────────

/// Extract the FDX-API-Client-Public-Key / Data-Provider-Id /
/// Data-Recipient-Id headers (§8) into an audit-friendly map. The client
/// public key drives JWS-in-JWE response encryption for sensitive fields
/// when present, handlers mark sensitive fields for envelope encryption;
/// this service records its presence in the audit event and returns it in
/// `x-fdx-client-key-alg` so the recipient can correlate.
pub fn fdx_party_headers(headers: &HeaderMap) -> serde_json::Value {
    let h = |name: &str| -> Option<String> {
        headers
            .get(name)
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string())
    };
    serde_json::json!({
        "client_public_key_present": h("FDX-API-Client-Public-Key").is_some(),
        "data_provider_id": h("FDX-API-Data-Provider-Id"),
        "data_recipient_id": h("FDX-API-Data-Recipient-Id"),
    })
}

/// Inject an interaction ID into the response headers.
/// If the request carried an `x-fapi-interaction-id`, it is echoed back;
/// otherwise a fresh one is generated.
pub fn inject_interaction_id(headers: &HeaderMap, resp_headers: &mut HeaderMap) {
    let id = extract_fdx_headers(headers).interaction_id_or_new();
    if let Ok(val) = HeaderValue::from_str(&id) {
        resp_headers.insert(&X_FAPI_INTERACTION_ID, val);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_headers(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut h = HeaderMap::new();
        for (k, v) in pairs {
            h.insert(
                HeaderName::from_bytes(k.as_bytes()).unwrap(),
                HeaderValue::from_str(v).unwrap(),
            );
        }
        h
    }

    #[test]
    fn test_extract_all_headers() {
        let h = make_headers(&[
            ("x-fapi-interaction-id", "abc-123"),
            ("fdx-api-actor-type", "customer"),
            ("idempotency-key", "key-001"),
        ]);
        let f = extract_fdx_headers(&h);
        assert_eq!(f.interaction_id.as_deref(), Some("abc-123"));
        assert_eq!(f.actor_type.as_deref(), Some("customer"));
        assert_eq!(f.idempotency_key.as_deref(), Some("key-001"));
    }

    #[test]
    fn test_extract_no_headers() {
        let h = HeaderMap::new();
        let f = extract_fdx_headers(&h);
        assert!(f.interaction_id.is_none());
        assert!(f.actor_type.is_none());
        assert!(f.idempotency_key.is_none());
    }

    #[test]
    fn test_interaction_id_or_new_when_present() {
        let f = FdxHeaders {
            interaction_id: Some("existing".into()),
            actor_type: None,
            idempotency_key: None,
        };
        assert_eq!(f.interaction_id_or_new(), "existing");
    }

    #[test]
    fn test_interaction_id_or_new_when_absent() {
        let f = FdxHeaders {
            interaction_id: None,
            actor_type: None,
            idempotency_key: None,
        };
        let id = f.interaction_id_or_new();
        assert!(uuid::Uuid::parse_str(&id).is_ok());
    }

    #[test]
    fn test_generate_interaction_id_is_uuid() {
        let id = generate_interaction_id();
        assert!(uuid::Uuid::parse_str(&id).is_ok());
    }

    #[test]
    fn test_generate_interaction_id_unique() {
        let a = generate_interaction_id();
        let b = generate_interaction_id();
        assert_ne!(a, b);
    }

    #[test]
    fn test_inject_interaction_id_echoes_request() {
        let req = make_headers(&[("x-fapi-interaction-id", "req-id-1")]);
        let mut resp = HeaderMap::new();
        inject_interaction_id(&req, &mut resp);
        assert_eq!(
            resp.get(&X_FAPI_INTERACTION_ID).unwrap().to_str().unwrap(),
            "req-id-1"
        );
    }

    #[test]
    fn test_inject_interaction_id_generates_when_absent() {
        let req = HeaderMap::new();
        let mut resp = HeaderMap::new();
        inject_interaction_id(&req, &mut resp);
        let val = resp.get(&X_FAPI_INTERACTION_ID).unwrap().to_str().unwrap();
        assert!(uuid::Uuid::parse_str(val).is_ok());
    }

    // ── : party headers ─────────────────────────────────────────────

    #[test]
    fn test_party_headers_detect_presence_and_ids() {
        let h = make_headers(&[
            ("FDX-API-Client-Public-Key", "jwk-blob"),
            ("FDX-API-Data-Provider-Id", "bank8"),
        ]);
        let m = fdx_party_headers(&h);
        assert_eq!(m["client_public_key_present"], true);
        assert_eq!(m["data_provider_id"], "bank8");
        assert_eq!(m["data_recipient_id"], serde_json::Value::Null);
    }

    #[test]
    fn test_party_headers_absent_when_empty() {
        let m = fdx_party_headers(&HeaderMap::new());
        assert_eq!(m["client_public_key_present"], false);
        assert_eq!(m["data_provider_id"], serde_json::Value::Null);
        assert_eq!(m["data_recipient_id"], serde_json::Value::Null);
    }
}

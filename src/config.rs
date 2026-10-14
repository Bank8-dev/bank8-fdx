// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Bank8:FDX
// SPDX-License-Identifier: Apache-2.0

//! FDX configuration.

use std::env;

use sentin8::auth::client::{Client as AuthClient, ClientOptions};

/// FDX configuration.
#[derive(Clone)]
pub struct Fdx8Config {
    pub port: u16,
    pub database_url: String,
    pub sentin8_auth_issuer: String,
    pub sentin8_auth_jwks_url: String,
    /// FDX's own external URL (e.g. https://bank8-fdx.ops.sys.sentin8.local) — used for
    /// consent authorize URLs that FDX serves itself.
    pub fdx_base_url: String,
    pub ledger_url: String,
    /// Certificate-presenting transport for the fdx→ledger proxy calls
    /// (workload `bank8-fdx-ledger`; CERTFREE-8V — no static token).
    pub ledger_http: Option<reqwest::Client>,
    pub payments_url: String,
    /// Certificate-presenting transport for the fdx→payments proxy calls
    /// (workload `bank8-fdx-payments`; CERTFREE-8V — no static token).
    pub payments_http: Option<reqwest::Client>,
    pub sentin8_bus_url: String,
    pub stream_family: String,
    /// Story — Stat config for FDX telemetry.
    pub sentin8_stat_url: String,
    pub sentin8_stat_property_id: uuid::Uuid,
    /// Story — Flow integration for consent workflows.
    pub sentin8_flow_url: String,
    pub sentin8_flow_token: String,
    /// Certificate-presenting transport for the service's own workload
    /// identity (CERTFREE-4V — no M2M token exists): the `fdx`
    /// certificate presents in the TLS handshake — the receiving
    /// service's TLS layer authenticates it and the enroll-published
    /// registry map authorizes the scopes.
    pub m2m_http: Option<reqwest::Client>,
    /// Shared Auth client — constructed once so the discovery and JWKS
    /// caches are reused across every request (5-minute TTL each).
    /// Cloning is cheap (the caches live behind an `Arc`).
    pub sentin8_auth_client: AuthClient,
}

/// Manual `Debug` — never logs the transport internals.
impl std::fmt::Debug for Fdx8Config {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Fdx8Config")
            .field("port", &self.port)
            .field("database_url", &"<redacted>")
            .field("sentin8_auth_issuer", &self.sentin8_auth_issuer)
            .field("stream_family", &self.stream_family)
            .field("m2m_http", &self.m2m_http.is_some())
            .finish_non_exhaustive()
    }
}

impl Fdx8Config {
    pub fn from_env() -> Self {
        let cfg = sentin8::config::Sentin8Config::from_env();
        Self {
            port: env::var("BANK8_FDX_PORT").expect("BANK8_FDX_PORT must be set by captain").parse().expect("BANK8_FDX_PORT must be a valid u16"),
            database_url: env::var("BANK8_FDX_DATABASE_URL").unwrap_or_else(|_| env::var("DATABASE_URL").unwrap_or_else(|_| sentin8::config::Sentin8Config::default_database_url().to_string())),
            sentin8_auth_issuer: env::var("SENTIN8_AUTH_ISSUER").unwrap_or_else(|_| cfg.sentin8_auth_issuer()),
            sentin8_auth_jwks_url: env::var("SENTIN8_AUTH_JWKS_URL").unwrap_or_else(|_| cfg.sentin8_auth_jwks_url()),
            fdx_base_url: env::var("BANK8_FDX_BASE_URL").unwrap_or_else(|_| format!("https://{}", cfg.platform_domain("bank8:fdx"))),
            ledger_url: env::var("BANK8_LEDGER_URL").unwrap_or_else(|_| format!("https://{}", cfg.platform_domain("bank8:ledger"))),
            ledger_http: None,
            payments_url: env::var("BANK8_PAYMENTS_URL").unwrap_or_else(|_| format!("https://{}", cfg.platform_domain("bank8:payments"))),
            payments_http: None,
            sentin8_bus_url: env::var("SENTIN8_BUS_URL").unwrap_or_else(|_| cfg.sentin8_bus_url()),
            stream_family: env::var("BANK8_FDX_STREAM_FAMILY").unwrap_or_else(|_| "fdx".into()),
            sentin8_stat_url: env::var("SENTIN8_STAT_URL").unwrap_or_else(|_| cfg.sentin8_stat_url()),
            sentin8_stat_property_id: env::var("BANK8_FDX_STAT_PROPERTY_ID")
                .ok()
                .and_then(|s| uuid::Uuid::parse_str(&s).ok())
                .unwrap_or_else(|| uuid::Uuid::parse_str("a0000000-0000-0000-0000-000000000005").unwrap()),
            sentin8_flow_url: env::var("SENTIN8_FLOW_URL").unwrap_or_else(|_| cfg.sentin8_flow_url()),
            sentin8_flow_token: env::var("SENTIN8_FLOW_TOKEN").unwrap_or_else(|_| "fdx-dev".into()),
            m2m_http: None,
            sentin8_auth_client: AuthClient::new(ClientOptions {
                base_url: env::var("SENTIN8_AUTH_ISSUER").unwrap_or_else(|_| cfg.sentin8_auth_issuer()),
                ..Default::default()
            }),
        }
    }

    /// Certificate-presenting transport for the service's own `fdx`
    /// workload (CERTFREE-4V — no M2M token exists). Set at startup by
    /// `server::build_state` (the Flow step-handler registration rides
    /// it — Flow's certificate-first gate resolves the `fdx` workload);
    /// `None` until then (the registration keeps the static dev token).
    pub fn m2m_http(&self) -> Option<&reqwest::Client> {
        self.m2m_http.as_ref()
    }

    /// Certificate-presenting transport for the fdx→ledger proxy
    /// (workload `bank8-fdx-ledger`; CERTFREE-8V). `None` until the
    /// boot mint succeeds — the proxy lanes 503 loudly rather than
    /// degrading to an unauthenticated call.
    pub fn ledger_http(&self) -> Option<&reqwest::Client> {
        self.ledger_http.as_ref()
    }

    /// Certificate-presenting transport for the fdx→payments proxy
    /// (workload `bank8-fdx-payments`; CERTFREE-8V).
    pub fn payments_http(&self) -> Option<&reqwest::Client> {
        self.payments_http.as_ref()
    }
}
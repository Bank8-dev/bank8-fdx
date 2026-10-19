// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Bank8:FDX
// SPDX-License-Identifier: Apache-2.0

//! Auth token verification for Fdx8.
//! Re-exports the shared types from the sentin8-auth-client SDK and provides
//! thin wrappers matching the original Fdx8 call sites (taking `&Fdx8Config` + `&HeaderMap`).
//!  : step 5 is the ONLY gate (policy design §4.3). The
//! `require_any_scope` helper is gone - handlers verify the token
//! (steps 1-4) with [`verify_token`], then evaluate a
//! `bank8:fdx:<resource>:<action>` Shield action via `crate::policy::require`.
//! The consent-binding rule (holder relation on the consent object) is
//! authored as a tenant Shield set over the ReBAC substrate - never a
//! handler scope check.

use axum::http::{HeaderMap, StatusCode};

use crate::config::Fdx8Config;

pub use sentin8::auth::client::AuthContext;

/// Verify the Bearer token and return the auth context (steps 1-4: identity
/// + signature + expiry + tenant). NO scope check - step 5
///
/// (`crate::policy::require`) is the authorization decision.
pub async fn verify_token(
    config: &Fdx8Config,
    headers: &HeaderMap,
) -> Result<AuthContext, (StatusCode, String)> {
    sentin8::auth::client::verify_bearer_token(&config.sentin8_auth_client, headers).await
}

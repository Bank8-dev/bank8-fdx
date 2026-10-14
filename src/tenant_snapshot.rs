// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Bank8:FDX
// SPDX-License-Identifier: Apache-2.0

//! Sys tenant-snapshot client for fdx (VDC §VDC.5).
//!
//! The FDX provider-catalog URL derivation needs the provider env's
//! slug + org domain. The former cross-database `sentin8.sys_environments`
//! joins never existed in the vertical's own database (VDC-2) and always
//! returned empty. The sanctioned on-demand read is Sys's tenant-snapshot
//! API (`GET /v1/tenants/{env_id}`) via the cert-presenting
//! `bank8-fdx-sys` workload (CERTFREE-4V — no M2M token; the scope
//! `sentin8:sys:tenants:read` rides the enroll-published registry map).
//! Same pattern as the ledger's `tenant_snapshot` module and the event
//! consumer's `fetch_tenant_snapshot` (peers cannot share a crate).

/// The env identity fields URL derivation needs (Sys
/// `GET /v1/tenants/{env_id}` response). `Ok(None)` = 404 — the caller
/// derives nothing (fail-closed); `Err` = transport/5xx — also fail-closed.
pub async fn env_identity(
    env_id: uuid::Uuid,
) -> Result<Option<(String, String)>, String> {
    let cfg = sentin8::config::Sentin8Config::from_env();
    let ca_path = sentin8::auth::m2m::platform_ca_path();
    let cert = sentin8::auth::m2m::ensure_workload_certificate(
        &cfg.sentin8_auth_issuer(),
        "bank8-fdx-sys",
        &ca_path,
    )
    .await
    .map_err(|e| format!("workload certificate: {e}"))?;
    let mtls = sentin8::middleware::mtls::MtlsConfig::new(
        &cert.ca_cert_path,
        &cert.cert_path,
        &cert.key_path,
    );
    let http = sentin8::middleware::mtls::build_mtls_client(&mtls)
        .map_err(|e| format!("transport: {e}"))?;
    let url = format!("{}/v1/tenants/{}", cfg.sentin8_sys_url().trim_end_matches('/'), env_id);
    let resp = http
        .get(&url)
        .send()
        .await
        .map_err(|e| format!("sys snapshot fetch: {e}"))?;
    let status = resp.status();
    if status == reqwest::StatusCode::NOT_FOUND {
        return Ok(None);
    }
    if !status.is_success() {
        return Err(format!("sys snapshot: {status}"));
    }
    let data: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| format!("sys snapshot decode: {e}"))?;
    let env_slug = data["env_slug"].as_str().unwrap_or("").to_string();
    let org_domain = data["org_domain"].as_str().unwrap_or("").to_string();
    Ok(Some((env_slug, org_domain)))
}
// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Bank8:FDX
// SPDX-License-Identifier: Apache-2.0

//! Axum server setup for FDX.

use std::sync::Arc;
use axum::routing::{get, post};
use crate::handlers::{self, AppState};

/// Build a cert-presenting HTTP transport for `workload` (CERTFREE-4V,
/// auth DESIGN §4.3f): mint-or-load the Acme-issued pair and wrap it in
/// a reqwest client. The receiving service's TLS layer authenticates the
/// handshake and the enroll-published registry map authorizes the
/// scopes — no bearer token exists on this path.
///
/// # Errors
/// Returns the certificate-ensure or transport-build failure (the
/// caller logs and degrades).
async fn build_workload_http(
    auth_issuer: &str,
    workload: &str,
) -> anyhow::Result<reqwest::Client> {
    let cert = sentin8::auth::m2m::ensure_workload_certificate(
        auth_issuer,
        workload,
        &sentin8::auth::m2m::platform_ca_path(),
    )
    .await?;
    let mtls = sentin8::middleware::mtls::MtlsConfig::new(
        &cert.ca_cert_path,
        &cert.cert_path,
        &cert.key_path,
    );
    sentin8::middleware::mtls::build_mtls_client(&mtls)
        .map_err(|e| anyhow::anyhow!("workload '{workload}' transport: {e}"))
}

pub async fn build_state(core: sentin8::shell::ServiceCore)
    -> anyhow::Result<crate::handlers::AppState> {
    let mut config = crate::config::Fdx8Config::from_env();

    // The service's own workload transport (CERTFREE-4V): the
    // `fdx` certificate presents in the TLS handshake — the
    // receiving service's TLS layer authenticates it and the registry
    // map authorizes the scopes. Non-fatal on failure — the Flow
    // registration keeps the static dev token until the next boot.
    match build_workload_http(&config.sentin8_auth_issuer, "fdx").await {
        Ok(http) => config.m2m_http = Some(http),
        Err(e) => tracing::warn!(error = %e, "fdx workload transport unavailable — Flow registration degraded"),
    }

    // CERTFREE-8V: the proxy lanes' cross-service workloads — the fdx→
    // ledger reads and fdx→payments transfers/payments present their own
    // certificates (the static BANK8_*_TOKEN dev convention is retired;
    // the receiving gates resolve the workloads against the registry
    // map). None → the proxy lanes 503 loudly at the handler gate.
    match build_workload_http(&config.sentin8_auth_issuer, "bank8-fdx-ledger").await {
        Ok(http) => config.ledger_http = Some(http),
        Err(e) => tracing::warn!(error = %e, "fdx ledger proxy transport unavailable — account/balance/transaction reads degraded"),
    }
    match build_workload_http(&config.sentin8_auth_issuer, "bank8-fdx-payments").await {
        Ok(http) => config.payments_http = Some(http),
        Err(e) => tracing::warn!(error = %e, "fdx payments proxy transport unavailable — transfers/payments degraded"),
    }
    // ── Sentin8:Policy ──────────────────────────────
    // Load the service's policy sets; an unparsable policy text REFUSES TO
    // START (fail-closed at boot, design §3.3). Hot-reload consumes the
    // `policy` stream as a direct consumer (design §3.2); deny/would-deny
    // decisions emit to Stat (§4.2f). The engine is stored in AppState so
    // handlers gate via `policy::require` (step 5 is the ONLY gate).
    // ── Sentin8:Policy (§4.2b — shell-owned boot): consume the
    // engine the shell booted in step 8 — no second engine, consumer, or
    // DCR registration here.
    let policy_engine = core.admin.policy.clone();

    let state = AppState {
        config: Arc::new(config),
        pool: core.pool.clone(),
        policy: policy_engine.clone(),
        cert_metrics_cache: handlers::CertMetricsCache::default(),
        admin: sentin8::shield::admin::SharedAdminState {
            service: "bank8:fdx".to_string(),
            pool: core.pool.clone(),
            policy: policy_engine,
            auth_client: Arc::new(core.config.sentin8_auth_client.clone()),
        },
    };

    // Register FDX step handler profile with Flow (best-effort). The
    // registration rides the cert-presenting `fdx` transport when boot
    // minted it (Flow's certificate-first gate resolves the `fdx` workload
    // and its `sentin8:flow:write` scope); a missing transport degrades
    // to the static dev token path (design §2 — Flow registration
    // contract). The body's `auth_token` is the proxy-back callback
    // credential — the static dev token, inert on the cert path.
    let cfg = state.config.clone();
    let self_url = format!("http://0.0.0.0:{}", cfg.port);
    let flow_token = cfg.sentin8_flow_token.clone();
    let flow_http = cfg.m2m_http().cloned();
    match crate::flow::register_with_flow(&cfg.sentin8_flow_url, &flow_token, &self_url, &flow_token, flow_http).await {
        Ok(()) => {}
        Err(e) => tracing::warn!(error = %e, "failed to register FDX step handler profile with Flow"),
    }
    // Cert-presenting Bus client (CERTFREE-4V): the `fdx` workload
    // CERTIFICATE is the identity — no DCR, no token (auth DESIGN
    // §4.3f); the mint retries while the fleet boots.
    let bus_client = loop {
        match sentin8::bus::client::BusClient::for_workload(
            &cfg.sentin8_bus_url,
            &cfg.sentin8_auth_issuer,
            "fdx",
        )
        .await
        {
            Ok(c) => break c,
            Err(e) => {
                tracing::debug!(error = %e, "fdx bus client: certificate not ready yet");
                tokio::time::sleep(std::time::Duration::from_secs(2)).await;
            }
        }
    };
    // Spawn the notification delivery worker: delivers pending
    // notifications to subscription callback URLs, HMAC-signed with the
    // per-subscription secret (design §5.1a — Auth webhook signature scheme).
    crate::event_notifications::spawn_notification_delivery(state.clone());

    // Spawn the Sentin8:Bus consumer for event-driven FDX provider registration.
    // Subscribes to the `sys` stream family and reacts to `sentin8:sys.service.updated`
    // when `fdx` is enabled, auto-registering an FDX provider profile.
    crate::event_consumer::spawn(core.pool.clone(), bus_client);

    Ok(state)
}

/// Add this service's routes onto the shell-provided router. The shell
/// owns the boot sequence, state binding, OpenAPI merge and the standard
/// middleware stack; this adds ONLY routes (including the service's own
/// `/v1/health` — custom payload).
/// The `/fdx/v6/*` provider routes are mounted on their own sub-router with
/// the provider middleware (contract validation, x-fapi-interaction-id,
/// audit) as a route layer — non-provider routes bypass it.
pub fn routes(router: axum::Router<crate::handlers::AppState>, state: crate::handlers::AppState)
    -> axum::Router<crate::handlers::AppState> {
    use axum::routing::{delete, put};
    let provider = axum::Router::new()
        .route("/fdx/v6/accounts", get(handlers::get_accounts))
        .route("/fdx/v6/accounts/{id}", get(handlers::get_account_detail))
        .route("/fdx/v6/accounts/{id}/transactions", get(handlers::get_account_transactions))
        .route("/fdx/v6/accounts/{id}/statements", get(handlers::list_account_statements))
        .route("/fdx/v6/accounts/{id}/payment-networks", get(handlers::get_payment_networks))
        .route("/fdx/v6/customers", get(handlers::list_customers))
        .route("/fdx/v6/customers/current", get(handlers::get_current_customer))
        .route("/fdx/v6/consents/{id}", get(handlers::get_fdx_consent))

        .route("/fdx/v6/transfers", post(handlers::create_transfer))
        .route("/fdx/v6/payments", post(handlers::create_payment))
        .route("/fdx/v6/capability", get(handlers::get_capability))
        .route("/fdx/v6/availability", get(handlers::get_availability))
        .route("/fdx/v6/certification-metrics", get(handlers::get_certification_metrics))
        // ── FDX v6.5 API completion handlers (..15, design §5.1) ────
        // : statement download (302 to the Storage signed URL).
        .route("/fdx/v6/accounts/{id}/statements/{statementId}", get(crate::statement_download::download_statement))
        // : money-movement reads + cancel + payees proxy.
        .route("/fdx/v6/payments/{paymentId}", get(crate::money_movement::get_payment))
        .route("/fdx/v6/transfers/{transferId}", get(crate::money_movement::get_transfer).patch(crate::money_movement::update_transfer).delete(crate::money_movement::cancel_transfer))
        .route("/fdx/v6/payees", get(crate::money_movement::list_payees).post(crate::money_movement::create_payee))
        .route("/fdx/v6/payees/{payeeId}", put(crate::money_movement::update_payee))
        // : payment-initiation parties + recurring payments.
        .route("/fdx/v6/payment-initiation-parties", post(crate::pip::create_pip_party))
        .route("/fdx/v6/payment-initiation-parties/{partyId}", get(crate::pip::get_pip_party))
        .route("/fdx/v6/payment-initiation-parties/{partyId}/payment-methods", post(crate::pip::create_pip_payment_method))
        .route("/fdx/v6/payment-initiation-parties/{partyId}/payment-methods/{regId}", delete(crate::pip::revoke_pip_payment_method))
        .route("/fdx/v6/recurring-payments", post(crate::recurring::create_recurring_payment).get(crate::recurring::list_recurring_payments))
        .route("/fdx/v6/recurring-payments/{recurringPaymentId}", get(crate::recurring::get_recurring_payment))
        .route("/fdx/v6/recurring-payments/{recurringPaymentId}/payments", get(crate::recurring::list_recurring_payment_occurrences))
        // : payment network detail + revocation.
        .route("/fdx/v6/accounts/{id}/payment-networks/{paymentNetworkId}", get(crate::payment_networks::get_payment_network))
        .route("/fdx/v6/accounts/{id}/payment-networks/{paymentNetworkId}/revocation", put(crate::payment_networks::revoke_payment_network).get(crate::payment_networks::get_payment_network_revocations))
        // /: notification subscriptions + feed.
        .route("/fdx/v6/notification-subscriptions", post(crate::event_notifications::create_notification_subscription).get(crate::event_notifications::list_notification_subscriptions))
        .route("/fdx/v6/notification-subscriptions/{subscriptionId}", get(crate::event_notifications::get_notification_subscription).delete(crate::event_notifications::delete_notification_subscription))
        .route("/fdx/v6/notifications", post(crate::event_notifications::publish_notification).get(crate::event_notifications::list_notifications_feed))
        // : revocation record (GET; PUT with body replaces the legacy
        // no-body revoke route above — both wired, the body-bearing one wins).
        .route("/fdx/v6/consents/{id}/revocation", put(crate::consent_records::revoke_consent_with_record).get(crate::consent_records::get_consent_revocation))
        // : revocation by the delegated subject (the recipient plane calls
        // this with the delegated provider token after revoking its
        // registry row — fdx DESIGN.md §4; POST alias of the PUT
        // revocation surface above for the RFW renderer + external
        // recipient clients).
        .route("/fdx/v6/consents/{id}/revoke", post(crate::consent_records::revoke_consent_with_record))
        // : consent lifecycle.
        .route("/fdx/v6/consents/{id}/lifecycle", put(crate::consent_records::update_consent_lifecycle))
        // : explicit operation-support statement.
        .route("/fdx/v6/operation-support", get(crate::operations::get_operation_support))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            crate::middleware::provider_middleware,
        ))
        .with_state(state);
    router
        .route("/v1/health", get(handlers::health))
        .merge(provider)
        // Consent service
        .route("/v1/consents", post(handlers::create_consent).get(handlers::list_consents))
        .route("/v1/consents/{id}", get(handlers::get_consent))
        .route("/v1/consents/{id}/revoke", post(handlers::revoke_consent))
        // Recipient API
        .route("/v1/recipient/providers", get(handlers::list_recipient_providers))
        .route("/v1/recipient/providers/{id}", get(handlers::get_recipient_provider))
        .route("/v1/recipient/consents/start", post(handlers::start_consent))
        .route("/fdx/consents/callback", get(handlers::consent_callback))
        .route("/v1/recipient/consents", get(handlers::list_recipient_consents))
        .route("/v1/recipient/consents/{id}", get(handlers::get_recipient_consent))
        .route("/v1/recipient/consents/{id}/refresh", post(handlers::refresh_consent))
        .route("/v1/recipient/consents/{id}/revoke", post(handlers::revoke_recipient_consent))
        .route("/v1/recipient/accounts", get(handlers::list_recipient_accounts))
        .route("/v1/recipient/accounts/{id}/transactions", get(handlers::get_recipient_account_transactions))
        .route("/v1/recipient/notifications", get(handlers::list_notifications))
        // Admin API
        .route("/v1/admin/provider-profile", get(handlers::get_provider_profile).put(handlers::update_provider_profile))
        .route("/v1/admin/recipients", get(handlers::list_recipients))
        .route("/v1/admin/recipients/{id}/activate", post(handlers::activate_recipient))
        .route("/v1/admin/recipients/{id}/suspend", post(handlers::suspend_recipient))
        .route("/v1/admin/consents", get(handlers::list_all_consents))
        .route("/v1/admin/audit", get(handlers::list_admin_audit))
        // ── Admin UI (RFW) ─────────────────────────────────────────────────
        .route("/v1/admin/ui/{*page}", get(crate::admin_ui::get_admin_ui))
        // ── Consent RFW endpoints (§4.16, proxied by Sentin8:Auth) ─────────
        .route("/v1/auth/consent/ui", get(crate::consent_rfw::auth_consent_ui))
        .route("/v1/auth/consent/accounts", get(crate::consent_rfw::auth_consent_accounts))
        .route("/v1/auth/consent/approve", post(crate::consent_rfw::auth_consent_approve))
        .route("/v1/auth/consent/deny", post(crate::consent_rfw::auth_consent_deny))
        // Flow proxy-back
        .route("/v1/internal/steps/execute", post(handlers::execute_step))
        // ── Sentin8:Policy admin API (§3.6 — shared
        // implementation; handlers generic over this AppState).
        .route("/v1/admin/policy-sets",
            get(sentin8::shield::admin::list_policy_sets::<handlers::AppState>))
        .route("/v1/admin/policy-sets/{name}",
            get(sentin8::shield::admin::get_policy_set::<handlers::AppState>)
                .put(sentin8::shield::admin::put_policy_set::<handlers::AppState>)
                .delete(sentin8::shield::admin::delete_policy_set::<handlers::AppState>))
        .route("/v1/admin/policy-sets/{name}/test",
            post(sentin8::shield::admin::test_policy_set::<handlers::AppState>))
        .route("/v1/admin/policy-sets/enforce",
            post(sentin8::shield::admin::admin_enforce_policy_set::<handlers::AppState>))
        .route("/v1/admin/policy-sets/shadow",
            post(sentin8::shield::admin::admin_shadow_policy_set::<handlers::AppState>))
        .route("/v1/admin/policy-sets/disable",
            post(sentin8::shield::admin::admin_disable_policy_set::<handlers::AppState>))
        .route("/v1/admin/relations",
            get(sentin8::shield::admin::list_relations::<handlers::AppState>)
                .put(sentin8::shield::admin::put_relation::<handlers::AppState>)
                .delete(sentin8::shield::admin::delete_relation::<handlers::AppState>))
        .route("/v1/admin/relations/check",
            get(sentin8::shield::admin::check_relation::<handlers::AppState>))
        .route("/v1/admin/attributes",
            get(sentin8::shield::admin::list_attributes::<handlers::AppState>)
                .put(sentin8::shield::admin::put_attribute::<handlers::AppState>)
                .delete(sentin8::shield::admin::delete_attribute::<handlers::AppState>))
}

/// Shared policy-admin surface accessor (§3.6) — the shared
/// handlers extract this service's admin state via [`HasPolicyAdmin`].
impl sentin8::shield::admin::HasPolicyAdmin for handlers::AppState {
    fn policy_admin(&self) -> &sentin8::shield::admin::SharedAdminState {
        &self.admin
    }
}

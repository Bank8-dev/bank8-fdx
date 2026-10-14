// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Bank8:FDX
// SPDX-License-Identifier: Apache-2.0

//! Sentin8:Bus consumers (fdx DESIGN.md §2) — two stream families:
//!
//! * `sys` — `sentin8:sys:service:updated` events: when the `fdx` service
//!   is enabled for an org/env, the consumer auto-registers an FDX
//!   provider profile in `provider_profiles` (the recipient-side catalog)
//!   so the org appears as a connectable provider. The provider profile
//!   uses the env's auth domain as the issuer URL.
//! * `auth` — `sentin8:auth:grant:created` events: the provider-side
//!   GRANT SEED (two-ledger model, DESIGN.md §1). The authorization
//!   server is the seed of open-banking grant truth: when a customer
//!   grants a consent at the AS, the provider-side fdx instance records
//!   the grant in its OWN tenant — consent handle parsed from the OAuth
//!   `state`, the provider-customer subject from the event's `user_id`,
//!   the selected accounts as `consent_resources`. The recipient NEVER
//!   writes into the provider.
//!
//! Uses the same SSE pattern as `bank8-ledger/src/handlers/event_consumer.rs`.
//! Design: `services/fdx/DESIGN.md`

use std::time::Duration;

use futures_util::StreamExt;
use sqlx::PgPool;

/// Consumer group name (sys family) — identifies this FDX instance to Sentin8:Bus.
const CONSUMER_GROUP: &str = "bank8:fdx:envinit";
/// Consumer group name (auth family) — the provider grant-seed group.
const AUTH_CONSUMER_GROUP: &str = "bank8:fdx:grantseed";

/// Reconnect delay when the Bus SSE connection drops or an error occurs.
const RECONNECT_DELAY: Duration = Duration::from_secs(2);

/// Spawn the Bus consumer background tasks. Called once from `server::serve`.
pub fn spawn(
    pool: PgPool,
    bus_client: sentin8::bus::client::BusClient,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        // Two families, one task: the SSE loops are sequential within the
        // task but independent streams at the bus — each connect/ack is
        // family-scoped. A drop on one family never stalls the other.
        tokio::select! {
            _ = run_envinit(pool.clone(), bus_client.clone()) => {},
            _ = run_grantseed(pool, bus_client) => {},
        }
    })
}

/// Run the sys-family consumer loop: env-init events.
async fn run_envinit(pool: PgPool, bus_client: sentin8::bus::client::BusClient) {
    tracing::info!("fdx: bus env-init consumer started (consumer_group={CONSUMER_GROUP})");

    // Startup backfill: ensure provider profiles exist for all orgs/envs
    // where the `fdx` service is already enabled. This catches events that
    // were emitted before this consumer started (e.g. after a redeploy).
    backfill_enabled_envs(&pool).await;

    loop {
        match bus_client.sse_consume("sys", CONSUMER_GROUP).await {
            Ok(resp) => {
                tracing::info!("fdx: bus SSE connected to stream family 'sys'");
                sse_loop("sys", CONSUMER_GROUP, &pool, &bus_client, resp).await;
                tracing::info!("fdx: bus SSE disconnected — reconnecting");
            }
            Err(e) => {
                tracing::warn!(error = %e, "fdx: bus SSE consume failed — reconnecting");
            }
        }
        tokio::time::sleep(RECONNECT_DELAY).await;
    }
}

/// Run the auth-family consumer loop: the provider grant seed.
async fn run_grantseed(pool: PgPool, bus_client: sentin8::bus::client::BusClient) {
    tracing::info!("fdx: bus grant-seed consumer started (consumer_group={AUTH_CONSUMER_GROUP})");
    loop {
        match bus_client.sse_consume("auth", AUTH_CONSUMER_GROUP).await {
            Ok(resp) => {
                tracing::info!("fdx: bus SSE connected to stream family 'auth'");
                sse_loop("auth", AUTH_CONSUMER_GROUP, &pool, &bus_client, resp).await;
                tracing::info!("fdx: bus SSE disconnected (auth) — reconnecting");
            }
            Err(e) => {
                tracing::warn!(error = %e, "fdx: bus SSE consume failed (auth) — reconnecting");
            }
        }
        tokio::time::sleep(RECONNECT_DELAY).await;
    }
}

/// Process messages from a single Bus SSE connection until it drops.
/// `handle` is the family-specific dispatcher (ACK after every processed
/// message — the BUSACK-1 contract).
async fn sse_loop(
    family: &'static str,
    group: &'static str,
    pool: &PgPool,
    bus_client: &sentin8::bus::client::BusClient,
    resp: reqwest::Response,
) {
    let mut stream = resp.bytes_stream();
    let mut buffer = String::new();

    while let Some(chunk_result) = stream.next().await {
        let chunk = match chunk_result {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!(error = %e, "fdx: bus SSE stream error");
                return;
            }
        };

        buffer.push_str(&String::from_utf8_lossy(&chunk));

        while let Some(blank_pos) = buffer.find("\n\n") {
            let event_str = buffer[..blank_pos].to_string();
            buffer = buffer[blank_pos + 2..].to_string();

            let data_line = event_str
                .lines()
                .filter_map(|l| l.strip_prefix("data:").map(|s| s.trim_start()))
                .collect::<Vec<_>>()
                .join("");
            if data_line.is_empty() {
                continue;
            }

            let msg: sentin8::bus::contracts::Message = match serde_json::from_str(&data_line) {
                Ok(m) => m,
                Err(e) => {
                    tracing::warn!(error = %e, "fdx: failed to parse SSE message");
                    continue;
                }
            };

            // Family dispatch: sys → env-init, auth → grant seed
            // (fdx DESIGN.md §2 — two families, one loop shape).
            match family {
                "sys" => handle_envinit_message(pool, &msg).await,
                "auth" => handle_grant_message(pool, &msg).await,
                _ => {}
            }

            if let Err(e) = bus_client.ack(family, group, &msg.message_id).await {
                tracing::warn!(error = %e, message_id = %msg.message_id, "fdx: ack failed");
            }
        }
    }
}

/// Startup backfill: catch events emitted before this consumer started
/// (e.g. after a redeploy). VDC-9 (design/sentin8-vertical-data-plane-
/// contract.md §VDC.5/§VDC.8): the former cross-database scan of the
/// platform `sys_services` table never worked (those tables do not exist in
/// the bank8 database) — the sanctioned discovery surface is the snapshot
/// consumer loop itself: the platform re-emits nothing, so a redeployed
/// consumer re-derives profiles for envs already known LOCALLY (the
/// `provider_profiles` rows) and relies on `sentin8:sys:service:updated`
/// events for newly enabled envs. Idempotent per env.
async fn backfill_enabled_envs(pool: &PgPool) {
    let rows: Vec<(uuid::Uuid,)> = match sqlx::query_as(
        r#"SELECT DISTINCT env_id FROM provider_profiles"#,
    )
    .fetch_all(pool)
    .await
    {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(error = %e, "fdx: backfill query failed");
            return;
        }
    };

    tracing::info!("fdx: backfill — {} known env(s) re-verified", rows.len());

    for (env_id,) in rows {
        ensure_provider_profile(pool, env_id).await;
    }
}

/// Ensure a provider profile exists for the given env. Idempotent.
///
/// VDC-9 (design/sentin8-vertical-data-plane-contract.md §VDC.5): the
/// tenant identity snapshot (env slug, org domain, org display name,
/// auth domain) is obtained from Sys's tenant-snapshot API
/// (`GET /v1/tenants/{env_id}`, M2M `sentin8:sys:tenants:read`) — the
/// sanctioned on-demand read. The former cross-database join against the
/// platform `sys_environments`/`sys_organizations` never worked (those
/// tables do not exist in the bank8 database) and is removed.
async fn ensure_provider_profile(pool: &PgPool, env_id: uuid::Uuid) {
    // Fetch the tenant snapshot from the platform (Sys tenant-snapshot
    // API). A transient outage returns early — the next env-init or
    // backfill pass retries (both are idempotent).
    let snapshot = match fetch_tenant_snapshot(env_id).await {
        Ok(Some(s)) => s,
        Ok(None) => {
            tracing::warn!(%env_id, "fdx: env not found for provider profile");
            return;
        }
        Err(e) => {
            tracing::warn!(error = %e, %env_id, "fdx: tenant snapshot fetch failed");
            return;
        }
    };

    let env_slug: String = snapshot.env_slug.clone();
    let org_domain: String = snapshot.org_domain.clone();
    let org_name: String = snapshot.org_display_name.clone();

    if org_domain.is_empty() {
        tracing::warn!(%env_id, "fdx: no org_domain — skipping provider profile");
        return;
    }

    // Derive the auth hostname centrally via sentin8::config. The snapshot's
    // `auth_domain` (the platform's per-env auth server hostname) wins when
    // present; otherwise the standard env-domain derivation applies.
    let cfg = sentin8::config::Sentin8Config::from_env();
    let env_domain = cfg.env_domain(&env_slug, &org_domain);
    let auth_host = snapshot
        .auth_domain
        .clone()
        .unwrap_or_else(|| cfg.env_auth_domain(&env_domain));
    let auth_base = format!("https://{auth_host}");
    let issuer_url = auth_base.trim_end_matches('/').to_string();
    let jwks_url = format!("{}/.well-known/jwks.json", auth_base.trim_end_matches('/'));

    tracing::info!(
        env_id = %snapshot.env_id,
        env_slug = %env_slug,
        org_slug = %snapshot.org_slug,
        "fdx: provider profile derivation (tenant snapshot)"
    );

    // Insert the provider profile (idempotent upsert on env_id+provider_name).
    // FORCE-RLS: the insert must carry the env context on the SAME
    // connection (rule 2) — a bare-pool insert is rejected by
    // `WITH CHECK (env_id = sentin8_current_env_id())`.
    let mut tx = match pool.begin().await {
        Ok(t) => t,
        Err(e) => {
            tracing::warn!(error = %e, %env_id, "fdx: provider-profile tx begin failed");
            return;
        }
    };
    let _ = sqlx::query("SELECT sentin8_set_tenant_context($1, '', 'm2m', 'sys:admin')")
        .bind(env_id)
        .execute(&mut *tx)
        .await;
    if let Err(e) = sqlx::query(
        r#"INSERT INTO provider_profiles
           (env_id, provider_name, issuer_url, jwks_url, fdx_version, capabilities, status)
           VALUES ($1, $2, $3, $4, 'v6.5', '["accounts","transactions","payments"]'::jsonb, 'active')
           ON CONFLICT (env_id, provider_name)
           DO UPDATE SET status = 'active', issuer_url = EXCLUDED.issuer_url, jwks_url = EXCLUDED.jwks_url"#,
    )
    .bind(env_id)
    .bind(&org_name)
    .bind(&issuer_url)
    .bind(&jwks_url)
    .execute(&mut *tx)
    .await
    {
        tracing::warn!(error = %e, %env_id, "fdx: provider-profile insert failed");
        let _ = tx.rollback().await;
        return;
    }
    let _ = tx.commit().await;
    tracing::info!(%env_id, %org_name, "fdx: provider profile registered");
}

/// Provider grant-seed dispatcher (auth family, DESIGN.md §1): consume
/// `sentin8:auth:grant:created` and record the grant in the provider's OWN
/// tenant. Payload-complete envelope from Sentin8:Auth (auth DESIGN §4):
/// `{grant_id, client_id, user_id, env_id, scope, state,
/// selected_account_ids}`. The `state` is the recipient's opaque OAuth
/// state — for Bank8:FDX consents it is `"<consent handle>|<app origin>"`
/// (packed at PAR time by the recipient's consent start); only the handle
/// segment identifies the flow.
/// Non-FDX grants (any other client's `state`) are seeded as plain grant
/// rows keyed by the AS's own grant identity — the ledger records every
/// authorization the AS reports for this env, so consent filtering stays
/// complete regardless of which client ran the ceremony.
async fn handle_grant_message(pool: &PgPool, msg: &sentin8::bus::contracts::Message) {
    if msg.event_type != "sentin8:auth:grant:created" {
        return;
    }

    // VDC-2 consumer-side defense-in-depth: the event's first colon
    // segment must match the recorded producer vertical (`sentin8`).
    if let Err(reason) = sentin8::bus::client::BusClient::require_publisher(msg) {
        tracing::warn!(reason = %reason, "fdx: untrusted publisher — skipping grant seed");
        return;
    }

    let p = &msg.payload;
    let env_id = match p.get("env_id").and_then(|v| v.as_str()).and_then(|s| uuid::Uuid::parse_str(s).ok()) {
        Some(id) => id,
        None => {
            tracing::warn!("fdx: grant:created without env_id — skipping");
            return;
        }
    };
    let user_id = match p.get("user_id").and_then(|v| v.as_str()).and_then(|s| uuid::Uuid::parse_str(s).ok()) {
        Some(id) => id,
        None => {
            tracing::warn!("fdx: grant:created without user_id — skipping");
            return;
        }
    };
    let client_id: String = p.get("client_id").and_then(|v| v.as_str()).unwrap_or_default().to_string();
    let grant_id: Option<String> = p.get("grant_id").and_then(|v| v.as_str()).map(|s| s.to_string());
    let scope: String = p.get("scope").and_then(|v| v.as_str()).unwrap_or_default().to_string();
    // The OAuth `state` carries the recipient's flow handle (the
    // "handle|app_origin" form packed at PAR time by the recipient-side
    // consent start). Only the handle segment is recorded.
    let state: String = p.get("state").and_then(|v| v.as_str()).unwrap_or_default().to_string();
    let handle: Option<uuid::Uuid> = state
        .split('|')
        .next()
        .and_then(|s| uuid::Uuid::parse_str(s).ok());
    let selected: Vec<String> = p
        .get("selected_account_ids")
        .and_then(|v| v.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect()
        })
        .unwrap_or_default();
    let scopes: Vec<String> = scope.split_whitespace().map(|s| s.to_string()).collect();

    // Same-transaction discipline (DESIGN.md §5): context + INSERT on one
    // connection — the grant row is written under the PROVIDER env's RLS.
    let mut tx = match pool.begin().await {
        Ok(t) => t,
        Err(e) => {
            tracing::warn!(error = %e, "fdx: grant-seed tx begin failed");
            return;
        }
    };
    let _ = sqlx::query("SELECT sentin8_set_tenant_context($1)")
        .bind(env_id)
        .execute(&mut *tx)
        .await;

    // Idempotent seed: when the state carried a consent handle, the handle
    // IS the grant row id (the recipient's start created the handle; the
    // provider adopts the SAME id so both sides reference one flow).
    // A repeated event (at-least-once delivery) re-INSERTs nothing.
    let inserted = if let Some(id) = handle {
        sqlx::query(
            r#"INSERT INTO consents
                   (id, env_id, customer_id, recipient_id, status, scopes)
               VALUES ($1, $2, $3, $4, 'active', $5)
               ON CONFLICT (id) DO UPDATE
                     SET status = 'active', updated_at = now()"#,
        )
        .bind(id)
        .bind(env_id)
        .bind(user_id)
        .bind(&client_id)
        .bind(&scopes)
        .execute(&mut *tx)
        .await
    } else {
        // No FDX handle in the state — a non-FDX client's grant. Record it
        // under the AS's grant id when present, else a fresh row.
        let row_id = grant_id
            .as_deref()
            .and_then(|g| uuid::Uuid::parse_str(g).ok())
            .unwrap_or_else(uuid::Uuid::new_v4);
        sqlx::query(
            r#"INSERT INTO consents
                   (id, env_id, customer_id, recipient_id, status, scopes)
               VALUES ($1, $2, $3, $4, 'active', $5)
               ON CONFLICT (id) DO UPDATE
                     SET status = 'active', updated_at = now()"#,
        )
        .bind(row_id)
        .bind(env_id)
        .bind(user_id)
        .bind(&client_id)
        .bind(&scopes)
        .execute(&mut *tx)
        .await
    };
    match inserted {
        Ok(res) => {
            let consent_id = if let Some(id) = handle {
                id
            } else {
                grant_id
                    .as_deref()
                    .and_then(|g| uuid::Uuid::parse_str(g).ok())
                    .unwrap_or_default()
            };
            // Per-account grant rows (FDX Consent API §4.2 / UX §3.1.6):
            // the customer's selected accounts from the hosted consent
            // screen ride the AS event; each becomes a consent_resources
            // row so the data plane filters reads to the selection.
            for aid in &selected {
                let _ = sqlx::query(
                    r#"INSERT INTO consent_resources (consent_id, resource_type, resource_id, data_clusters)
                       VALUES ($1, 'ACCOUNT', $2, ARRAY['ACCOUNT_BASIC', 'ACCOUNT_DETAILED', 'TRANSACTIONS'])
                       ON CONFLICT DO NOTHING"#,
                )
                .bind(consent_id)
                .bind(aid)
                .execute(&mut *tx)
                .await;
            }
            if let Err(e) = tx.commit().await {
                tracing::warn!(error = %e, "fdx: grant-seed commit failed");
                return;
            }
            tracing::info!(
                %env_id, consent_id = %consent_id, client_id = %client_id,
                accounts = selected.len(),
                "fdx: grant ledger seeded from AS grant event"
            );
            // Grant-created event for the vertical's own family (DESIGN §4):
            // downstream notification subscribers hear about the new grant.
            crate::handlers::emit_event(pool, env_id, "bank8:fdx:consent:created", serde_json::json!({
                "consent_id": consent_id, "client_id": client_id, "scopes": scopes,
            })).await;
            let _ = res;
        }
        Err(e) => {
            tracing::warn!(error = %e, "fdx: grant-seed insert failed");
            let _ = tx.rollback().await;
        }
    }
}

/// Dispatch a single Bus message (sys family). When
/// `sentin8:sys:service:updated` fires for `service == "fdx"` and
/// `enabled == true`, auto-register the FDX provider profile for the
/// target org/env.
async fn handle_envinit_message(pool: &PgPool, msg: &sentin8::bus::contracts::Message) {
    // Event names use ALL-COLON segments (AGENTS.md event-naming rule).
    if msg.event_type != "sentin8:sys:service:updated" {
        return;
    }

    let payload: &serde_json::Value = &msg.payload;
    let service = payload.get("service").and_then(|v| v.as_str()).unwrap_or("");
    let enabled = payload.get("enabled").and_then(|v| v.as_bool()).unwrap_or(false);

    if service != "fdx" || !enabled {
        return;
    }

    let env_id = match payload.get("env_id").and_then(|v| v.as_str()).and_then(|s| uuid::Uuid::parse_str(s).ok()) {
        Some(id) => id,
        None => return,
    };

    // VDC-2 consumer-side defense-in-depth: the event's first colon
    // segment must match the recorded producer vertical (`sentin8`) —
    // Bus's produce-side ownership gate is the structural control; this
    // verifies the message Bus delivered before seeding tenant state.
    if let Err(reason) = sentin8::bus::client::BusClient::require_publisher(msg) {
        tracing::warn!(reason = %reason, "fdx: untrusted publisher — skipping env-init");
        return;
    }

    tracing::info!(%env_id, "fdx: auto-registering provider profile (event-driven)");
    // Shield per-env set seeding (VDC §VDC.6): the fdx Shield engine
    // evaluates per-request env; without an env-local set a tenant-env
    // user request hits `no_set_for_env` fail-closed denial. Seed the
    // env's copy of fdx's platform-origin sets from the SYSTEM template.
    if let Err(e) = seed_env_policy_sets(pool, env_id).await {
        tracing::warn!(error = %e, %env_id, "fdx: per-env policy-set seed failed");
    }
    ensure_provider_profile(pool, env_id).await;
}

/// Copy fdx's `origin='platform'` policy sets from the SYSTEM-env
/// substrate template into the given env — the vertical-DB mirror of what
/// Sentin8:Sys does for the platform DB at env creation. Idempotent
/// (`ON CONFLICT DO NOTHING` — operator edits survive re-enable events).
async fn seed_env_policy_sets(pool: &PgPool, env_id: uuid::Uuid) -> anyhow::Result<()> {
    const SYSTEM_ENV_ID: uuid::Uuid = uuid::Uuid::from_u128(2);
    let mut tx = pool.begin().await?;
    let _ = sqlx::query("SELECT sentin8_set_tenant_context($1, '', 'm2m', 'sys:admin')")
        .bind(SYSTEM_ENV_ID)
        .execute(&mut *tx)
        .await;
    let seeded = sqlx::query(
        r#"INSERT INTO sys.policy_sets
               (env_id, service, policy_set_name, description, policies, schema, origin, mode, version, enabled)
           SELECT $2, service, policy_set_name, description, policies, schema,
                  'platform', mode, 1, true
             FROM sys.policy_sets
            WHERE env_id = $1 AND service = $3 AND origin = 'platform' AND enabled
           ON CONFLICT (env_id, service, policy_set_name) DO NOTHING"#,
    )
    .bind(SYSTEM_ENV_ID)
    .bind(env_id)
    .bind("bank8:fdx")
    .execute(&mut *tx)
    .await?
    .rows_affected();
    tx.commit().await?;
    if seeded > 0 {
        tracing::info!(env_id = %env_id, sets = seeded, "fdx: seeded per-env policy sets");
    }
    Ok(())
}


// ── Sys tenant-snapshot API client (VDC-4/VDC-9) ──────────────────────────

/// The tenant identity fields the FDX provider-profile flow derives
/// issuer/JWKS/callback hostnames from (Sys `GET /v1/tenants/{env_id}`
/// response, VDC §VDC.5).
#[derive(Debug, Clone)]
struct TenantSnapshot {
    env_id: uuid::Uuid,
    env_slug: String,
    /// Carried for payload completeness; unused by the fdx flow.
    _env_display_name: String,
    /// Carried for payload completeness; unused by the fdx flow.
    _org_id: uuid::Uuid,
    org_slug: String,
    org_display_name: String,
    org_domain: String,
    auth_domain: Option<String>,
}

/// The shared cert-presenting `bank8-fdx-sys` transport (built once per
/// process, CERTFREE-4V): the workload certificate presents in the TLS
/// handshake — Sys's TLS layer authenticates it and the enroll-published
/// registry map authorizes `sentin8:sys:tenants:read`. No M2M token
/// exists on this path.
async fn sys_snapshot_http() -> Result<reqwest::Client, String> {
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
    sentin8::middleware::mtls::build_mtls_client(&mtls).map_err(|e| format!("transport: {e}"))
}

/// Fetch the tenant snapshot from Sys (`GET /v1/tenants/{env_id}`) via the
/// cert-presenting `bank8-fdx-sys` workload (CERTFREE-4V — no M2M token;
/// scope `sentin8:sys:tenants:read` rides the registry map).
/// `Ok(None)` = 404 (env unknown or fdx not enabled there — scoped
/// discovery); `Err` = transport/5xx (retryable).
async fn fetch_tenant_snapshot(env_id: uuid::Uuid) -> Result<Option<TenantSnapshot>, String> {
    let cfg = sentin8::config::Sentin8Config::from_env();
    let sys_base = cfg.sentin8_sys_url();

    let http = sys_snapshot_http().await?;
    let url = format!("{}/v1/tenants/{}", sys_base.trim_end_matches('/'), env_id);
    let resp = http
        .get(&url)
        .send()
        .await
        .map_err(|e| format!("snapshot request: {e}"))?;

    match resp.status() {
        s if s.is_success() => {
            let v: serde_json::Value =
                resp.json().await.map_err(|e| format!("snapshot decode: {e}"))?;
            let parse = |k: &str| {
                v.get(k).and_then(|x| x.as_str()).unwrap_or_default().to_string()
            };
            let opt = |k: &str| {
                v.get(k).and_then(|x| x.as_str()).map(|s| s.to_string())
            };
            Ok(Some(TenantSnapshot {
                env_id: v.get("env_id")
                    .and_then(|x| x.as_str())
                    .and_then(|s| uuid::Uuid::parse_str(s).ok())
                    .unwrap_or(env_id),
                env_slug: parse("env_slug"),
                _env_display_name: parse("env_display_name"),
                _org_id: v.get("org_id")
                    .and_then(|x| x.as_str())
                    .and_then(|s| uuid::Uuid::parse_str(s).ok())
                    .unwrap_or_default(),
                org_slug: parse("org_slug"),
                org_display_name: parse("org_display_name"),
                org_domain: parse("org_domain"),
                auth_domain: opt("auth_domain"),
            }))
        }
        reqwest::StatusCode::NOT_FOUND => Ok(None),
        s => Err(format!("snapshot returned {s}")),
    }
}

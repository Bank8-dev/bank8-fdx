// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Bank8:FDX
// SPDX-License-Identifier: Apache-2.0

//! Sentin8 FDX - open banking, FDX v6.5 provider/recipient.
//! See `services/fdx/DESIGN.md`.
//! Boot runs on the platform `sentin8-shell` crate (design
//! `sentin8/design/sentin8-sentin8-shell-technical-design.md`): registration
//! flag, PQ provider, config, capped pool, PG18 check, state binding, OpenAPI
//! merge, middleware stack and PQ-TLS listener are owned by the shell. This
//! binary supplies only its registration data, state and routes.

// allocation in the process routes through it). Rationale in the workspace
// Cargo.toml: glibc's per-thread arenas fragment under the many-worker tokio
// runtime and never return memory; measured 4 MB+ RSS growth per request
#[allow(dead_code)]
mod admin_ui;
#[allow(dead_code)]
mod auth;
mod common;
#[allow(dead_code)]
mod config;
#[allow(dead_code)]
mod consent_records;
mod consent_rfw;
#[allow(dead_code)]
mod csdf;
#[allow(dead_code)]
mod errors;
mod event_consumer;
#[allow(dead_code)]
mod event_notifications;
#[allow(dead_code)]
mod flow;
#[allow(dead_code)]
mod handlers;
#[allow(dead_code)]
mod headers;
mod middleware;
#[allow(dead_code)]
mod money_movement;
#[allow(dead_code)]
mod notifications;
mod openapi;
#[allow(dead_code)]
mod operations;
#[allow(dead_code)]
mod payment_networks;
#[allow(dead_code)]
mod pip;
pub mod policy;
#[allow(dead_code)]
#[allow(dead_code)]
mod recurring;
mod registration;
#[allow(dead_code)]
mod server;
#[allow(dead_code)]
mod statement_download;
#[allow(dead_code)]
mod tax;
mod tenant_snapshot;
mod tokens;
#[allow(dead_code)]
mod validation;

use utoipa::OpenApi;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    sentin8::shell::serve(
        sentin8::shell::Sentin8Shell::new("bank8:fdx", "BANK8_FDX")
            .with_registration(registration::print)
            .with_state(server::build_state)
            .with_own_health()
            .with_router(server::routes)
            .with_openapi(openapi::FdxOpenApi::openapi()),
    )
    .await
}

// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Bank8:FDX
// SPDX-License-Identifier: Apache-2.0

//! FDX v6.5 completion handlers - shared DB helpers.
//! Small cross-family plumbing used by the `/fdx/v6` completion handlers
//! (statements, money movement, PIP, recurring, recipients, payment
//! networks, notifications, consents, operations).

use uuid::Uuid;

use crate::errors::FdxErrorResponse;

/// Set the transaction-local RLS tenant context on a connection. MUST be
/// awaited on the same connection every subsequent tenant query runs on
/// `set_config(..., true)` scopes the setting to the transaction/connection
/// (architecture-principles §4.3d).
pub(crate) async fn set_tenant_context(conn: &mut sqlx::PgConnection, env_id: Uuid) {
    let _ = sqlx::query(
        "SELECT sentin8_set_tenant_context($1, NULL, NULL, NULL, false, false, false, NULL, 'fdx')",
    )
    .bind(env_id)
    .execute(conn)
    .await;
}

/// Map a sqlx error to the FDX internal-error response .
pub(crate) fn db_err(e: sqlx::Error) -> FdxErrorResponse {
    FdxErrorResponse::internal(format!("db: {e}"))
}

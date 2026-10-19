// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Bank8:FDX
// SPDX-License-Identifier: Apache-2.0

//! Delegated provider-token storage via secret references (fdx DESIGN.md §1,
//! two-ledger model). The recipient-side consent callback exchanges the
//! authorization code at the provider's AS and stores the resulting access
//! and refresh tokens on its OWN registry row (`fdx.recipient_consents`) -
//! token custody follows the PKCE verifier, and the recipient is the OAuth
//! client. Tokens are never stored as plaintext columns: each is written to
//! the local secrets directory under `SENTIN8_SECRETS_DIR` (dev default
//! `/etc/sentin8/secrets`) and only the `sentin8-secrets://` URI is stored
//! on the registry row - the platform vault backend swaps in via the same
//! `SecretResolver` trait.

use sentin8_secrets_sdk::secrets::{SecretError, SecretRef, SecretResolver, SecretValue};
use sqlx::Row;
use uuid::Uuid;

/// Secret backend name used in `sentin8-secrets://` URIs.
const BACKEND: &str = "sentin8-secrets";

/// A `SecretResolver` over the local secrets directory.
pub struct LocalFileSecrets {
    base: std::path::PathBuf,
}

impl LocalFileSecrets {
    pub fn from_env() -> Self {
        let base =
            std::env::var("SENTIN8_SECRETS_DIR").unwrap_or_else(|_| "/etc/sentin8/secrets".into());
        Self { base: base.into() }
    }

    #[allow(dead_code)]
    pub fn with_dir(base: impl Into<std::path::PathBuf>) -> Self {
        Self { base: base.into() }
    }

    fn path_for(&self, path: &str) -> std::path::PathBuf {
        self.base.join(path)
    }

    /// Write the secret value and return the reference URI.
    pub fn store(&self, path: &str, value: &[u8]) -> Result<String, SecretError> {
        let full = self.path_for(path);
        if let Some(parent) = full.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| SecretError::InvalidRef(format!("mkdir {}: {e}", parent.display())))?;
        }
        std::fs::write(&full, value)
            .map_err(|e| SecretError::InvalidRef(format!("write {}: {e}", full.display())))?;
        Ok(SecretRef::new(BACKEND, path).to_uri())
    }
}

impl SecretResolver for LocalFileSecrets {
    #[allow(clippy::manual_async_fn)]
    fn resolve<'life0, 'life1, 'async_trait>(
        &'life0 self,
        reference: &'life1 SecretRef,
    ) -> ::core::pin::Pin<
        Box<
            dyn ::core::future::Future<Output = Result<SecretValue, SecretError>>
                + ::core::marker::Send
                + 'async_trait,
        >,
    >
    where
        'life0: 'async_trait,
        'life1: 'async_trait,
        Self: 'async_trait,
    {
        Box::pin(async move {
            let path = self.path_for(&reference.path);
            let bytes = std::fs::read(&path)
                .map_err(|e| SecretError::InvalidRef(format!("read {}: {e}", path.display())))?;
            Ok(SecretValue::new(bytes))
        })
    }
}

/// Paths for one recipient-consent row's delegated provider tokens
/// (the recipient registry row that ran the token exchange).
pub fn access_token_path(consent_id: Uuid) -> String {
    format!("fdx/recipient-consents/{consent_id}/access-token")
}

pub fn refresh_token_path(consent_id: Uuid) -> String {
    format!("fdx/recipient-consents/{consent_id}/refresh-token")
}

/// Path for one recipient client row's DPoP signing key
/// (one per `fdx.recipients` row - the recipient's per-provider client).
pub fn dpop_key_path(recipient_row_id: Uuid) -> String {
    format!("fdx/recipients/{recipient_row_id}/dpop-key")
}

/// Persist both delegated provider tokens as secret references on the
/// recipient registry row. The old token files are overwritten in place
/// (rotation).
pub async fn store_provider_tokens(
    conn: &mut sqlx::PgConnection,
    consent_id: Uuid,
    access_token: &str,
    refresh_token: Option<&str>,
    expires_in: i64,
) -> Result<(), String> {
    let secrets = LocalFileSecrets::from_env();
    let access_ref = secrets
        .store(&access_token_path(consent_id), access_token.as_bytes())
        .map_err(|e| format!("store access token: {e}"))?;
    let refresh_ref = match refresh_token {
        Some(rt) if !rt.is_empty() => Some(
            secrets
                .store(&refresh_token_path(consent_id), rt.as_bytes())
                .map_err(|e| format!("store refresh token: {e}"))?,
        ),
        _ => None,
    };
    sqlx::query(
        r#"UPDATE recipient_consents
              SET provider_access_token_ref = $2,
                  provider_refresh_token_ref = COALESCE($3, provider_refresh_token_ref),
                  provider_token_expires_at = now() + ($4 || ' seconds')::interval,
                  updated_at = now()
            WHERE id = $1"#,
    )
    .bind(consent_id)
    .bind(&access_ref)
    .bind(refresh_ref)
    .bind(expires_in.to_string())
    .execute(conn)
    .await
    .map_err(|e| format!("persist token refs: {e}"))?;
    Ok(())
}

/// Load the delegated provider access token from its secret reference
/// (on the recipient registry row).
pub async fn load_provider_access_token(
    conn: &mut sqlx::PgConnection,
    consent_id: Uuid,
) -> Result<Option<String>, String> {
    let row = sqlx::query("SELECT provider_access_token_ref FROM recipient_consents WHERE id = $1")
        .bind(consent_id)
        .fetch_optional(&mut *conn)
        .await
        .map_err(|e| format!("load token ref: {e}"))?;
    let Some(row) = row else {
        return Ok(None);
    };
    let uri: Option<String> = row
        .try_get::<Option<String>, _>("provider_access_token_ref")
        .ok()
        .flatten();
    let Some(uri) = uri else {
        return Ok(None);
    };
    let secrets = LocalFileSecrets::from_env();
    let r = SecretRef::parse(&uri).map_err(|e| e.to_string())?;
    let value = secrets.resolve(&r).await.map_err(|e| e.to_string())?;
    Ok(value.into_string().ok())
}

/// Load the delegated provider refresh token from its secret reference
/// (on the recipient registry row).
pub async fn load_provider_refresh_token(
    conn: &mut sqlx::PgConnection,
    consent_id: Uuid,
) -> Result<Option<String>, String> {
    let row =
        sqlx::query("SELECT provider_refresh_token_ref FROM recipient_consents WHERE id = $1")
            .bind(consent_id)
            .fetch_optional(&mut *conn)
            .await
            .map_err(|e| format!("load refresh ref: {e}"))?;
    let Some(row) = row else {
        return Ok(None);
    };
    let uri: Option<String> = row
        .try_get::<Option<String>, _>("provider_refresh_token_ref")
        .ok()
        .flatten();
    let Some(uri) = uri else {
        return Ok(None);
    };
    let secrets = LocalFileSecrets::from_env();
    let r = SecretRef::parse(&uri).map_err(|e| e.to_string())?;
    let value = secrets.resolve(&r).await.map_err(|e| e.to_string())?;
    Ok(value.into_string().ok())
}

/// Store the recipient client's DPoP signing key sealed behind a secret
/// reference and return the reference URI (fdx DESIGN.md §1 - key material
/// is never a plaintext column). One key per `fdx.recipients` row (the
/// recipient's per-provider client). Overwrites in place (key rotation).
pub fn store_dpop_key(recipient_row_id: Uuid, pem: &str) -> Result<String, String> {
    let secrets = LocalFileSecrets::from_env();
    secrets
        .store(&dpop_key_path(recipient_row_id), pem.as_bytes())
        .map_err(|e| format!("store dpop key: {e}"))
}

/// Resolve the recipient client's DPoP signing key PEM from the
/// `fdx.recipients` row's sealed reference.
pub async fn load_dpop_key(
    conn: &mut sqlx::PgConnection,
    recipient_row_id: Uuid,
) -> Result<Option<String>, String> {
    let row = sqlx::query("SELECT dpop_key_ref FROM recipients WHERE id = $1")
        .bind(recipient_row_id)
        .fetch_optional(&mut *conn)
        .await
        .map_err(|e| format!("load dpop key ref: {e}"))?;
    let Some(row) = row else {
        return Ok(None);
    };
    let uri: Option<String> = row
        .try_get::<Option<String>, _>("dpop_key_ref")
        .ok()
        .flatten();
    let Some(uri) = uri else {
        return Ok(None);
    };
    let secrets = LocalFileSecrets::from_env();
    let r = SecretRef::parse(&uri).map_err(|e| e.to_string())?;
    let value = secrets.resolve(&r).await.map_err(|e| e.to_string())?;
    Ok(value.into_string().ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("fdx-tokens-test-{name}-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[tokio::test]
    async fn store_and_resolve_roundtrip() {
        let dir = temp_dir("roundtrip");
        let secrets = LocalFileSecrets::with_dir(dir.clone());
        let uri = secrets
            .store("fdx/consents/test/access", b"tok-abc")
            .unwrap();
        assert!(uri.starts_with("sentin8-secrets://"));
        let r = SecretRef::parse(&uri).unwrap();
        let value = secrets.resolve(&r).await.unwrap();
        assert_eq!(value.into_string().unwrap(), "tok-abc");
    }

    #[tokio::test]
    async fn store_overwrites_existing() {
        let dir = temp_dir("overwrite");
        let secrets = LocalFileSecrets::with_dir(dir.clone());
        let path = "fdx/consents/test/rotating";
        secrets.store(path, b"old").unwrap();
        secrets.store(path, b"new").unwrap();
        let r = SecretRef::parse(&SecretRef::new(BACKEND, path).to_uri()).unwrap();
        assert_eq!(
            secrets.resolve(&r).await.unwrap().into_string().unwrap(),
            "new"
        );
    }

    #[tokio::test]
    async fn resolve_missing_returns_error() {
        let dir = temp_dir("missing");
        let secrets = LocalFileSecrets::with_dir(dir.clone());
        let r = SecretRef::new(BACKEND, "fdx/consents/none/here");
        assert!(secrets.resolve(&r).await.is_err());
    }

    #[test]
    fn token_paths_are_unique_per_consent() {
        let a = Uuid::new_v4();
        let b = Uuid::new_v4();
        assert_ne!(access_token_path(a), access_token_path(b));
        assert_ne!(access_token_path(a), refresh_token_path(a));
    }

    #[tokio::test]
    async fn parse_rejects_bad_uri() {
        assert!(SecretRef::parse("not-a-uri").is_err());
    }
}

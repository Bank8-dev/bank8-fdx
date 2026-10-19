-- SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
-- SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
-- SPDX-FileCopyrightText: Copyright Contributors to the Bank8:FDX
-- SPDX-License-Identifier: Apache-2.0

-- Bank8:FDX - the service's own schema `fdx` (schema-per-service):
-- fdx_* domain tables + fdx.outbox / fdx.audit_journal producer tables,
-- all FORCE-RLS env-scoped (provider_profiles is the public cross-env
-- catalog - no RLS by design).
--
-- TWO LEDGERS (fdx DESIGN.md §1): the provider's GRANT ledger
-- (`fdx.consents` - seeded from sentin8:auth:grant:created) lives in the
-- provider tenant; the recipient's REGISTRY (`fdx.recipient_consents` +
-- `fdx.recipients`) lives in the recipient tenant. The OAuth client
-- belongs to the recipient; the delegated tokens belong to the recipient
-- (it exchanges the code). No column on one side's tables references the
-- other side's tenant identity beyond opaque OAuth handles.

-- The PROVIDER grant ledger - the data holder's statutory record of what
-- the customer granted to which recipient (client_id). Seeded by the
-- auth-family consumer from `sentin8:auth:grant:created` (consent handle
-- parsed from the OAuth `state`; the customer_id IS the token `sub` -
-- both are the provider's user id at code issuance). No token or PKCE
-- material here - those are the RECIPIENT's (client) custody.
CREATE SCHEMA IF NOT EXISTS fdx;
CREATE TABLE IF NOT EXISTS fdx.consents (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    env_id  UUID NOT NULL,
    customer_id     UUID NOT NULL,
    recipient_id    TEXT,
    provider_id     TEXT,
    provider_name   TEXT,
    status          TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('pending', 'active', 'expired', 'revoked', 'reauthorization_required')),
    scopes          TEXT[] NOT NULL DEFAULT '{}',
    data_clusters   TEXT[] NOT NULL DEFAULT '{}',
    duration_days   INTEGER,
    -- FC-8: FDX ConsentGrant lifecycle (consent spec §ConsentGrant).
    -- durationType: ONE_TIME | PERSISTENT | TIME_BOUND.
    duration_type   TEXT CHECK (duration_type IN ('ONE_TIME', 'PERSISTENT', 'TIME_BOUND')),
    -- durationPeriod: days from original grant (TIME_BOUND).
    duration_period_days INTEGER,
    -- lookbackPeriod: days of historical data requestable; measured from
    -- request time, not grant time (consent spec §lookbackPeriod).
    lookback_period_days INTEGER,
    expires_at      TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_fdx_consents_env ON fdx.consents (env_id);
CREATE INDEX IF NOT EXISTS idx_fdx_consents_customer ON fdx.consents (customer_id);

-- Bank8:FDX consent resources - per-account grants within a consent.
-- Per FDX Consent API Specification v1.0 §4.2, a ConsentGrant enumerates
-- the permissioned resources (accounts) with their data clusters. This
-- table stores the per-account grants so the recipient API can filter
-- accounts to only those the customer selected during the consent flow.
-- See FDX UX Guidelines v3.1 §3.1.6 "Select Accounts".
CREATE TABLE IF NOT EXISTS fdx.consent_resources (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    consent_id      UUID NOT NULL REFERENCES fdx.consents(id) ON DELETE CASCADE,
    resource_type   TEXT NOT NULL DEFAULT 'ACCOUNT',
    resource_id     TEXT NOT NULL,
    data_clusters   TEXT[] NOT NULL DEFAULT '{}',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_fdx_consent_resources_consent
    ON fdx.consent_resources (consent_id);
CREATE INDEX IF NOT EXISTS idx_fdx_consent_resources_resource
    ON fdx.consent_resources (resource_type, resource_id);

-- Bank8:FDX provider profiles - the recipient-side directory of providers
-- (the cross-env catalog). Registered by env-init; the recipient app
-- lists providers from it. Carries NO recipient/OAuth-client material -
-- the recipient's client is registered at the provider's AS by the
-- recipient's own consent-start flow (fdx.recipients caches it).
CREATE TABLE IF NOT EXISTS fdx.provider_profiles (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    env_id  UUID NOT NULL,
    provider_name   TEXT NOT NULL,
    issuer_url      TEXT NOT NULL,
    jwks_url        TEXT NOT NULL,
    fdx_version     TEXT NOT NULL DEFAULT 'v6.5',
    capabilities    JSONB NOT NULL DEFAULT '[]',
    status          TEXT NOT NULL DEFAULT 'active',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_fdx_provider_profiles_env_name
    ON fdx.provider_profiles (env_id, provider_name);

-- Bank8:FDX recipient client registrations - the RECIPIENT's per-provider
-- OAuth client cache (two-ledger model, fdx DESIGN.md §1). One row per
-- (recipient env, provider): the public client the recipient registered
-- at the provider's authorization server via DCR (RFC 7591), the redirect
-- URI registered for it, and the sealed DPoP key the recipient uses for
-- RFC 9449 proofs at that provider's token endpoint. Key material lives
-- in the secrets backend; only the sentin8-secrets:// reference is stored.
CREATE TABLE IF NOT EXISTS fdx.recipients (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    env_id  UUID NOT NULL,
    provider_id     TEXT NOT NULL,
    recipient_name  TEXT NOT NULL,
    client_id       TEXT,
    redirect_uris   TEXT[] NOT NULL DEFAULT '{}',
    dpop_key_ref    TEXT,
    status          TEXT NOT NULL DEFAULT 'active',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_fdx_recipients_env_provider
    ON fdx.recipients (env_id, provider_id);

-- The RECIPIENT consent registry - the fintech's own bookkeeping of its
-- customers' bank connections (two-ledger model, fdx DESIGN.md §1).
-- Written by the recipient-side consent-start (pending) and OAuth callback
-- (active) surfaces; read by the fintech app's Connections/Accounts pages.
-- The PKCE verifier and delegated provider tokens live HERE - the recipient
-- is the OAuth client, so token custody follows the verifier. Tokens are
-- stored as sentin8-secrets:// references - never plaintext.
CREATE TABLE IF NOT EXISTS fdx.recipient_consents (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    env_id  UUID NOT NULL,
    customer_id     UUID NOT NULL,
    provider_id     TEXT NOT NULL,
    provider_name   TEXT,
    client_id       TEXT,
    scopes          TEXT[] NOT NULL DEFAULT '{}',
    selected_account_ids TEXT[] NOT NULL DEFAULT '{}',
    status          TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'active', 'expired', 'revoked')),
    code_verifier   TEXT,
    app_redirect_uri TEXT,
    provider_access_token_ref TEXT,
    provider_refresh_token_ref TEXT,
    provider_token_expires_at TIMESTAMPTZ,
    expires_at      TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_fdx_recipient_consents_env ON fdx.recipient_consents (env_id);
CREATE INDEX IF NOT EXISTS idx_fdx_recipient_consents_customer ON fdx.recipient_consents (customer_id);

-- Bank8:FDX audit events
CREATE TABLE IF NOT EXISTS fdx.audit_events (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    env_id      UUID,
    actor_user_id       TEXT,
    action              TEXT NOT NULL,
    target_resource_type TEXT,
    target_resource_id  TEXT,
    correlation_id      TEXT,
    timestamp           TIMESTAMPTZ NOT NULL DEFAULT now(),
    schema_version      TEXT NOT NULL DEFAULT '1.0'
);

-- ── RLS: Bank8:FDX tenant isolation (Story 12.4.36) ──────────────────────
-- All Bank8:FDX tables with env_id are tenant-scoped. The Delegation
-- Gateway ensures tokens carry the target env, so RLS naturally
-- scopes to the right tenant. env_id is the sole tenant key
-- (architecture-principles.md §4.3).

ALTER TABLE fdx.consents ENABLE ROW LEVEL SECURITY;
ALTER TABLE fdx.consents FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS consents_select ON fdx.consents;
CREATE POLICY consents_select ON fdx.consents FOR SELECT
    USING (sentin8_context_initialized() AND env_id = sentin8_current_env_id());
DROP POLICY IF EXISTS consents_insert ON fdx.consents;
CREATE POLICY consents_insert ON fdx.consents FOR INSERT
    WITH CHECK (sentin8_context_initialized() AND env_id = sentin8_current_env_id());
DROP POLICY IF EXISTS consents_update ON fdx.consents;
CREATE POLICY consents_update ON fdx.consents FOR UPDATE
    USING (sentin8_context_initialized() AND env_id = sentin8_current_env_id());
DROP POLICY IF EXISTS consents_delete ON fdx.consents;
CREATE POLICY consents_delete ON fdx.consents FOR DELETE
    USING (sentin8_context_initialized() AND env_id = sentin8_current_env_id());

-- fdx.consent_resources: no env_id - protected transitively via
-- fdx.consents (CASCADE FK). RLS is not needed (the parent table filters).
-- No RLS on this table.

-- fdx.provider_profiles: explicitly NO RLS - it is a PUBLIC cross-env
-- registry (the recipient catalog: any environment's caller discovers any
-- active provider; fdx design §4.3c). The tenant-visibility FORCE-RLS pattern
-- must NOT apply here - with it, the cross-env catalog read saw nothing and
-- the provider observation poll returned an empty list. The idempotent
-- statements below REMOVE any policy a prior blanket pass may have applied
-- (convergent on re-enroll).
ALTER TABLE fdx.provider_profiles NO FORCE ROW LEVEL SECURITY;
ALTER TABLE fdx.provider_profiles DISABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS provider_profiles_select ON fdx.provider_profiles;
DROP POLICY IF EXISTS provider_profiles_insert ON fdx.provider_profiles;
DROP POLICY IF EXISTS provider_profiles_update ON fdx.provider_profiles;
DROP POLICY IF EXISTS provider_profiles_delete ON fdx.provider_profiles;
ALTER TABLE fdx.recipients ENABLE ROW LEVEL SECURITY;
ALTER TABLE fdx.recipients FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS recipients_select ON fdx.recipients;
CREATE POLICY recipients_select ON fdx.recipients FOR SELECT
    USING (sentin8_context_initialized() AND env_id = sentin8_current_env_id());
DROP POLICY IF EXISTS recipients_insert ON fdx.recipients;
CREATE POLICY recipients_insert ON fdx.recipients FOR INSERT
    WITH CHECK (sentin8_context_initialized() AND env_id = sentin8_current_env_id());
DROP POLICY IF EXISTS recipients_update ON fdx.recipients;
CREATE POLICY recipients_update ON fdx.recipients FOR UPDATE
    USING (sentin8_context_initialized() AND env_id = sentin8_current_env_id());
DROP POLICY IF EXISTS recipients_delete ON fdx.recipients;
CREATE POLICY recipients_delete ON fdx.recipients FOR DELETE
    USING (sentin8_context_initialized() AND env_id = sentin8_current_env_id());

-- fdx.recipient_consents: the RECIPIENT registry (two-ledger model) -
-- same env-scoped FORCE-RLS pattern as the grant ledger; the recipient
-- reads/writes ONLY its own tenant's connection rows.
ALTER TABLE fdx.recipient_consents ENABLE ROW LEVEL SECURITY;
ALTER TABLE fdx.recipient_consents FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS recipient_consents_select ON fdx.recipient_consents;
CREATE POLICY recipient_consents_select ON fdx.recipient_consents FOR SELECT
    USING (sentin8_context_initialized() AND env_id = sentin8_current_env_id());
DROP POLICY IF EXISTS recipient_consents_insert ON fdx.recipient_consents;
CREATE POLICY recipient_consents_insert ON fdx.recipient_consents FOR INSERT
    WITH CHECK (sentin8_context_initialized() AND env_id = sentin8_current_env_id());
DROP POLICY IF EXISTS recipient_consents_update ON fdx.recipient_consents;
CREATE POLICY recipient_consents_update ON fdx.recipient_consents FOR UPDATE
    USING (sentin8_context_initialized() AND env_id = sentin8_current_env_id());
DROP POLICY IF EXISTS recipient_consents_delete ON fdx.recipient_consents;
CREATE POLICY recipient_consents_delete ON fdx.recipient_consents FOR DELETE
    USING (sentin8_context_initialized() AND env_id = sentin8_current_env_id());

ALTER TABLE fdx.audit_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE fdx.audit_events FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS audit_events_select ON fdx.audit_events;
CREATE POLICY audit_events_select ON fdx.audit_events FOR SELECT
    USING (sentin8_context_initialized() AND (env_id IS NULL OR env_id = sentin8_current_env_id()));
DROP POLICY IF EXISTS audit_events_insert ON fdx.audit_events;
CREATE POLICY audit_events_insert ON fdx.audit_events FOR INSERT
    WITH CHECK (sentin8_context_initialized() AND (env_id IS NULL OR env_id = sentin8_current_env_id()));

-- Holder-scoped RLS policies
-- ── FDX-COMPLETE epic (2026-09-06) - new tables ──────────────────────────
-- FC-7: Consent revocation record (reason/initiator persisted per §5.1).
-- FC-8: ConsentGrant lifecycle fields (durationType/durationPeriod/
--       lookbackPeriod) as new columns on consents.
-- NOTE: new platform - no migration code. Columns are added to the
-- CREATE TABLE above in the canonical schema; re-run vertical init.
-- (The CREATE TABLE in this file has been updated directly; this block
--  documents the additions and creates the new tables.)

-- FC-14: Notification subscriptions (event-notifications family §5.1a).
-- Secret is stored as a sentin8-secrets:// reference - never plaintext
-- (AGENTS.md secret-references rule). Delivery is via Sentin8:Auth signed
-- webhooks (design §5.1a): the delivery consumer posts the payload to the
-- callback URL with `x-sentin8-signature: sha256=...` (HMAC-SHA256 of the
-- body with the subscription secret) - the same signing scheme as Auth's
-- webhook relay (auth webhooks.rs relay_tick).
CREATE TABLE IF NOT EXISTS fdx.notification_subscriptions (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    env_id  UUID NOT NULL,
    customer_id     UUID,
    -- FDX NotificationSubscription fields (spec: type/category/
    -- callbackUrl/subscriber).
    event_type      TEXT NOT NULL CHECK (event_type IN (
        'ACCOUNT_TAKEOVER', 'ADDRESS_CHANGED', 'BALANCE',
        'CONSENT_EXPIRED', 'CONSENT_GRANTED', 'CONSENT_REVOKED',
        'CONSENT_UPDATED', 'CUSTOM', 'MFA_TARGET_CHANGED',
        'PHONE_CHANGED', 'PLANNED_OUTAGE', 'RISK', 'SERVICE',
        'SUSPECTED_INCIDENT', 'TAN_ACTIVATED', 'TAN_CREATED'
    )),
    category        TEXT NOT NULL CHECK (category IN (
        'CONSENT', 'FRAUD', 'MAINTENANCE', 'NEW_DATA', 'SECURITY',
        'TOKENIZED_ACCOUNT_NUMBER'
    )),
    callback_url    TEXT NOT NULL,
    subscriber      JSONB NOT NULL DEFAULT '{}',
    -- HMAC secret reference (sentin8-secrets://...) - per-subscription
    -- signing secret used by the delivery consumer.
    secret_ref      TEXT,
    status          TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'paused', 'deleted')),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_fdx_notification_subscriptions_env
    ON fdx.notification_subscriptions (env_id);

ALTER TABLE fdx.notification_subscriptions ENABLE ROW LEVEL SECURITY;
ALTER TABLE fdx.notification_subscriptions FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS notification_subscriptions_select ON fdx.notification_subscriptions;
CREATE POLICY notification_subscriptions_select ON fdx.notification_subscriptions FOR SELECT
    USING (sentin8_context_initialized() AND env_id = sentin8_current_env_id());
DROP POLICY IF EXISTS notification_subscriptions_insert ON fdx.notification_subscriptions;
CREATE POLICY notification_subscriptions_insert ON fdx.notification_subscriptions FOR INSERT
    WITH CHECK (sentin8_context_initialized() AND env_id = sentin8_current_env_id());
DROP POLICY IF EXISTS notification_subscriptions_update ON fdx.notification_subscriptions;
CREATE POLICY notification_subscriptions_update ON fdx.notification_subscriptions FOR UPDATE
    USING (sentin8_context_initialized() AND env_id = sentin8_current_env_id());
DROP POLICY IF EXISTS notification_subscriptions_delete ON fdx.notification_subscriptions;
CREATE POLICY notification_subscriptions_delete ON fdx.notification_subscriptions FOR DELETE
    USING (sentin8_context_initialized() AND env_id = sentin8_current_env_id());

-- FC-6: Notification feed (published/ingested notifications, pollable).
CREATE TABLE IF NOT EXISTS fdx.notifications (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    env_id  UUID NOT NULL,
    subscription_id UUID REFERENCES fdx.notification_subscriptions(id) ON DELETE SET NULL,
    notification_type TEXT NOT NULL,
    category        TEXT,
    severity        TEXT,
    priority        TEXT,
    payload         JSONB NOT NULL DEFAULT '{}',
    delivery_status TEXT NOT NULL DEFAULT 'pending' CHECK (delivery_status IN ('pending', 'delivered', 'failed', 'skipped')),
    delivery_attempts INTEGER NOT NULL DEFAULT 0,
    last_attempt_at TIMESTAMPTZ,
    delivered_at    TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_fdx_notifications_env ON fdx.notifications (env_id, created_at);

ALTER TABLE fdx.notifications ENABLE ROW LEVEL SECURITY;
ALTER TABLE fdx.notifications FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS notifications_select ON fdx.notifications;
CREATE POLICY notifications_select ON fdx.notifications FOR SELECT
    USING (sentin8_context_initialized() AND env_id = sentin8_current_env_id());
DROP POLICY IF EXISTS notifications_insert ON fdx.notifications;
CREATE POLICY notifications_insert ON fdx.notifications FOR INSERT
    WITH CHECK (sentin8_context_initialized() AND env_id = sentin8_current_env_id());
DROP POLICY IF EXISTS notifications_update ON fdx.notifications;
CREATE POLICY notifications_update ON fdx.notifications FOR UPDATE
    USING (sentin8_context_initialized() AND env_id = sentin8_current_env_id());

-- FC-3: Payment initiation parties (PIP family).
CREATE TABLE IF NOT EXISTS fdx.payment_initiation_parties (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    env_id  UUID NOT NULL,
    party_name      TEXT NOT NULL,
    party_type      TEXT NOT NULL DEFAULT 'MERCHANT',
    contact         JSONB NOT NULL DEFAULT '{}',
    registry        TEXT,
    registered_id   TEXT,
    status          TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'suspended', 'deleted')),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
ALTER TABLE fdx.payment_initiation_parties ENABLE ROW LEVEL SECURITY;
ALTER TABLE fdx.payment_initiation_parties FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS pip_select ON fdx.payment_initiation_parties;
CREATE POLICY pip_select ON fdx.payment_initiation_parties FOR SELECT
    USING (sentin8_context_initialized() AND env_id = sentin8_current_env_id());
DROP POLICY IF EXISTS pip_insert ON fdx.payment_initiation_parties;
CREATE POLICY pip_insert ON fdx.payment_initiation_parties FOR INSERT
    WITH CHECK (sentin8_context_initialized() AND env_id = sentin8_current_env_id());
DROP POLICY IF EXISTS pip_update ON fdx.payment_initiation_parties;
CREATE POLICY pip_update ON fdx.payment_initiation_parties FOR UPDATE
    USING (sentin8_context_initialized() AND env_id = sentin8_current_env_id());
DROP POLICY IF EXISTS pip_delete ON fdx.payment_initiation_parties;
CREATE POLICY pip_delete ON fdx.payment_initiation_parties FOR DELETE
    USING (sentin8_context_initialized() AND env_id = sentin8_current_env_id());

-- FC-3: PIP payment-method registrations.
CREATE TABLE IF NOT EXISTS fdx.pip_payment_methods (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    env_id  UUID NOT NULL,
    party_id        UUID NOT NULL REFERENCES fdx.payment_initiation_parties(id) ON DELETE CASCADE,
    method_type     TEXT NOT NULL,
    instrument      JSONB NOT NULL DEFAULT '{}',
    status          TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'revoked')),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
ALTER TABLE fdx.pip_payment_methods ENABLE ROW LEVEL SECURITY;
ALTER TABLE fdx.pip_payment_methods FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS pip_pm_select ON fdx.pip_payment_methods;
CREATE POLICY pip_pm_select ON fdx.pip_payment_methods FOR SELECT
    USING (sentin8_context_initialized() AND env_id = sentin8_current_env_id());
DROP POLICY IF EXISTS pip_pm_insert ON fdx.pip_payment_methods;
CREATE POLICY pip_pm_insert ON fdx.pip_payment_methods FOR INSERT
    WITH CHECK (sentin8_context_initialized() AND env_id = sentin8_current_env_id());
DROP POLICY IF EXISTS pip_pm_update ON fdx.pip_payment_methods;
CREATE POLICY pip_pm_update ON fdx.pip_payment_methods FOR UPDATE
    USING (sentin8_context_initialized() AND env_id = sentin8_current_env_id());
DROP POLICY IF EXISTS pip_pm_delete ON fdx.pip_payment_methods;
CREATE POLICY pip_pm_delete ON fdx.pip_payment_methods FOR DELETE
    USING (sentin8_context_initialized() AND env_id = sentin8_current_env_id());

-- FC-7: Consent revocation records (immutable - the revocation event).
CREATE TABLE IF NOT EXISTS fdx.consent_revocations (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    env_id  UUID NOT NULL,
    consent_id      UUID NOT NULL REFERENCES fdx.consents(id) ON DELETE CASCADE,
    reason          TEXT NOT NULL CHECK (reason IN ('BUSINESS_RULE', 'OTHER', 'SECURITY_EVENT', 'USER_ACTION')),
    other_reason    TEXT,
    initiator       TEXT NOT NULL CHECK (initiator IN (
        'DATA_ACCESS_PLATFORM', 'DATA_PROVIDER', 'DATA_RECIPIENT',
        'INDIVIDUAL', 'MERCHANT', 'TOKEN_ISSUER', 'VENDOR'
    )),
    revoked_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
ALTER TABLE fdx.consent_revocations ENABLE ROW LEVEL SECURITY;
ALTER TABLE fdx.consent_revocations FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS consent_revocations_select ON fdx.consent_revocations;
CREATE POLICY consent_revocations_select ON fdx.consent_revocations FOR SELECT
    USING (sentin8_context_initialized() AND env_id = sentin8_current_env_id());
DROP POLICY IF EXISTS consent_revocations_insert ON fdx.consent_revocations;
CREATE POLICY consent_revocations_insert ON fdx.consent_revocations FOR INSERT
    WITH CHECK (sentin8_context_initialized() AND env_id = sentin8_current_env_id());

-- FC-5: Payment network identifier revocations (per paymentNetworkId).
CREATE TABLE IF NOT EXISTS fdx.payment_network_revocations (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    env_id  UUID NOT NULL,
    account_id          UUID NOT NULL,
    payment_network_id  TEXT NOT NULL,
    reason              TEXT NOT NULL CHECK (reason IN ('BUSINESS_RULE', 'OTHER', 'SECURITY_EVENT', 'USER_ACTION')),
    other_reason        TEXT,
    initiator           TEXT NOT NULL CHECK (initiator IN (
        'DATA_ACCESS_PLATFORM', 'DATA_PROVIDER', 'DATA_RECIPIENT',
        'INDIVIDUAL', 'MERCHANT', 'TOKEN_ISSUER', 'VENDOR'
    )),
    revoked_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);
ALTER TABLE fdx.payment_network_revocations ENABLE ROW LEVEL SECURITY;
ALTER TABLE fdx.payment_network_revocations FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS pn_revocations_select ON fdx.payment_network_revocations;
CREATE POLICY pn_revocations_select ON fdx.payment_network_revocations FOR SELECT
    USING (sentin8_context_initialized() AND env_id = sentin8_current_env_id());
DROP POLICY IF EXISTS pn_revocations_insert ON fdx.payment_network_revocations;
CREATE POLICY pn_revocations_insert ON fdx.payment_network_revocations FOR INSERT
    WITH CHECK (sentin8_context_initialized() AND env_id = sentin8_current_env_id());

-- ── Local outbox (DBX, architecture-principles §6.7) ─────────────────────
-- Producer path: fdx rows are appended to the outbox in the SAME
-- transaction as the domain change (or via the pool helper on handlers
-- without an open transaction); the shell's post-commit relay pushes them
-- to Bus POST /v1/produce (idempotency_key = row id).
-- Generated from sentin8-outbox::outbox_table_sql("fdx") - the outbox lives
-- in the service's OWN leaf schema (`fdx`), matching the relay's notify
-- channel (`fdx_outbox_changed`) and the search_path-derived table
-- resolution; the fdx_* domain tables live in the SAME schema `fdx`
-- (schema-per-service - the leaf schema is the service's primary schema).
CREATE TABLE IF NOT EXISTS fdx.outbox (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    env_id          UUID NOT NULL,
    event_type      TEXT NOT NULL,
    stream_family   TEXT NOT NULL,
    payload         JSONB NOT NULL,
    publisher_id_token  TEXT,
    publisher_subject   TEXT,
    relayed         BOOLEAN NOT NULL DEFAULT false,
    relayed_at      TIMESTAMPTZ,
    relay_attempts  INT NOT NULL DEFAULT 0,
    next_retry_at   TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_fdx_outbox_unrelayed
    ON fdx.outbox (created_at) WHERE relayed = false;
ALTER TABLE fdx.outbox ENABLE ROW LEVEL SECURITY;
ALTER TABLE fdx.outbox FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS outbox_select ON fdx.outbox;
CREATE POLICY outbox_select ON fdx.outbox FOR SELECT
    USING (sentin8_context_initialized() AND env_id = sentin8_current_env_id());
DROP POLICY IF EXISTS outbox_insert ON fdx.outbox;
CREATE POLICY outbox_insert ON fdx.outbox FOR INSERT
    WITH CHECK (sentin8_context_initialized() AND env_id = sentin8_current_env_id());
DROP POLICY IF EXISTS outbox_update ON fdx.outbox;
CREATE POLICY outbox_update ON fdx.outbox FOR UPDATE
    USING (sentin8_context_initialized() AND env_id = sentin8_current_env_id());
CREATE OR REPLACE FUNCTION fdx.fdx_notify_outbox() RETURNS TRIGGER
LANGUAGE plpgsql AS $fn$
BEGIN
    PERFORM pg_notify('fdx_outbox_changed', '');
    RETURN NEW;
END;
$fn$;
DROP TRIGGER IF EXISTS fdx_outbox_notify_trigger ON fdx.outbox;
CREATE TRIGGER fdx_outbox_notify_trigger
    AFTER INSERT ON fdx.outbox
    FOR EACH ROW
    EXECUTE FUNCTION fdx.fdx_notify_outbox();

-- ── Local audit journal (DBX §6.8) ────────────────────────────────────────
-- Spill journal for the canonical audit push: rows written same-tx as the
-- domain change, pushed to Sys POST /v1/audit (sentin8:sys:audit:write), then
-- marked pushed. A Sys outage never drops audit.
-- Generated from sentin8-audit::audit_journal_sql("fdx").
CREATE TABLE IF NOT EXISTS fdx.audit_journal (
    id              UUID PRIMARY KEY,
    env_id          UUID NOT NULL,
    action          TEXT NOT NULL,
    target_resource_type TEXT,
    target_resource_id    TEXT,
    actor_user_id   TEXT,
    actor_subject_type TEXT,
    severity        TEXT NOT NULL DEFAULT 'info',
    correlation_id  TEXT,
    before_state    JSONB,
    after_state     JSONB,
    details         JSONB,
    pushed          BOOLEAN NOT NULL DEFAULT false,
    pushed_at       TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_fdx_audit_journal_unpushed
    ON fdx.audit_journal (created_at) WHERE pushed = false;
ALTER TABLE fdx.audit_journal ENABLE ROW LEVEL SECURITY;
ALTER TABLE fdx.audit_journal FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS audit_journal_dml ON fdx.audit_journal;
CREATE POLICY audit_journal_dml ON fdx.audit_journal
    USING (sentin8_context_initialized() AND env_id = sentin8_current_env_id())
    WITH CHECK (sentin8_context_initialized() AND env_id = sentin8_current_env_id());

-- ── Per-service role grants + search_path (F1 - §4.3e) ──────────────────
-- The fdx service connects via its own PostgreSQL role (bank8_fdx_service,
-- created + granted by `sentin8-cli vertical init/enroll` from this
-- service's --print-registration --section=pg_roles). RLS only ENFORCES
-- when the service does NOT bypass it. These grants give the role table
-- access; the RLS policies scope the rows.
-- The search_path puts the service's OWN schema FIRST (outbox/audit_journal
-- resolution for the shell's relay + journal pusher; unqualified fdx_*
-- domain tables resolve here too), then public (RLS helpers). The
-- `vertical enroll` never-clobber block preserves this role-level setting.
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'bank8_fdx_service') THEN
        ALTER ROLE bank8_fdx_service SET search_path = fdx, public;
        GRANT USAGE ON SCHEMA fdx TO bank8_fdx_service;
        GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA fdx TO bank8_fdx_service;
        GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA fdx TO bank8_fdx_service;
    END IF;
END $$;

-- ============================================================
-- Migration: Phase3Hardening
-- Date: 2026-05-07
--
-- Applies Phase 3 security + resilience schema additions:
--   1. federation_dispatches        — durable backchannel logout queue
--   2. federation_dispatch_attempts — per-attempt audit trail
--   3. client_secrets               — versioned secret rotation
--   4. replay_cache_entries         — generic replay-protection store
--
-- All CREATE TABLE operations are idempotent (IF NOT EXISTS).
-- ============================================================

-- ── 1. federation_dispatches ─────────────────────────────────────────────────
--
-- One row per (GlobalSession × App) logout delivery job.
-- Persisted before first delivery attempt so no event is lost during crashes.

CREATE TABLE IF NOT EXISTS federation_dispatches (
    "Id"                   UUID        NOT NULL DEFAULT gen_random_uuid() PRIMARY KEY,
    "GlobalSessionId"      UUID        NOT NULL,
    "Sid"                  VARCHAR(256) NOT NULL,
    "AppName"              VARCHAR(200) NOT NULL,
    "BackchannelLogoutUri" VARCHAR(2048) NOT NULL,
    "LogoutToken"          TEXT         NOT NULL,
    "Status"               INT          NOT NULL DEFAULT 0,   -- 0=Pending,1=Delivered,2=Failed,3=DeadLetter
    "AttemptCount"         INT          NOT NULL DEFAULT 0,
    "LastAttemptAt"        TIMESTAMPTZ,
    "NextAttemptAt"        TIMESTAMPTZ  DEFAULT NOW(),
    "DeliveredAt"          TIMESTAMPTZ,
    "DeadLetterAt"         TIMESTAMPTZ,
    "DispatchId"           VARCHAR(64)  NOT NULL,
    "CreatedAt"            TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_federation_dispatches_status
    ON federation_dispatches ("Status");

CREATE INDEX IF NOT EXISTS idx_federation_dispatches_next_attempt
    ON federation_dispatches ("NextAttemptAt");

CREATE INDEX IF NOT EXISTS idx_federation_dispatches_session
    ON federation_dispatches ("GlobalSessionId");

-- ── 2. federation_dispatch_attempts ──────────────────────────────────────────
--
-- Full audit trail of each HTTP delivery attempt (for debugging dead-letters).

CREATE TABLE IF NOT EXISTS federation_dispatch_attempts (
    "Id"                   UUID        NOT NULL DEFAULT gen_random_uuid() PRIMARY KEY,
    "FederationDispatchId" UUID        NOT NULL REFERENCES federation_dispatches ("Id") ON DELETE CASCADE,
    "AttemptedAt"          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    "HttpStatusCode"       INT         NOT NULL DEFAULT 0,
    "Success"              BOOLEAN     NOT NULL DEFAULT FALSE,
    "ErrorMessage"         VARCHAR(1000),
    "DurationMs"           BIGINT      NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_federation_dispatch_attempts_dispatch
    ON federation_dispatch_attempts ("FederationDispatchId");

-- ── 3. client_secrets ────────────────────────────────────────────────────────
--
-- Versioned secrets supporting overlap windows during rotation.
-- Multiple active rows per client allow graceful transition periods.

CREATE TABLE IF NOT EXISTS client_secrets (
    "Id"               UUID        NOT NULL DEFAULT gen_random_uuid() PRIMARY KEY,
    "ClientInternalId" UUID        NOT NULL REFERENCES oauth_clients ("Id") ON DELETE CASCADE,
    "SecretHash"       TEXT        NOT NULL,
    "SecretHint"       VARCHAR(20) NOT NULL,
    "Version"          INT         NOT NULL DEFAULT 1,
    "IsActive"         BOOLEAN     NOT NULL DEFAULT TRUE,
    "CreatedAt"        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    "ExpiresAt"        TIMESTAMPTZ,
    "RevokedAt"        TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_client_secrets_client_active
    ON client_secrets ("ClientInternalId", "IsActive");

-- ── 4. replay_cache_entries ───────────────────────────────────────────────────
--
-- Generic idempotency store for short-lived identifiers (auth codes, nonces, etc.).
-- JTIs for logout tokens continue to use the dedicated logout_token_jtis table.
-- SessionCleanupService prunes expired rows every 30 minutes.

CREATE TABLE IF NOT EXISTS replay_cache_entries (
    "Id"         UUID         NOT NULL DEFAULT gen_random_uuid() PRIMARY KEY,
    "EntryKey"   VARCHAR(512) NOT NULL,   -- "{bucket}:{key}" composite
    "Bucket"     VARCHAR(100) NOT NULL,
    "RecordedAt" TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    "ExpiresAt"  TIMESTAMPTZ  NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS uq_replay_cache_entries_key
    ON replay_cache_entries ("EntryKey");

CREATE INDEX IF NOT EXISTS idx_replay_cache_entries_expires
    ON replay_cache_entries ("ExpiresAt");

-- ── 5. consent_grants — add version index (Phase 2 added columns, add index now) ──

CREATE INDEX IF NOT EXISTS idx_consent_grants_user_client_version
    ON consent_grants ("UserId", "ClientId", "ConsentVersion");

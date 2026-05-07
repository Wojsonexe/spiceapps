-- ============================================================
-- Migration: Phase2Hardening
-- Date: 2026-05-07
--
-- Applies Phase 2 production-hardening schema changes:
--   1. GlobalSession  — DeviceFingerprint, Location columns
--   2. ConsentGrant   — ConsentVersion, LastUsedAt columns
--   3. OAuthClient    — FirstParty, ConsentVersion columns
--
-- All operations are idempotent (IF NOT EXISTS / DO NOTHING).
-- ============================================================

-- ── GlobalSession: device fingerprint + geo hint ─────────────────────────────

ALTER TABLE global_sessions
    ADD COLUMN IF NOT EXISTS "DeviceFingerprint" VARCHAR(256),
    ADD COLUMN IF NOT EXISTS "Location"          VARCHAR(200);

-- ── ConsentGrant: versioning + last-used tracking ────────────────────────────

ALTER TABLE consent_grants
    ADD COLUMN IF NOT EXISTS "ConsentVersion" INT         NOT NULL DEFAULT 1,
    ADD COLUMN IF NOT EXISTS "LastUsedAt"     TIMESTAMPTZ;

-- ── OAuthClient: first-party flag + consent version ──────────────────────────

ALTER TABLE oauth_clients
    ADD COLUMN IF NOT EXISTS "FirstParty"     BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS "ConsentVersion" INT     NOT NULL DEFAULT 1;

-- ── Index: consent_grants version lookup ─────────────────────────────────────

CREATE INDEX IF NOT EXISTS "IX_consent_grants_UserId_ClientId_ConsentVersion"
    ON consent_grants ("UserId", "ClientId", "ConsentVersion");

-- ── Index: global_sessions location/fingerprint (optional, for analytics) ────

CREATE INDEX IF NOT EXISTS "IX_global_sessions_CreatedAt"
    ON global_sessions ("CreatedAt");

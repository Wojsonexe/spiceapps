-- ============================================================
-- Migration: Phase3JK
-- Date: 2026-05-07
--
-- Phase 3J — JWKS key rotation: IsPrimary column on signing_keys
-- Phase 3K — Client secret lifecycle: new client_secrets schema
--
-- All operations are idempotent (IF NOT EXISTS / IF COLUMN NOT EXISTS).
-- ============================================================

-- ── Phase 3J: signing_keys.IsPrimary ─────────────────────────────────────────

ALTER TABLE signing_keys
    ADD COLUMN IF NOT EXISTS "IsPrimary" BOOLEAN NOT NULL DEFAULT FALSE;

-- Promote the most-recently-created active key to primary (one-time bootstrap).
-- If there is already exactly one active key, it becomes the primary.
-- If there are multiple active keys, the newest wins.
UPDATE signing_keys
SET    "IsPrimary" = TRUE
WHERE  id = (
    SELECT id
    FROM   signing_keys
    WHERE  "IsActive" = TRUE
    ORDER  BY "CreatedAt" DESC
    LIMIT  1
)
AND NOT EXISTS (
    SELECT 1 FROM signing_keys WHERE "IsPrimary" = TRUE
);

CREATE INDEX IF NOT EXISTS idx_signing_keys_primary
    ON signing_keys ("IsActive", "IsPrimary", "ExpiresAt");

-- ── Phase 3K: client_secrets — drop & recreate with new schema ───────────────
--
-- The table was freshly created in 20260507000002; no production data exists.
-- We drop and recreate to avoid complex ALTER chains.

DROP TABLE IF EXISTS client_secrets;

CREATE TABLE client_secrets (
    "Id"               UUID         NOT NULL DEFAULT gen_random_uuid() PRIMARY KEY,
    "ClientInternalId" UUID         NOT NULL REFERENCES oauth_clients ("Id") ON DELETE CASCADE,
    "Name"             VARCHAR(200),
    "Prefix"           VARCHAR(32)  NOT NULL,
    "SecretHash"       TEXT         NOT NULL,
    "IsActive"         BOOLEAN      NOT NULL DEFAULT TRUE,
    "CreatedAt"        TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    "ExpiresAt"        TIMESTAMPTZ,
    "RevokedAt"        TIMESTAMPTZ,
    "LastUsedAt"       TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_client_secrets_prefix
    ON client_secrets ("Prefix");

CREATE INDEX IF NOT EXISTS idx_client_secrets_client_active
    ON client_secrets ("ClientInternalId", "IsActive");

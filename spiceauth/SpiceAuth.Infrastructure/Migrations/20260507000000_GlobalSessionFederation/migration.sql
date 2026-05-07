-- ============================================================
-- Migration: GlobalSessionFederation
-- Date: 2026-05-07
--
-- Adds federation core: GlobalSession, AppSession,
-- logout jti replay store, and tenant foundation.
-- All operations are idempotent (IF NOT EXISTS / IF EXISTS).
-- ============================================================

-- ── global_sessions ──────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS global_sessions (
    "Id"             UUID         NOT NULL DEFAULT gen_random_uuid(),
    "Sid"            VARCHAR(256) NOT NULL,
    "UserId"         UUID         NOT NULL,
    "CreatedAt"      TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    "ExpiresAt"      TIMESTAMPTZ  NOT NULL,
    "RevokedAt"      TIMESTAMPTZ,
    "LastActivityAt" TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    "IpAddress"      VARCHAR(64),
    "UserAgent"      VARCHAR(512),

    CONSTRAINT "PK_global_sessions" PRIMARY KEY ("Id")
);

CREATE UNIQUE INDEX IF NOT EXISTS "IX_global_sessions_Sid"
    ON global_sessions ("Sid");

CREATE INDEX IF NOT EXISTS "IX_global_sessions_UserId"
    ON global_sessions ("UserId");

CREATE INDEX IF NOT EXISTS "IX_global_sessions_ExpiresAt"
    ON global_sessions ("ExpiresAt");

CREATE INDEX IF NOT EXISTS "IX_global_sessions_UserId_RevokedAt"
    ON global_sessions ("UserId", "RevokedAt");

-- ── app_sessions ──────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS app_sessions (
    "Id"                  UUID         NOT NULL DEFAULT gen_random_uuid(),
    "GlobalSessionId"     UUID         NOT NULL,
    "AppName"             VARCHAR(200) NOT NULL,
    "LocalSessionId"      VARCHAR(512),
    "BackchannelLogoutUri" VARCHAR(2048) NOT NULL,
    "RegisteredAt"        TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    "LastSeenAt"          TIMESTAMPTZ  NOT NULL DEFAULT NOW(),

    CONSTRAINT "PK_app_sessions" PRIMARY KEY ("Id"),

    CONSTRAINT "FK_app_sessions_GlobalSessionId"
        FOREIGN KEY ("GlobalSessionId")
        REFERENCES global_sessions ("Id")
        ON DELETE CASCADE
);

CREATE UNIQUE INDEX IF NOT EXISTS "IX_app_sessions_GlobalSessionId_AppName"
    ON app_sessions ("GlobalSessionId", "AppName");

CREATE INDEX IF NOT EXISTS "IX_app_sessions_GlobalSessionId"
    ON app_sessions ("GlobalSessionId");

-- ── logout_token_jtis ─────────────────────────────────────────────────────────
-- Replay-protection store. Entries are TTL-cleaned by SessionCleanupService.

CREATE TABLE IF NOT EXISTS logout_token_jtis (
    "Jti"    VARCHAR(256) NOT NULL,
    "UsedAt" TIMESTAMPTZ  NOT NULL DEFAULT NOW(),

    CONSTRAINT "PK_logout_token_jtis" PRIMARY KEY ("Jti")
);

CREATE INDEX IF NOT EXISTS "IX_logout_token_jtis_UsedAt"
    ON logout_token_jtis ("UsedAt");

-- ── tenants ───────────────────────────────────────────────────────────────────
-- Nullable tenant foundation. Existing single-tenant flows are unaffected.

CREATE TABLE IF NOT EXISTS tenants (
    "Id"          UUID         NOT NULL DEFAULT gen_random_uuid(),
    "Slug"        VARCHAR(100) NOT NULL,
    "DisplayName" VARCHAR(200) NOT NULL,
    "IsActive"    BOOLEAN      NOT NULL DEFAULT TRUE,
    "CreatedAt"   TIMESTAMPTZ  NOT NULL DEFAULT NOW(),

    CONSTRAINT "PK_tenants" PRIMARY KEY ("Id")
);

CREATE UNIQUE INDEX IF NOT EXISTS "IX_tenants_Slug"
    ON tenants ("Slug");

-- ── tenant_memberships ────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS tenant_memberships (
    "Id"       UUID        NOT NULL DEFAULT gen_random_uuid(),
    "TenantId" UUID        NOT NULL,
    "UserId"   UUID        NOT NULL,
    "Role"     VARCHAR(50) NOT NULL DEFAULT 'member',
    "JoinedAt" TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT "PK_tenant_memberships" PRIMARY KEY ("Id"),

    CONSTRAINT "FK_tenant_memberships_TenantId"
        FOREIGN KEY ("TenantId")
        REFERENCES tenants ("Id")
        ON DELETE CASCADE
);

CREATE UNIQUE INDEX IF NOT EXISTS "IX_tenant_memberships_TenantId_UserId"
    ON tenant_memberships ("TenantId", "UserId");

-- ============================================================
-- Migration: 20260507000005_FamilyIdNotNull
-- Date:      2026-05-07
--
-- FamilyId hardening: make refresh_tokens."FamilyId" NOT NULL.
--
-- Steps:
--   1. Auto-heal any legacy rows that have NULL FamilyId by
--      assigning a fresh UUID per row (each becomes its own family,
--      which is safe because NULL rows cannot have siblings).
--   2. Add NOT NULL constraint.
--
-- Safe to run multiple times (idempotent via DO block check).
-- PostgreSQL only — SQLite does not support ALTER COLUMN.
-- ============================================================

-- ── 1. Auto-heal NULL FamilyId rows ──────────────────────────────────────────

UPDATE refresh_tokens
   SET "FamilyId" = gen_random_uuid()
 WHERE "FamilyId" IS NULL;

-- ── 2. Add NOT NULL constraint ────────────────────────────────────────────────

DO $$ BEGIN
    -- Only run if the column is still nullable
    IF EXISTS (
        SELECT 1
          FROM information_schema.columns
         WHERE table_name  = 'refresh_tokens'
           AND column_name = 'FamilyId'
           AND is_nullable = 'YES'
    ) THEN
        ALTER TABLE refresh_tokens
            ALTER COLUMN "FamilyId" SET NOT NULL;
    END IF;
EXCEPTION WHEN OTHERS THEN
    NULL; -- SQLite: DO blocks not supported, skip gracefully
END $$;

-- ── Notes ─────────────────────────────────────────────────────────────────────
-- After this migration every new refresh token must have FamilyId set.
-- TokenService.GenerateRefreshTokenAsync already guarantees this:
--   var newFamilyId = familyId ?? Guid.NewGuid();
-- The startup auto-heal in Program.cs provides an additional safety net
-- in case this migration is not run before deployment.

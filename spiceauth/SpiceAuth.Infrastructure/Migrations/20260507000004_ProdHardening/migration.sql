-- ============================================================
-- Migration: 20260507000004_ProdHardening
-- Date:      2026-05-07
--
-- Phase 4 — Production hardening indexes and constraints.
--
-- Changes:
--   1. refresh_tokens: add index on FamilyId
--      Used by RevokeTokenFamilyAsync — the security-critical
--      query that revokes an entire token family on reuse detection.
--      Without this index the WHERE FamilyId = @id table scan is O(N).
--
--   2. federation_dispatches: replace two separate indexes with one
--      composite index on (Status, NextAttemptAt, CreatedAt).
--      The worker query is:
--        WHERE (Status=0 OR Status=2) AND NextAttemptAt <= NOW()
--        ORDER BY CreatedAt LIMIT 50
--      A composite index covers the filter + sort in a single scan.
--
-- All operations are idempotent (IF NOT EXISTS).
-- ============================================================

-- ── 1. refresh_tokens.FamilyId index ─────────────────────────────────────────

CREATE INDEX IF NOT EXISTS idx_refresh_tokens_family_id
    ON refresh_tokens ("FamilyId");

-- ── 2. federation_dispatches composite worker-query index ─────────────────────

-- Drop the two separate indexes if they exist (they are superseded)
DROP INDEX IF EXISTS idx_federation_dispatches_status;
DROP INDEX IF EXISTS idx_federation_dispatches_next_attempt;

-- Composite index covering the exact worker query pattern
CREATE INDEX IF NOT EXISTS idx_federation_dispatches_worker
    ON federation_dispatches ("Status", "NextAttemptAt", "CreatedAt");

-- ── 3. replay_cache_entries: add partial index for active entries only ─────────
-- Cleanup query is WHERE ExpiresAt < NOW(); lookup query adds AND ExpiresAt > NOW().
-- A partial index on active entries reduces index size significantly.
-- Note: PostgreSQL partial indexes; skip on SQLite.

DO $$ BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_indexes
        WHERE tablename = 'replay_cache_entries'
          AND indexname  = 'idx_replay_cache_active'
    ) THEN
        CREATE INDEX idx_replay_cache_active
            ON replay_cache_entries ("EntryKey")
            WHERE "ExpiresAt" > NOW();
    END IF;
EXCEPTION WHEN OTHERS THEN
    NULL;  -- SQLite: DO blocks not supported, skip gracefully
END $$;

-- ── 4. audit_logs: add index on action type for security queries ───────────────
-- Enables fast query: SELECT * FROM audit_logs WHERE action_type = X AND timestamp > Y

CREATE INDEX IF NOT EXISTS idx_audit_logs_action_timestamp
    ON audit_logs ("ActionType", "Timestamp");

-- ── Notes ─────────────────────────────────────────────────────────────────────
-- PostgreSQL-specific maintenance recommendations (run as superuser):
--
--   -- replay_cache_entries is high-churn (insert + delete every session)
--   ALTER TABLE replay_cache_entries SET (autovacuum_vacuum_scale_factor = 0.01);
--   ALTER TABLE replay_cache_entries SET (autovacuum_analyze_scale_factor = 0.005);
--
--   -- logout_token_jtis similar pattern
--   ALTER TABLE logout_token_jtis SET (autovacuum_vacuum_scale_factor = 0.01);
--
--   -- federation_dispatch_attempts: append-only, low vacuum pressure
--   -- No tuning needed.

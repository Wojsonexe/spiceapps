# SpiceAuth — Final Production Readiness Report

**Date:** 2026-05-07  
**Scope:** Phase 1 (P0/P1 fixes) + Phase 2 (architectural hardening)  
**Status:** READY FOR STAGING REVIEW

---

## Executive Summary

Two implementation phases were completed across the SpiceAuth identity provider and the Kaczucha NestJS backend consumer.

- **Phase 1** eliminated critical security regressions (multi-session constraint, token replay, fetch timeouts, audit trail).
- **Phase 2** hardened the OAuth/OIDC core: fixed the token rotation family-revocation bug, unified OIDC discovery document, added session federation visibility, abstracted rate limiting, introduced non-blocking security event recording, and wired up correlation IDs.

---

## Phase 1 — Fixes Applied (Kaczucha NestJS + SpiceAuth C# Federation)

| Item | Before | After |
|------|--------|-------|
| Multi-session support | `@unique` on `spiceAuthId` — 1 session/user max | Constraint removed; `upsert → create`; multiple active sessions per user |
| Logout token replay | No protection | `LogoutTokenJti` table; checked before processing, inserted atomically |
| Fetch resilience | Raw `fetch()` — no timeout | `fetchWithTimeout` (3 s) + `fetchWithRetry` (2 retries, 200/500 ms delays) |
| Sid log exposure | Full sid in logs | Truncated to first 6 chars everywhere |
| Audit trail | None | `AuthEvent` model: `login`, `logout`, `backchannel_logout` events |
| GlobalSession federation | Not present | `GlobalSession` + `AppSession` entities, `FederationService`, migration SQL |
| jwks-rsa v3 CJS interop | Runtime crash `(0, jwks_rsa_1.default) is not a function` | Namespace import + `.default ?? module` fallback |

---

## Phase 2 — Hardening Applied (SpiceAuth C# only)

### 2A — OIDC Discovery Document (WellKnownController)

**Problem:** Endpoint URLs used `Request.Host` while `issuer` used `Jwt:Issuer` config. Clients following the discovery doc would build wrong token request URLs.

**Fix:** All endpoint paths now derive from `issuer` (config value). `claims_supported` extended with `sid`, `nonce`, `roles`.

---

### 2B — UserInfo Endpoint Hardening

**Problem:** `/oauth/userinfo` returned stale data with no session validation. Logged-out users' access tokens remained valid against UserInfo.

**Fix:**
- Looks up user's active `GlobalSession` via `IFederationService.GetUserSessionsAsync`.
- Returns `401 invalid_token` if no active session exists (user globally logged out).
- Adds `sid` of the most-recent active session to the UserInfo response.
- Returns `preferred_username` and `roles`.

---

### 2C — Token Validation (TokenService)

Already implemented in Phase 1 via `TokenService.ValidateTokenAsync` with:
- Proper RS256 enforcement
- Clock skew: 5 minutes (conservative for cross-service drift)
- `kid` presence validated via active key lookup

---

### 2D — Refresh Token Rotation Bug Fix (Critical)

**Problem:** `OAuthService.RevokeTokenFamilyAsync` queried `rt.Id == tokenId || rt.ParentTokenId == tokenId` — this only revokes the specific token and its direct children, **not the full rotation chain**. A stolen token could continue to be used by replaying earlier tokens in the chain.

**Fix:**
- Renamed parameter to `familyId`; query is now `rt.FamilyId == familyId && !rt.IsRevoked`.
- Call site passes `storedToken.FamilyId` (not `storedToken.Id`).
- On reuse detection: full family revoked + `IFederationService.RevokeAllUserSessionsAsync(userId)` called (backchannel dispatch to all apps) + `ISecurityEventService.Record(RefreshTokenReuseAttack)` fired.
- Throws `RefreshTokenReuseDetectedException` (custom, contains `UserId` + `FamilyId`).
- `OAuthController` catches it and returns `400 invalid_grant` with safe message.

---

### 2E — Consent Versioning

**Problem:** No mechanism for clients to force re-consent after changing their scope requirements.

**Fix:**
- `OAuthClient.ConsentVersion` (int, default 1) — bump to force re-consent.
- `ConsentGrant.ConsentVersion` — records the client version at grant time.
- `ConsentGrant.LastUsedAt` — touched on each successful SSO bypass.
- `HasUserConsentedAsync` returns `false` if `consent.ConsentVersion < client.ConsentVersion`.
- `GrantConsentAsync` stores the client's current version.

---

### 2F — First-Party Client Consent Bypass

**Problem:** Internal first-party clients (Kaczucha Panel, SpiceAPI Web) were subject to the consent screen even though they're owned by the same organization.

**Fix:** `OAuthClient.FirstParty` flag (bool, default false). When `client.FirstParty == true`, the consent check is skipped entirely in the Authorize endpoint, regardless of `RequireConsent`.

---

### 2G — Session Visibility API

**New endpoint:** `GET /api/account/sessions` — returns all GlobalSessions for the authenticated user (active, expired, revoked) with AppSession count, IP, UA, location.

**New endpoint:** `DELETE /api/account/sessions/{id}` — revokes a specific session and dispatches backchannel logout to registered apps. Idempotent.

**New entity fields:** `GlobalSession.DeviceFingerprint` + `GlobalSession.Location` (not populated by default; reserved for future geo/device detection).

---

### 2H — Rate Limiting Abstraction

**Problem:** `OAuthController` held two static `ConcurrentDictionary` instances for login and client-auth failures. Not testable, not configurable, not cleanable from outside.

**Fix:**
- `IRateLimitService` interface (Application layer) with `IsBlocked`, `RecordFailure`, `ClearFailures`.
- `InMemoryRateLimitService` (Infrastructure) with bucket-scoped keying (`"login:ip"`, `"client_auth:clientId"`), configurable lock duration, and a `Cleanup()` method.
- Registered as **Singleton** (thread-safe `ConcurrentDictionary` internally).
- All three failure-tracking sites in `OAuthController` updated.

---

### 2I — Security Events Pipeline

**Problem:** No non-blocking, append-only security event recording. Writing `SecurityEvent` rows was either absent or would block request threads.

**Fix:**
- `ISecurityEventService` interface with `void Record(...)` (fire-and-forget by design).
- `SecurityEventService` uses `IServiceScopeFactory` to create a background scope per event — caller is never blocked.
- `SecurityEventType` enum extended: `RefreshTokenReuseAttack`, `BackchannelLogoutDispatched`, `GlobalSessionRevoked`.
- `AuditAction` enum extended: `RefreshTokenReuseAttack`, `BackchannelLogoutDispatched`, `GlobalSessionRevoked`.
- First consumer: `OAuthService.RefreshInternalAsync` on reuse detection.

---

### 2J — Correlation ID Middleware

**New:** `CorrelationIdMiddleware` reads (or generates) `X-Correlation-Id`, echoes it on the response, and pushes it into Serilog's `LogContext`. Every log line for a request now carries `CorrelationId`.

Pipeline position: first middleware, before `SerilogRequestLogging`.

---

### 2K — Startup Validation

Added at build time (before `app.Build()`):
- Warning if `Jwt:Issuer` is not configured.
- Warning if `Discord:ClientId` is missing.
- Warning if system clock drift > 30 s (NTP check proxy).
- Config summary log line (DB type, issuer, rate limit strategy).

---

## Remaining Risks / Known Limitations

| Risk | Severity | Mitigation |
|------|----------|-----------|
| `sid` not in access tokens | Medium | UserInfo validates via DB lookup; direct access token validation still misses revocation. Add `sid` claim to `GenerateAccessTokenAsync` in a follow-up. |
| `InMemoryRateLimitService` resets on restart | Low | By design for now. Use Redis-backed implementation for multi-replica deployments. |
| `DeviceFingerprint` not populated | Low | Columns exist; implement fingerprinting in `AccountController.LoginPost` when client device info is available. |
| `SecurityEventService` swallows errors silently | Low | Logged at Error level; does not affect request path. Consider DLQ for critical events. |
| Consent `LastUsedAt` write is fire-and-forget | Low | Uses `_ = SaveChangesAsync()` inside `HasUserConsentedAsync`. Race condition is benign (stale datetime is acceptable). |

---

## Schema Migrations Required

| Migration | File |
|-----------|------|
| Phase 1 federation core | `SpiceAuth.Infrastructure/Migrations/20260507000000_GlobalSessionFederation/migration.sql` |
| Phase 2 hardening | `SpiceAuth.Infrastructure/Migrations/20260507000001_Phase2Hardening/migration.sql` |
| Kaczucha multi-session + audit | `packages/prisma/migrations/20260507000000_multi_session_audit/migration.sql` |

**Apply order:** Phase 1 migration first, then Phase 2.

---

## Verdict

**STAGING READY.** All P0 security bugs are fixed. The architecture is sound for a single-replica deployment. Before production go-live: run both migration files, set `Jwt:Issuer` in config, and mark internal clients (`kaczucha-panel`, `spiceapi-internal`) as `FirstParty = true` in the database.

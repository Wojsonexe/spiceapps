# SpiceAuth ↔ Kaczucha Integration — Session Summary
**Date:** 2026-04-24  
**Branch:** spiceauth/architecture (SpiceAuth) + feature branch (Kaczucha)

---

## Overview

Full OAuth2 Authorization Code + PKCE integration between Kaczucha (NestJS app)
and SpiceAuth (custom OIDC provider). SpiceAuth users now log in to Kaczucha,
receive a session cookie, and have their SpiceAuth roles visible in the app.

---

## Repository: spiceapps/spiceauth

### 1. `SpiceAuth.API/Controllers/AdminController.cs`
**Added role management endpoints** (all require `[Authorize(Roles = "Admin")]`):

| Endpoint | Description |
|---|---|
| `GET /api/admin/roles` | List all custom roles in SpiceAuth |
| `GET /api/admin/users/{id}/roles` | Get roles assigned to a user |
| `POST /api/admin/users/{id}/roles/{roleName}` | Assign a role to a user |
| `DELETE /api/admin/users/{id}/roles/{roleName}` | Remove a role from a user |

Previously `AdminController` had no role management. Roles are from the custom
`roles` / `user_roles` tables (not ASP.NET Identity `asp_roles`).

### 2. `spiceauth-admin/src/lib/api.ts`
**Added `adminApi`** with methods:
- `getUsers`, `getUser`, `getRoles`, `getUserRoles`
- `assignRole(userId, roleName)`, `removeRole(userId, roleName)`
- `suspendUser`, `activateUser`

### 3. `spiceauth-admin/src/hooks/use-users.ts` *(new file)*
React Query hooks: `useUser`, `useAllRoles`, `useUserRoles`, `useAssignRole`, `useRemoveRole`.

### 4. `spiceauth-admin/src/app/(panel)/users/[id]/page.tsx` *(was 0 bytes)*
Built full user detail page:
- User info card (name, email, status badges)
- Role management: all SpiceAuth roles listed with toggle buttons
- Assign/remove role on click, invalidates query cache

---

## Repository: SpiceGears/Kaczucha

### 1. `apps/backend/.env`
**Fixed `SPICEAUTH_REDIRECT_URI`** — two bugs corrected:
- Port: `3001` → `5001` (backend runs on 5001)
- Path: `/api/auth/spice/callback` → `/api/auth/spiceauth/callback`

**Updated OAuth client credentials** (registered fresh client in SpiceAuth):
- `SPICEAUTH_CLIENT_ID=520c0607fae344dd875b6fad7fb79a9d`
- `SPICEAUTH_CLIENT_SECRET=dJGd/QNBka9H5ghXwjE13Pf23l4ypM4kjetk257d7m0=`
- Removed stray quotes from old secret value

### 2. `apps/backend/src/auth/spiceauth.controller.ts`
**Three changes:**

a) Added `private readonly isProduction: boolean` field + init in constructor  
b) Added `secure: this.isProduction` to `session_id` cookie (consistency with `auth.controller.ts`)  
c) **Save SpiceAuth roles at login:** userinfo response already includes `roles[]`.
   Upsert now stores them:
   ```ts
   roles: { spiceauth: spiceRoles }   // in both create and update
   ```
   Roles are refreshed on every login.

### 3. `apps/backend/src/auth/auth.controller.ts`
**`GET /auth/check` — split role resolution by session type:**

- `session.discordId` → unchanged: `prisma.user.findUnique` → Kaczucha `user_roles`
- `session.spiceAuthId` → reads `session.roles.spiceauth` (JSON), maps to
  `{ role: { name, displayName, permissions: [] } }` shape

SpiceAuth users now get real roles in `/auth/check` response instead of `[]`.

---

## Already in Place (confirmed, no changes needed)

| Item | Status |
|---|---|
| `SpiceAuthController` registered in `auth.module.ts` | ✅ |
| `/oauth/userinfo` endpoint path correct in SpiceAuth | ✅ |
| `UserSession.spiceAuthId @unique` in Prisma schema | ✅ |
| Migration `20260404184805_add_spiceauth_session` applied | ✅ |
| `UserSession.roles Json @default("{}")` in schema | ✅ |
| `auth.api.ts loginWithSpiceAuth()` → `GET /auth/spiceauth` | ✅ |
| Login page has "Zaloguj się przez SpiceAuth" button | ✅ |
| SpiceAuth runs on port 5045 (confirmed via launchSettings.json) | ✅ |

---

## Remaining: Seed SpiceAuth Custom Roles

The `roles` table in SpiceAuth DB is empty. ASP.NET Identity `asp_roles` has
"Admin" and "User", but those are separate from the custom `roles` table used
by the admin panel and returned in userinfo.

**Run this SQL in psql / pgAdmin against the SpiceAuth database:**

```sql
INSERT INTO roles ("Id", "Name", "NormalizedName", "Description", "IsSystemRole", "Permissions", "CreatedAt")
VALUES
  (gen_random_uuid(), 'MECHANICY',    'MECHANICY',    'Dział mechaniczny',    false, NULL, NOW()),
  (gen_random_uuid(), 'PROGRAMISCI',  'PROGRAMISCI',  'Dział programowania',  false, NULL, NOW()),
  (gen_random_uuid(), 'SOCIAL_MEDIA', 'SOCIAL_MEDIA', 'Social media',         false, NULL, NOW()),
  (gen_random_uuid(), 'MENTORZY',     'MENTORZY',     'Mentorzy',             false, NULL, NOW()),
  (gen_random_uuid(), 'KAPITANOWIE',  'KAPITANOWIE',  'Kapitanowie',          false, NULL, NOW()),
  (gen_random_uuid(), 'MARKETING',    'MARKETING',    'Marketing',            false, NULL, NOW());
```

After inserting: go to `localhost:5045` (spiceauth-admin), navigate to
Users → select a user → assign roles via the new toggle UI.

---

## End-to-End Login Flow (after all changes)

```
1. User clicks "Zaloguj się przez SpiceAuth" on Kaczucha /login
2. Frontend → GET /auth/spiceauth (Kaczucha backend)
3. Backend generates state + PKCE verifier/challenge, stores in httpOnly cookies
4. Backend redirects → SpiceAuth /api/oauth/authorize?...&code_challenge=...
5. User logs in at SpiceAuth, grants consent
6. SpiceAuth redirects → GET /auth/spiceauth/callback?code=...&state=...
7. Backend verifies state, exchanges code + verifier for tokens
8. Backend calls /oauth/userinfo → gets { sub, email, roles: ["MECHANICY", ...] }
9. UserSession upserted with roles: { spiceauth: ["MECHANICY", ...] }
10. session_id cookie set on browser
11. Frontend GET /auth/check → session validated → roles read from session.roles
12. Auth store populated: user + roles visible in Kaczucha UI
```

---

## Files Changed

### spiceapps/spiceauth
```
SpiceAuth.API/Controllers/AdminController.cs          — role endpoints added
spiceauth-admin/src/lib/api.ts                        — adminApi added
spiceauth-admin/src/hooks/use-users.ts                — new file
spiceauth-admin/src/app/(panel)/users/[id]/page.tsx   — built from 0 bytes
```

### SpiceGears/Kaczucha
```
apps/backend/.env                                     — REDIRECT_URI + CLIENT_ID/SECRET
apps/backend/src/auth/spiceauth.controller.ts         — secure cookie + save roles
apps/backend/src/auth/auth.controller.ts              — /check reads SpiceAuth roles
```

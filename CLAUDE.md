# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```bash
npm run dev          # local dev server (localhost:3000)
npm run build        # static export to out/
npm run lint         # ESLint via next lint
npm run type-check   # tsc --noEmit (no tests exist yet)
```

There are no automated tests. Verify behaviour manually with `npm run dev`.

## Architecture

**PropSpace** is a Telegram Mini App for real estate management. It is a **static SPA** (Next.js 15 `output: 'export'`) deployed to Vercel. Because it is fully static, all `NEXT_PUBLIC_*` environment variables are baked in at build time — changing them requires a Vercel redeploy.

### Client-side navigation

There is **no Next.js router**. Navigation is a simple state machine in `src/store/appStore.ts` (Zustand). `src/app/page.tsx` renders a `switch` over `store.screen` and lazy-loads the matching screen component. `store.history` is a stack; `store.back()` pops it. The Telegram `BackButton` is wired to `store.back()` in `page.tsx`.

To navigate: `useAppStore().navigate('db-list', { dbId: '...' })`.  
To read params: `useAppStore().screenParams.dbId`.

### Screen pattern

Every file in `src/screens/` is a self-contained screen component. Screens pull their own data (Supabase hooks) and call `navigate()` / `back()` directly. There are no layout wrappers — each screen renders its full UI including header and bottom bar.

### Auth flow

1. `SplashScreen` calls `restoreSession()` from `useAuth` → tries `supabase.auth.getSession()`, links session to `public.users` via `tg_id` extracted from the email `{tgId}@telegram.propspace.app`.
2. If no session → `WelcomeScreen` calls `loginViaTelegram(window.Telegram.WebApp.initData)`.
3. The Edge Function (`supabase/functions/telegram-auth/index.ts`) validates the HMAC-SHA256 Telegram signature, upserts the user in `public.users`, then uses `admin.generateLink` + `verifyOtp` to produce a real Supabase JWT.
4. On return: `setSession(access_token, refresh_token)` → `setUser(user)` → navigate based on `user.role`.

`public.users.id` (UUID) ≠ `auth.users.id`. The link is `tg_id` stored as the auth email prefix.

### Supabase client

`src/lib/supabase.ts` exports a lazy `supabase` proxy. It initialises `createClient` only once on first property access, avoiding SSR issues. Always import from `@/lib/supabase`, never construct a client inline.

### Edge Function

`supabase/functions/telegram-auth/index.ts` runs on Deno v2. Use `Deno.serve(async (req) => { ... })` — the old `serve()` from `deno.land/std@0.168.0` is incompatible and causes EarlyDrop. Pass `tg_id` to Supabase queries as `parseInt(tgUser.id, 10)` (BIGINT column rejects string comparisons with a PostgrestError).

Session creation uses `admin.createUser({ email, password, email_confirm: true })` + `signInWithPassword`, **not** `generateLink`/`verifyOtp`. The password is derived deterministically via `HMAC(SERVICE_KEY, email)` and never leaves the function. This avoids any dependency on Supabase's email-sending provider being enabled (which made `generateLink` fail with "Database error saving new user").

Deploying the Edge Function requires `SUPABASE_ACCESS_TOKEN` in GitHub repository secrets. Push to `main` or `claude/lucid-planck-Hjo1u` with changes under `supabase/functions/**` to trigger `.github/workflows/deploy-edge-function.yml`.

### Database schema & migrations

`supabase/migrations/` holds three files: `001_schema.sql` (canonical fresh schema), `002_rls.sql` (RLS + the `current_app_user_id()` helper), and `003_reconcile.sql` (idempotent — brings any existing/legacy DB up to spec and removes legacy artifacts).

Two non-obvious things that broke auth historically and must stay correct:
1. **`current_app_user_id()` resolves identity from the JWT *email* claim**, not a `tg_id` claim (Supabase doesn't add custom claims here). Email is `{tgId}@telegram.propspace.app`; the helper parses tg_id from it. A `tg_id`-claim version silently returns NULL → every RLS check fails → empty data everywhere.
2. **No `handle_new_user` trigger may exist on `auth.users`.** The Supabase starter template installs one that inserts into `public.users` with stale column names; it makes GoTrue fail with "Database error creating new user". `003_reconcile.sql` drops it. The edge function is the only thing that writes `public.users`.

The container running Claude Code on the web has **no outbound network** (Supabase host returns 403), so migrations cannot be pushed from here. Apply schema changes by running the SQL in the Supabase dashboard SQL Editor, or via the `migrate.yml` workflow on push to `main`.

### Roles

- `owner` — creates and manages property databases; sees `db-list` after login.
- `realtor` — subscribes to owner databases via share token; sees `realtor-dashboard` after login.
- New users get `role: 'owner'` by default but are sent to `role-select` if `user.role` is falsy.

### Environment variables

| Variable | Where used |
|---|---|
| `NEXT_PUBLIC_SUPABASE_URL` | frontend fetch + supabase client |
| `NEXT_PUBLIC_SUPABASE_ANON_KEY` | frontend supabase client |
| `SUPABASE_SERVICE_ROLE_KEY` | Edge Function only (Deno env) |
| `TELEGRAM_BOT_TOKEN` | Edge Function HMAC validation |

Frontend env vars must be set in Vercel project settings before building. Edge Function env vars are set in the Supabase dashboard under Project Settings → Edge Functions.

### Security rules (enforce always)

1. **Never expose internal errors to clients.** Edge Function 500 responses must not include stack traces or `detail` fields — log server-side only.
2. **RLS on every table.** Every `CREATE TABLE` must be followed by `ALTER TABLE … ENABLE ROW LEVEL SECURITY`. Use `current_app_user_id()` (not `auth.uid()`) — the JWT email claim is the identity source.
3. **No self-escalation.** The `prevent_privilege_escalation` trigger blocks users from modifying their own `plan`/`role`. Never call `updateProfile({ plan, role })` from the client — strip those fields before the query.
4. **initData must be HMAC-validated server-side.** Never trust `initDataUnsafe` alone. The Edge Function validates the full Telegram HMAC-SHA256 signature before issuing any JWT.
5. **Share tokens expire server-side.** The `db_share_lookup` RLS policy enforces `share_expires_at > now()`. Client-side expiry checks are UX only.
6. **Storage paths are per-property.** Upload paths are `{propertyId}/{timestamp}_{rand}.{ext}`. Never allow user-controlled path segments.
7. **SQL injections are impossible** via PostgREST parameterised queries — never build raw SQL strings with user input.

### Code style

- **TypeScript strict** — no `any` except where Telegram SDK types are unavailable (annotate with `// deno-lint-ignore no-explicit-any`).
- **No inline Supabase client construction** — always import from `@/lib/supabase`.
- **Explicit column lists in SELECT** — avoid `select('*')` in list views; fetch only columns the screen renders.
- **Derive state, don't sync it** — prefer computed values from existing state over extra `useState` booleans (e.g. `done = queue.every(...)`).
- **No comments that describe what code does** — only comments that explain non-obvious WHY (hidden constraints, workarounds).
- **Error handling at boundaries only** — validate at API/user-input boundaries; trust internal code and RLS.

### Remote session (Claude Code on the web)

The session-start hook (`.claude/hooks/session-start.sh`) runs `npm install` and, if `GH_PAT` env var is set, rewrites the git remote to embed the token so pushes work. Set `GH_PAT` in session Environment Variables via the Claude Code web UI.

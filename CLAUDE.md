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

Deploying the Edge Function requires `SUPABASE_ACCESS_TOKEN` in GitHub repository secrets. Push to `main` or `claude/lucid-planck-Hjo1u` with changes under `supabase/functions/**` to trigger `.github/workflows/deploy-edge-function.yml`.

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

### Remote session (Claude Code on the web)

The session-start hook (`.claude/hooks/session-start.sh`) runs `npm install` and, if `GH_PAT` env var is set, rewrites the git remote to embed the token so pushes work. Set `GH_PAT` in session Environment Variables via the Claude Code web UI.

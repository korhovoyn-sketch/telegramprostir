import type { Page, Route } from '@playwright/test'

export interface HarnessUser {
  id: string
  tg_id: number
  first_name: string
  last_name?: string
  tg_username?: string
  role: 'owner' | 'realtor' | null
  language_code: string
  currency: string
  plan: 'free' | 'pro'
}

export const DEFAULT_USER: HarnessUser = {
  id: '00000000-0000-0000-0000-000000000001',
  tg_id: 111222333,
  first_name: 'Test',
  tg_username: 'tester',
  role: null,
  language_code: 'uk',
  currency: 'USD',
  plan: 'free',
}

// A structurally valid, decodable (unsigned) JWT with a future exp so
// supabase-js setSession() accepts it without a network round-trip.
function makeJwt(user: HarnessUser): string {
  const enc = (o: unknown) => Buffer.from(JSON.stringify(o)).toString('base64url')
  const header = { alg: 'HS256', typ: 'JWT' }
  const payload = {
    sub: user.id,
    email: `${user.tg_id}@telegram.propspace.app`,
    aud: 'authenticated',
    role: 'authenticated',
    iat: Math.floor(Date.now() / 1000),
    exp: Math.floor(Date.now() / 1000) + 3600,
  }
  return `${enc(header)}.${enc(payload)}.sig`
}

export interface HarnessOptions {
  user?: HarnessUser
  /** Suppress auto-login so the idle Welcome screen is shown (fromLogout param). */
  noAutoLogin?: boolean
  startParam?: string
  /** ms delay before the Edge Function login responds (to observe the loading UI). */
  loginDelayMs?: number
}

/** Inject window.Telegram.WebApp before any app script runs. */
export async function installTelegram(page: Page, opts: HarnessOptions = {}) {
  const user = opts.user ?? DEFAULT_USER
  await page.addInitScript(
    ({ tgId, firstName, username, startParam }) => {
      const cloud = new Map<string, string>()
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      ;(window as any).Telegram = {
        WebApp: {
          initData: 'mock_init_data_signed',
          initDataUnsafe: { user: { id: tgId, first_name: firstName, username }, start_param: startParam },
          colorScheme: 'dark',
          viewportHeight: 568,
          viewportStableHeight: 568,
          ready() {}, expand() {}, close() {},
          enableClosingConfirmation() {}, disableClosingConfirmation() {},
          setHeaderColor() {}, setBackgroundColor() {}, disableVerticalSwipes() {},
          openTelegramLink() {}, onEvent() {}, offEvent() {},
          BackButton: { isVisible: false, show() { this.isVisible = true }, hide() { this.isVisible = false }, onClick() {}, offClick() {} },
          HapticFeedback: { impactOccurred() {}, notificationOccurred() {}, selectionChanged() {} },
          CloudStorage: {
            getItem: (k: string, cb: (e: unknown, v: string | null) => void) => cb(null, cloud.get(k) ?? null),
            setItem: (k: string, v: string, cb?: (e: unknown, ok: boolean) => void) => { cloud.set(k, v); cb?.(null, true) },
            removeItem: (k: string, cb?: (e: unknown, ok: boolean) => void) => { cloud.delete(k); cb?.(null, true) },
          },
        },
      }
    },
    { tgId: user.tg_id, firstName: user.first_name, username: user.tg_username, startParam: opts.startParam },
  )
}

/** Intercept every Supabase REST / Auth / Edge call with deterministic fixtures. */
export async function mockBackend(page: Page, opts: HarnessOptions = {}) {
  const user = opts.user ?? DEFAULT_USER
  const jwt = makeJwt(user)
  const json = (route: Route, body: unknown, status = 200) =>
    route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(body) })

  const authUser = { id: user.id, email: `${user.tg_id}@telegram.propspace.app`, aud: 'authenticated', role: 'authenticated' }
  const sessionBody = { access_token: jwt, refresh_token: 'refresh-xyz', token_type: 'bearer', expires_in: 3600, expires_at: Math.floor(Date.now() / 1000) + 3600, user: authUser }

  // Edge Function login (POST) + diagnostics (GET)
  await page.route('**/functions/v1/telegram-auth', async (route) => {
    if (route.request().method() === 'GET') return json(route, { ok: true, checks: {} })
    if (opts.loginDelayMs) await new Promise((r) => setTimeout(r, opts.loginDelayMs))
    return json(route, { access_token: jwt, refresh_token: 'refresh-xyz', user, is_new: user.role === null })
  })

  // GoTrue auth endpoints touched by setSession / refresh / getUser
  await page.route('**/auth/v1/token**', (route) => json(route, sessionBody))
  await page.route('**/auth/v1/user**', (route) => json(route, authUser))
  await page.route('**/auth/v1/logout**', (route) => json(route, {}))

  // PostgREST tables — empty by default; users returns the profile row
  await page.route('**/rest/v1/users**', (route) => {
    const accept = route.request().headers()['accept'] ?? ''
    return json(route, accept.includes('object') ? user : [user])
  })
  await page.route('**/rest/v1/**', (route) => json(route, []))
}

export async function setupApp(page: Page, opts: HarnessOptions = {}) {
  await installTelegram(page, opts)
  await mockBackend(page, opts)
}

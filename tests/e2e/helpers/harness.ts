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
      // Реальний емітер подій: без нього застосунок ніколи не бачить
      // viewportChanged, і всю клавіатурну логіку неможливо перевірити.
      const listeners = new Map<string, ((...a: unknown[]) => void)[]>()
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      ;(window as any).Telegram = {
        WebApp: {
          initData: 'mock_init_data_signed',
          initDataUnsafe: { user: { id: tgId, first_name: firstName, username }, start_param: startParam },
          colorScheme: 'dark',
          viewportHeight: 568,
          viewportStableHeight: 568,
          // Bot API 8.0: врізи пристрою і власних контролів Telegram. Нулі —
          // як на пристрої без нотча; тести піднімають їх через __tgSafeArea.
          safeAreaInset: { top: 0, bottom: 0, left: 0, right: 0 },
          contentSafeAreaInset: { top: 0, bottom: 0, left: 0, right: 0 },
          ready() {}, expand() {}, close() {},
          enableClosingConfirmation() {}, disableClosingConfirmation() {},
          // Кольори нативного хрому ЗАПАМʼЯТОВУЮТЬСЯ: чорна смуга під світлим
          // низом градієнта — це рамка навколо клавіатури на реальному iOS
          // (заміряно по запису), тож гард мусить читати останнє значення.
          setHeaderColor(c: string) { (window as unknown as Record<string, unknown>).__tgHeaderColor = c },
          setBackgroundColor(c: string) { (window as unknown as Record<string, unknown>).__tgBgColor = c },
          setBottomBarColor(c: string) { (window as unknown as Record<string, unknown>).__tgBottomBarColor = c },
          disableVerticalSwipes() {},
          openTelegramLink() {},
          onEvent(name: string, cb: (...a: unknown[]) => void) {
            listeners.set(name, [...(listeners.get(name) ?? []), cb])
          },
          offEvent(name: string, cb: (...a: unknown[]) => void) {
            listeners.set(name, (listeners.get(name) ?? []).filter((f) => f !== cb))
          },
          BackButton: { isVisible: false, show() { this.isVisible = true }, hide() { this.isVisible = false }, onClick() {}, offClick() {} },
          HapticFeedback: { impactOccurred() {}, notificationOccurred() {}, selectionChanged() {} },
          CloudStorage: {
            getItem: (k: string, cb: (e: unknown, v: string | null) => void) => cb(null, cloud.get(k) ?? null),
            setItem: (k: string, v: string, cb?: (e: unknown, ok: boolean) => void) => { cloud.set(k, v); cb?.(null, true) },
            removeItem: (k: string, cb?: (e: unknown, ok: boolean) => void) => { cloud.delete(k); cb?.(null, true) },
          },
        },
      }
      // Тестовий хелпер: імітує відкриття клавіатури так, як це робить Telegram.
      // `resized` — режим, у якому webview СТИСНУВСЯ (лейаут уже без клавіатури).
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      ;(window as any).__tgKeyboard = (height: number) => {
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        const tg = (window as any).Telegram.WebApp
        tg.viewportHeight = tg.viewportStableHeight - height
        for (const cb of listeners.get('viewportChanged') ?? []) cb({ isStateStable: false })
      }
      // Тестовий хелпер: Telegram повідомляє врізи (нотч/home-індикатор і власні
      // контроли). Саме цей шлях працює на iOS, де env() лишається нулем.
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      ;(window as any).__tgSafeArea = (device: { top?: number; bottom?: number }, content?: { top?: number; bottom?: number }) => {
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        const tg = (window as any).Telegram.WebApp
        tg.safeAreaInset = { top: 0, bottom: 0, left: 0, right: 0, ...device }
        tg.contentSafeAreaInset = { top: 0, bottom: 0, left: 0, right: 0, ...(content ?? {}) }
        for (const cb of listeners.get('safeAreaChanged') ?? []) cb()
        for (const cb of listeners.get('contentSafeAreaChanged') ?? []) cb()
      }
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      ;(window as any).__tgViewportStable = (h: number) => {
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        const tg = (window as any).Telegram.WebApp
        tg.viewportStableHeight = h
        tg.viewportHeight = h
        for (const cb of listeners.get('viewportChanged') ?? []) cb({ isStateStable: true })
      }
      // Нативний попап — ОПЦІЙНО (клієнти без нього мусять і далі покриватись
      // фолбек-модалкою, тож базовий стаб його НЕ має). Тест вмикає його сам і
      // задає відповідь: 'ok' | 'cancel' | null (закриття свайпом).
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      ;(window as any).__tgEnablePopups = (answer: string | null = 'ok') => {
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        const w = window as any
        w.__tgPopups = []
        w.__tgPopupAnswer = answer
        w.Telegram.WebApp.showPopup = (
          params: unknown,
          cb?: (id: string | null) => void,
        ) => {
          w.__tgPopups.push(params)
          // Реальний Telegram віддає відповідь асинхронно — синхронний виклик
          // приховав би гонки, яких у продакшені не буде.
          setTimeout(() => cb?.(w.__tgPopupAnswer), 30)
        }
      }
      // MainButton/SecondaryButton — теж опційно: без них екрани малюють DOM
      // `.mbtn`, і саме цей шлях перевіряє решта тестів.
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      ;(window as any).__tgEnableMainButton = (withSecondary = true) => {
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        const w = window as any
        const make = (name: string) => {
          const clicks: (() => void)[] = []
          const state: Record<string, unknown> = { name, isVisible: false, text: '', params: {} }
          w[`__tg${name}`] = state
          w[`__tg${name}Click`] = () => { for (const c of clicks) c() }
          // Стаб ВАЛІДУЄ як справжній клієнт: порожній/пробільний підпис Telegram
          // відкидає, кидаючи WebAppBottomButtonParamInvalid СИНХРОННО. Без цієї
          // строгості стаб пропускав `text: ' '` — і падіння форми створення
          // об'єкта не було видно в тестах узагалі.
          const badText = (t: unknown) => typeof t !== 'string' || t.trim() === ''
          return {
            setText(t: string) {
              if (badText(t)) throw new Error('WebAppBottomButtonParamInvalid')
              state.text = t
            },
            setParams(p: Record<string, unknown>) {
              if ('text' in p && badText(p.text)) throw new Error('WebAppBottomButtonParamInvalid')
              state.params = { ...(state.params as object), ...p }
              if (typeof p.text === 'string') state.text = p.text
              if (typeof p.is_visible === 'boolean') state.isVisible = p.is_visible
            },
            show() { state.isVisible = true },
            hide() { state.isVisible = false },
            enable() { state.isActive = true },
            disable() { state.isActive = false },
            showProgress() { state.progress = true },
            hideProgress() { state.progress = false },
            onClick(fn: () => void) { clicks.push(fn) },
            offClick(fn: () => void) { const i = clicks.indexOf(fn); if (i >= 0) clicks.splice(i, 1) },
          }
        }
        w.Telegram.WebApp.MainButton = make('Main')
        // `setBottomBarColor` більше не підмінюємо: базовий стаб його ЗАПИСУЄ,
        // а no-op тут стирав би значення, яке перевіряє гард нижньої смуги.
        if (withSecondary) w.Telegram.WebApp.SecondaryButton = make('Secondary')
      }
    },
    { tgId: user.tg_id, firstName: user.first_name, username: user.tg_username, startParam: opts.startParam },
  )
}

/** Intercept every Supabase REST / Auth / Edge call with deterministic fixtures. */
export async function mockBackend(page: Page, opts: HarnessOptions = {}) {
  // Герметичність БУКВАЛЬНО: справжній telegram-web-app.js з telegram.org
  // ПЕРЕЗАПИСУЄ наш стаб window.Telegram (initData стає '', start_param зникає,
  // методи кидають WebAppMethodUnsupported). У пісочниці Claude Code зовнішня
  // мережа закрита і це маскувалось; на GitHub-раннерах SDK вантажився і валив
  // 7 тестів. Віддаємо порожній скрипт.
  await page.route('**/telegram-web-app.js', (route) =>
    route.fulfill({ status: 200, contentType: 'application/javascript', body: '' }))
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

  // PostgREST tables — empty by default.
  // Register catch-all FIRST so the more-specific users route (added next) wins in Playwright
  // (last-registered wins when multiple patterns match).
  await page.route('**/rest/v1/**', (route) => {
    if (route.request().url().includes('/rest/v1/users')) return // let the specific handler below run
    return json(route, [])
  })

  // Users table — handles GET and PATCH. PATCH merges the request body so
  // role/profile changes are visible immediately (mirrors real DB behaviour).
  let currentUser = { ...user }
  await page.route('**/rest/v1/users**', async (route) => {
    const method = route.request().method()
    if (method === 'PATCH') {
      try {
        const body = JSON.parse(route.request().postData() ?? '{}')
        currentUser = { ...currentUser, ...body }
      } catch { /* ignore parse errors */ }
    }
    const accept = route.request().headers()['accept'] ?? ''
    return json(route, accept.includes('object') ? currentUser : [currentUser])
  })
}

export async function setupApp(page: Page, opts: HarnessOptions = {}) {
  await installTelegram(page, opts)
  await mockBackend(page, opts)
}

/** Standard JSON fulfill for page.route handlers — import instead of
 *  re-declaring per spec (the inline copies had already drifted on `status`). */
export const jsonRoute = (route: Route, body: unknown, status = 200) =>
  route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(body) })

/** Every onboarding coachmark pre-dismissed — one source for the id list so a
 *  new coachmark can't silently re-appear and steal clicks in old specs. */
export function skipCoachmarks(page: Page) {
  return page.addInitScript(() => {
    localStorage.setItem('ob_v1', JSON.stringify(['owner-fab', 'obj-fab', 'realtor-qr', 'col-fab']))
  })
}

/** Cached profile → Fast Path 0 restores the session instantly (no splash
 *  detour to the public preview screens on deep links). Includes coachmarks. */
export function seedSession(page: Page, user: Record<string, unknown>) {
  return page.addInitScript((u) => {
    localStorage.setItem('ps_user', JSON.stringify(u))
    localStorage.setItem('ob_v1', JSON.stringify(['owner-fab', 'obj-fab', 'realtor-qr', 'col-fab']))
  }, user)
}

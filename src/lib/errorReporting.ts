'use client'

/**
 * ЗВІТИ ПРО ЗБОЇ — ЄДИНИЙ ШЛЯХ.
 *
 * До цього збій у проді не бачив НІХТО: `@sentry/react` лежав у залежностях,
 * але `Sentry.init` не викликався ніде, а `ErrorBoundary` перевіряв
 * `window.Sentry`, якого за побудовою не існувало. Тобто «Щось пішло не так» у
 * користувача лишалось подією без свідка — дізнатись про неї можна було лише зі
 * скарги.
 *
 * Вмикається ЛИШЕ змінною `NEXT_PUBLIC_SENTRY_DSN` (Vercel). Без неї модуль
 * нічого не вантажить і нікуди не шле — це і є стан за замовчуванням.
 *
 * Що НЕ їде назовні, і чому це перелічено явно: share-токени живуть у query
 * (`/v?prop=…`) і в параметрах старту (`db_…`), а вони — креденшл, що не
 * ротується. Тому з URL прибирається query, токенні параметри маскуються, а
 * хлібних крихт (там URL кожного запиту) немає зовсім. Користувач не
 * ідентифікується — ні id, ні tg_id, ні імені.
 */

const DSN = process.env.NEXT_PUBLIC_SENTRY_DSN ?? ''

type Reporter = { captureException: (e: unknown, ctx?: { tags?: Record<string, string>; extra?: Record<string, unknown> }) => unknown }

let reporter: Reporter | null = null
let started = false
const pending: Array<[unknown, ReportContext | undefined]> = []
const MAX_PENDING = 10

export type ReportContext = { tags?: Record<string, string>; extra?: Record<string, unknown> }

const URL_QUERY = /(https?:\/\/[^\s?#"'<>]+)[?#][^\s"'<>]*/g
const START_TOKEN = /\b(db|prop|col|guest|team)_[A-Za-z0-9_-]{4,}/g

/** Прибирає з рядка все, що може бути креденшлом: query в URL і токени старту. */
export function scrubText(s: string): string {
  return s
    .replace(URL_QUERY, (_m, base: string) => base)
    .replace(START_TOKEN, (_m, kind: string) => kind + '_…')
}

type Scrubbable = {
  user?: unknown
  breadcrumbs?: unknown
  request?: { url?: string; query_string?: unknown; headers?: unknown; cookies?: unknown; data?: unknown }
  message?: string
  exception?: { values?: Array<{ value?: string }> }
  extra?: Record<string, unknown>
}

/** Остання лінія перед відправкою: те саме правило, що й для тексту, на всю подію. */
export function scrubEvent<E extends Scrubbable>(event: E): E {
  delete event.user
  delete event.breadcrumbs
  if (event.request) {
    if (event.request.url) event.request.url = scrubText(event.request.url)
    delete event.request.query_string
    delete event.request.headers
    delete event.request.cookies
    delete event.request.data
  }
  if (event.message) event.message = scrubText(event.message)
  for (const v of event.exception?.values ?? []) {
    if (v.value) v.value = scrubText(v.value)
  }
  if (event.extra) {
    for (const [k, val] of Object.entries(event.extra)) {
      if (typeof val === 'string') event.extra[k] = scrubText(val)
    }
  }
  return event
}

export function reportError(err: unknown, ctx?: ReportContext): void {
  if (!DSN) return
  if (reporter) {
    try { reporter.captureException(err, ctx) } catch { /* звіт не сміє валити застосунок */ }
  } else if (pending.length < MAX_PENDING) {
    pending.push([err, ctx])
  }
}

export function initErrorReporting(): void {
  if (!DSN || started || typeof window === 'undefined') return
  started = true
  const load = () => {
    import('@sentry/react')
      .then((S) => {
        S.init({
          dsn: DSN,
          release: process.env.NEXT_PUBLIC_BUILD_SHA,
          sendDefaultPii: false,
          maxBreadcrumbs: 0,
          tracesSampleRate: 0,
          // Глобальні `error`/`unhandledrejection` ловить `layout.tsx` і шле
          // сюди ж — дві підписки дали б кожен збій двічі. Сесії (release
          // health) і крихти не потрібні й лише розширюють те, що йде назовні.
          integrations: (defaults) => defaults.filter((i) =>
            !['GlobalHandlers', 'Breadcrumbs', 'BrowserSession'].includes(i.name)),
          beforeSend: (event) => scrubEvent(event),
        })
        reporter = S
        for (const [e, c] of pending.splice(0)) reporter.captureException(e, c)
      })
      .catch(() => { started = false })
  }
  // Не на критичному шляху старту — той самий принцип, що для xlsx/jsPDF.
  const ric = (window as Window & { requestIdleCallback?: (cb: () => void, o?: { timeout: number }) => number }).requestIdleCallback
  if (ric) ric(load, { timeout: 4000 })
  else setTimeout(load, 2000)
}

/**
 * Застарілий чанк після деплою. Застосунок — статичний експорт, і відкрита в
 * Telegram вкладка тримає index від ПОПЕРЕДНЬОГО білда: перший же ледачий екран
 * чи `import('jspdf')` просить файл, якого на новому деплої немає.
 */
export function isChunkLoadError(err: unknown): boolean {
  if (!err || typeof err !== 'object') return false
  const e = err as { name?: string; message?: string }
  if (e.name === 'ChunkLoadError') return true
  return /Loading (CSS )?chunk [\w-]+ failed|Failed to fetch dynamically imported module|Importing a module script failed|error loading dynamically imported module/i
    .test(e.message ?? '')
}

/**
 * Reduce a human-entered env value to a bare Telegram handle/short-name.
 * These vars are typed into the Vercel dashboard by hand and have been
 * mis-entered as a full URL before — NEXT_PUBLIC_TELEGRAM_APP_NAME set to
 * "https://t.me/prostirapplbot/prostir" instead of the bare short name
 * "prostir" made buildDeepLink emit a doubled, unresolvable link
 * (t.me/bot/https://t.me/bot/app?startapp=…), so shares silently 404'd in
 * Telegram. Normalise: drop scheme/host/query/@, keep the last path segment.
 * Mini App short names and bot usernames never contain '/' so this is lossless.
 */
function tgHandle(v: string | undefined): string {
  return (v ?? '').trim().replace(/^@/, '').split(/[?#]/)[0].split('/').filter(Boolean).pop() ?? ''
}

export const TG_BOT = tgHandle(process.env.NEXT_PUBLIC_TELEGRAM_BOT_USERNAME)

/** Mini App short name from BotFather (/newapp). Enables direct-link format. */
const TG_APP = tgHandle(process.env.NEXT_PUBLIC_TELEGRAM_APP_NAME)

// ── Haptics ──────────────────────────────────────────────────────────────────
// Read window.Telegram directly (optional-chained) so these work from event
// handlers, hooks, and plain modules alike — no hook/tg-state wiring, no throw
// when opened outside Telegram. Replaces the inline
// window.Telegram?.WebApp?.HapticFeedback?.… calls scattered across the app.

/** Light selection tick — segment/toggle/tab changes. */
export function hapticSelection(): void {
  window.Telegram?.WebApp?.HapticFeedback?.selectionChanged()
}

/** Physical impact — taps that commit or open something. */
export function hapticImpact(style: 'light' | 'medium' | 'heavy' = 'light'): void {
  window.Telegram?.WebApp?.HapticFeedback?.impactOccurred(style)
}

/** Outcome feedback — success / error / warning. */
export function hapticNotify(type: 'success' | 'error' | 'warning'): void {
  window.Telegram?.WebApp?.HapticFeedback?.notificationOccurred(type)
}

/**
 * Build a Telegram Mini App deep-link.
 * Direct-link format (t.me/bot/app?startapp=) launches the Mini App
 * immediately with start_param; bare t.me/bot?startapp= only auto-opens
 * when a Main Mini App is configured in BotFather and otherwise drops
 * the param, leaving the user in an empty bot chat.
 * Returns '#' if the bot username env var is not configured (safe fallback
 * for /v/ page renders in build or preview environments).
 */
export function buildDeepLink(startParam: string): string {
  if (!TG_BOT) return '#'
  const base = TG_APP ? `https://t.me/${TG_BOT}/${TG_APP}` : `https://t.me/${TG_BOT}`
  return `${base}?startapp=${encodeURIComponent(startParam)}`
}

/**
 * Build the public web viewer URL for an object, database, or collection.
 * Recipients open this in any browser — no Telegram required.
 * Format: https://<origin>/v/?prop=<share_token>
 */
/** start_param-префікси, які обробляє useDeepLink. Splash/Welcome/useAuth не
 *  мають навігувати додому, коли такий параметр присутній — інакше екран
 *  блимає домашнім перед лендингом diп-лінка. Єдине джерело правди: три
 *  інлайн-копії списку вже якось розійшлися (team_ був пропущений скрізь). */
const DEEP_LINK_PREFIXES = ['db_', 'prop_', 'col_', 'guest_', 'team_'] as const
export function isDeepLinkStartParam(p: string | null | undefined): boolean {
  return !!p && DEEP_LINK_PREFIXES.some((x) => p.startsWith(x))
}

export function buildPublicUrl(type: 'prop' | 'db' | 'col', token: string): string {
  const origin = typeof window !== 'undefined' ? window.location.origin : ''
  return `${origin}/v/?${type}=${encodeURIComponent(token)}`
}

/** Open Telegram's native share sheet for any URL. Single home for the
 *  t.me/share/url construction — do not rebuild it inline in screens. */
export function openTelegramShare(url: string, text?: string): void {
  const shareUrl = text
    ? `https://t.me/share/url?url=${encodeURIComponent(url)}&text=${encodeURIComponent(text)}`
    : `https://t.me/share/url?url=${encodeURIComponent(url)}`
  const tg = window.Telegram?.WebApp
  if (tg?.openTelegramLink) {
    tg.openTelegramLink(shareUrl)
    return
  }
  // Поза Telegram (веб-прев'ю, десктоп-браузер) кнопка інакше мовчки не робила
  // б нічого — відкриваємо t.me/share у новій вкладці.
  window.open(shareUrl, '_blank', 'noopener')
}

/**
 * Open Telegram's native share sheet with the public viewer URL.
 * The recipient sees the beautiful /v page in any browser; the page
 * has an "Відкрити в Telegram" button that deep-links back to the Mini App.
 */
export function sharePublicUrl(type: 'prop' | 'db' | 'col', token: string, text?: string): void {
  openTelegramShare(buildPublicUrl(type, token), text)
}

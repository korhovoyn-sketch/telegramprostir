/**
 * Telegram bot username used for share links.
 * Set NEXT_PUBLIC_TELEGRAM_BOT_USERNAME in Vercel environment variables.
 * Example: prostirapplbot  (no @, no https)
 */
function getTgBot(): string {
  const bot = process.env.NEXT_PUBLIC_TELEGRAM_BOT_USERNAME
  if (!bot) throw new Error('[PropSpace] Missing NEXT_PUBLIC_TELEGRAM_BOT_USERNAME env var')
  return bot
}

export const TG_BOT = process.env.NEXT_PUBLIC_TELEGRAM_BOT_USERNAME ?? ''

/** Mini App short name from BotFather (/newapp). Enables direct-link format. */
const TG_APP = process.env.NEXT_PUBLIC_TELEGRAM_APP_NAME ?? ''

/**
 * Build a Telegram Mini App deep-link.
 * Direct-link format (t.me/bot/app?startapp=) launches the Mini App
 * immediately with start_param; bare t.me/bot?startapp= only auto-opens
 * when a Main Mini App is configured in BotFather and otherwise drops
 * the param, leaving the user in an empty bot chat.
 */
export function buildDeepLink(startParam: string): string {
  const bot = getTgBot()
  const base = TG_APP ? `https://t.me/${bot}/${TG_APP}` : `https://t.me/${bot}`
  return `${base}?startapp=${encodeURIComponent(startParam)}`
}

/**
 * Build the public web viewer URL for an object, database, or collection.
 * Recipients open this in any browser — no Telegram required.
 * Format: https://<origin>/v/?prop=<share_token>
 */
export function buildPublicUrl(type: 'prop' | 'db' | 'col', token: string): string {
  const origin = typeof window !== 'undefined' ? window.location.origin : ''
  return `${origin}/v/?${type}=${encodeURIComponent(token)}`
}

/**
 * Open Telegram's native share sheet with the public viewer URL.
 * The recipient sees the beautiful /v page in any browser; the page
 * has an "Відкрити в Telegram" button that deep-links back to the Mini App.
 */
export function sharePublicUrl(type: 'prop' | 'db' | 'col', token: string, text?: string): void {
  const url = buildPublicUrl(type, token)
  const shareUrl = text
    ? `https://t.me/share/url?url=${encodeURIComponent(url)}&text=${encodeURIComponent(text)}`
    : `https://t.me/share/url?url=${encodeURIComponent(url)}`
  window.Telegram?.WebApp?.openTelegramLink(shareUrl)
}

/** @deprecated Use sharePublicUrl for new share flows */
export function shareDeepLink(startParam: string, text?: string): void {
  const link = buildDeepLink(startParam)
  const shareUrl = text
    ? `https://t.me/share/url?url=${encodeURIComponent(link)}&text=${encodeURIComponent(text)}`
    : `https://t.me/share/url?url=${encodeURIComponent(link)}`
  window.Telegram?.WebApp?.openTelegramLink(shareUrl)
}

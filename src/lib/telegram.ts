/**
 * Telegram bot username used for share links.
 * Set NEXT_PUBLIC_TELEGRAM_BOT_USERNAME in Vercel environment variables.
 * Example: prostirapplbot  (no @, no https)
 */
export const TG_BOT = process.env.NEXT_PUBLIC_TELEGRAM_BOT_USERNAME ?? 'prostirapplbot'

/** Build a deep-link that opens the Mini App with start_param */
export function buildDeepLink(startParam: string): string {
  return `https://t.me/${TG_BOT}?startapp=${encodeURIComponent(startParam)}`
}

/** Open Telegram's native share sheet for a deep-link */
export function shareDeepLink(startParam: string, text?: string): void {
  const link = buildDeepLink(startParam)
  const shareUrl = text
    ? `https://t.me/share/url?url=${encodeURIComponent(link)}&text=${encodeURIComponent(text)}`
    : `https://t.me/share/url?url=${encodeURIComponent(link)}`
  window.Telegram?.WebApp?.openTelegramLink(shareUrl)
}

/**
 * Retry wrapper for Supabase queries in Telegram's unreliable network.
 * Retries up to `attempts` times with exponential back-off on network errors.
 * Does NOT retry on 4xx / auth errors — those are deterministic failures.
 */
export async function withRetry<T>(
  fn: () => Promise<{ data: T | null; error: { message: string; status?: number } | null }>,
  attempts = 3,
): Promise<{ data: T | null; error: { message: string; status?: number } | null }> {
  let last: { data: T | null; error: { message: string; status?: number } | null } = { data: null, error: { message: 'Unknown' } }
  for (let i = 0; i < attempts; i++) {
    last = await fn()
    if (!last.error) return last
    const status = last.error.status ?? 0
    // Don't retry auth / bad-request errors
    if (status >= 400 && status < 500) return last
    if (i < attempts - 1) await new Promise((r) => setTimeout(r, 400 * 2 ** i))
  }
  return last
}

export function formatPrice(amount: number, currency = 'USD'): string {
  if (currency === 'USD') return `$${amount.toLocaleString('uk-UA')}`
  if (currency === 'EUR') return `€${amount.toLocaleString('uk-UA')}`
  return `₴${amount.toLocaleString('uk-UA')}`
}

export function formatArea(m2: number): string {
  return `${m2} м²`
}

export function formatLeaseDate(d: string): string {
  return new Date(d).toLocaleDateString('uk-UA', { day: '2-digit', month: '2-digit', year: 'numeric' })
}

export function formatLeasePeriod(start?: string | null, end?: string | null): string | null {
  if (!start && !end) return null
  if (start && end) return `${formatLeaseDate(start)} — ${formatLeaseDate(end)}`
  if (start) return `від ${formatLeaseDate(start)}`
  return `до ${formatLeaseDate(end!)}`
}

export function formatDate(iso: string): string {
  const d = new Date(iso)
  const now = new Date()
  const diff = now.getTime() - d.getTime()
  const mins = Math.floor(diff / 60000)
  const hours = Math.floor(diff / 3600000)
  const days = Math.floor(diff / 86400000)

  if (mins < 1) return 'щойно'
  if (mins < 60) return `${mins} хв тому`
  if (hours < 24) return `${hours} год тому`
  if (days === 1) return 'вчора'
  if (days < 5) return `${days} дні тому`
  if (days < 7) return `${days} днів тому`

  return d.toLocaleDateString('uk-UA', { day: 'numeric', month: 'short' })
}

export function calcRent(areaUseful: number, rentRate: number, rentType: string): number {
  if (rentType === 'fixed') return rentRate
  return Math.round(areaUseful * rentRate)
}

export function calcUtilities(areaTotal: number, utilitiesRate: number): number {
  return Math.round(areaTotal * utilitiesRate)
}

export function calcTotal(
  areaUseful: number,
  areaTotal: number,
  rentRate: number,
  rentType: string,
  utilitiesRate: number
): number {
  const rent = calcRent(areaUseful, rentRate, rentType)
  const utils = calcUtilities(areaTotal, utilitiesRate)
  return rent + utils
}

export function getInitials(firstName: string, lastName?: string): string {
  const f = firstName.charAt(0).toUpperCase()
  const l = lastName ? lastName.charAt(0).toUpperCase() : ''
  return f + l
}

export function freshnessLabel(updatedAt: string): { label: string; cls: string } {
  const days = Math.floor((Date.now() - new Date(updatedAt).getTime()) / 86400000)
  if (days === 0) return { label: 'сьогодні', cls: 'fresh' }
  if (days <= 3) return { label: `${days}д тому`, cls: 'fresh' }
  if (days <= 7) return { label: `${days}д тому`, cls: 'stale' }
  return { label: `${days}д тому`, cls: 'old' }
}

export const DB_TYPE_LABELS: Record<string, string> = {
  business_center: 'Бізнес-центр',
  residential: 'ЖК',
  retail: 'Рітейл',
  warehouse: 'Склади',
  individual: 'Приватне',
  parking: 'Паркінг',
}

export const DB_TYPE_ICONS: Record<string, string> = {
  business_center: 'ti-building-skyscraper',
  residential: 'ti-building-community',
  retail: 'ti-building-store',
  warehouse: 'ti-building-warehouse',
  individual: 'ti-home',
  parking: 'ti-car-garage',
}

export const DB_TYPE_EMOJI: Record<string, string> = {
  business_center: '🏢',
  residential: '🏘',
  retail: '🏪',
  warehouse: '🏭',
  individual: '🏠',
  parking: '🅿️',
}

export const STATUS_LABELS: Record<string, string> = {
  free: 'Вільно',
  occupied: 'Зайнято',
  for_sale: 'Продаж',
}

export const STATUS_BADGE_CLS: Record<string, string> = {
  free: 'bdg-ok',
  occupied: 'bdg-busy',
  for_sale: 'bdg-sale',
}

export const DB_COLORS: Record<string, string> = {
  purple: 'linear-gradient(135deg,#7B30EB,#5B1FD4)',
  blue: 'linear-gradient(135deg,#2AABEE,#1070B8)',
  green: 'linear-gradient(135deg,#34C759,#1A8A38)',
  orange: 'linear-gradient(135deg,#FF9500,#D06000)',
  pink: 'linear-gradient(135deg,#FF7AB8,#C42378)',
  teal: 'linear-gradient(135deg,#5AC8FA,#2A8AB0)',
}

/**
 * onFocusCapture handler: scrolls the focused input/textarea into view once the
 * on-screen keyboard has opened. Telegram's webview overlays the keyboard without
 * resizing the layout viewport on iOS, so fields below the fold stay hidden.
 * Two-pass: immediate scroll for fast keyboards + delayed scroll using visualViewport
 * to account for iOS keyboard (fully opens in ~450 ms).
 */
export function scrollFocusedIntoView(e: import('react').FocusEvent<HTMLElement>): void {
  const el = e.target as HTMLElement
  const tag = el?.tagName
  if (tag !== 'INPUT' && tag !== 'TEXTAREA' && tag !== 'SELECT') return
  // Pass 1: quick scroll so the field is at least in the DOM-visible area.
  el.scrollIntoView({ behavior: 'instant' as ScrollBehavior, block: 'center' })
  // Pass 2: after keyboard finishes opening, re-check using visualViewport height
  // which reflects the true visible area with the keyboard shown.
  setTimeout(() => {
    const vh = window.visualViewport?.height ?? window.innerHeight
    const rect = el.getBoundingClientRect()
    if (rect.top < 56 || rect.bottom > vh - 20) {
      el.scrollIntoView({ behavior: 'smooth', block: 'center' })
    }
  }, 500)
}

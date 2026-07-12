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

/**
 * Turn any thrown/returned Supabase/Postgres error into a safe, friendly
 * Ukrainian message for a user-facing toast — never the raw PostgREST/Postgres
 * text (which leaks column names, RLS policy text, constraint names). The raw
 * message is logged to console for diagnostics. Use this instead of
 * `subtitle: (e as Error).message` anywhere a toast is shown to the user.
 */
export function humanizeDbError(e: unknown, fallback = 'Спробуйте ще раз'): string {
  const raw = e instanceof Error ? e.message
    : (typeof e === 'object' && e !== null && 'message' in e) ? String((e as { message: unknown }).message)
    : String(e ?? '')
  if (raw) console.error('[db]', raw)

  const m = raw.toLowerCase()
  // Network / connectivity (PostgREST resolves fetch failures as status 0)
  if (m.includes('fetch') || m.includes('network') || m.includes('failed to fetch')) {
    return 'Немає з\'єднання. Перевірте інтернет і спробуйте ще раз.'
  }
  // RLS / permission denied — the user can't touch this row
  if (m.includes('row-level security') || m.includes('permission denied') || m.includes('not authorized')) {
    return 'Немає доступу до цих даних.'
  }
  // Unique violation (Postgres 23505) — duplicate
  if (m.includes('duplicate key') || m.includes('23505') || m.includes('already exists')) {
    return 'Такий запис уже існує.'
  }
  // Foreign-key / not-null / check violations — bad input shape
  if (m.includes('violates') || m.includes('23503') || m.includes('23502') || m.includes('23514')) {
    return 'Некоректні дані. Перевірте введене й спробуйте ще раз.'
  }
  // Missing table/relation — deploy/migration issue, not the user's fault
  if (m.includes('does not exist') || m.includes('42p01')) {
    return 'Сервіс тимчасово недоступний. Спробуйте пізніше.'
  }
  return fallback
}

const SUPABASE_URL = process.env.NEXT_PUBLIC_SUPABASE_URL ?? ''

export function photoUrl(storagePath: string): string {
  return `${SUPABASE_URL}/storage/v1/object/public/photos/${storagePath}`
}

export function daysSince(dateStr: string): number {
  return Math.floor((Date.now() - new Date(dateStr).getTime()) / 86400000)
}

export function daysUntil(dateStr: string): number {
  return Math.ceil((new Date(dateStr).getTime() - Date.now()) / 86400000)
}

export function formatPrice(amount: number, currency = 'USD'): string {
  if (currency === 'USD') return `$${amount.toLocaleString('uk-UA')}`
  if (currency === 'EUR') return `€${amount.toLocaleString('uk-UA')}`
  return `₴${amount.toLocaleString('uk-UA')}`
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
  // per_m2 multiplies by useful area; fixed (monthly) and per_day (daily) store
  // the rate itself. calcRent returns the raw figure for that unit — for a
  // per_day spot that's the DAILY rate; monthlyRent() below scales it to a month.
  if (rentType === 'fixed' || rentType === 'per_day') return rentRate
  return Math.round(areaUseful * rentRate)
}

// Monthly value of a rent, used only for income aggregations (dashboard stats,
// payment calendar). A daily parking rate is projected across ~30 days.
const DAYS_PER_MONTH = 30
export function monthlyRent(areaUseful: number, rentRate: number, rentType: string): number {
  if (rentType === 'per_day') return Math.round(rentRate * DAYS_PER_MONTH)
  return calcRent(areaUseful, rentRate, rentType)
}

// Ukrainian plural picker: 1 → one, 2-4 → few, else → many (with the 11-14
// exception). Replaces the hardcoded "об'єктів" that read wrong for 1 ("1
// об'єктів") and 2-4 ("2 об'єктів") across cards, counts and delete dialogs.
export function pluralUk(n: number, one: string, few: string, many: string): string {
  const mod10 = Math.abs(n) % 10
  const mod100 = Math.abs(n) % 100
  if (mod10 === 1 && mod100 !== 11) return one
  if (mod10 >= 2 && mod10 <= 4 && (mod100 < 12 || mod100 > 14)) return few
  return many
}

// "об'єкт" / "об'єкти" / "об'єктів" — the app's most common counted noun.
export function objectsWord(n: number): string {
  return pluralUk(n, 'об\'єкт', 'об\'єкти', 'об\'єктів')
}

// Unit suffix for a rent RATE (the raw rent_rate value): per_m2 → /м²,
// per_day → /добу, else → /міс. Use only next to the rate itself.
export function rentUnitLabel(rentType: string | null | undefined): string {
  if (rentType === 'per_m2') return '/м²'
  if (rentType === 'per_day') return '/добу'
  return '/міс'
}

// Unit suffix for a COMPUTED rent amount (calcRent/monthlyRent output). per_m2
// and fixed both compute a MONTHLY figure, so the unit is /міс — NOT /м² (that
// would misread e.g. a $1 800 monthly total as $1 800 per square metre). per_day
// computes a daily figure, so /добу.
export function computedRentUnit(rentType: string | null | undefined): string {
  return rentType === 'per_day' ? '/добу' : '/міс'
}

// Name for a duplicated object: increment a trailing number («Офіс 101» →
// «Офіс 102», «A-09» → «A-10», zero-padding preserved), skipping names already
// taken; otherwise append «(копія)».
export function nextCopyName(base: string, taken: string[]): string {
  const has = new Set(taken)
  const m = base.match(/^(.*?)(\d+)\s*$/)
  if (m) {
    const pad = m[2].length
    let n = parseInt(m[2], 10)
    let candidate: string
    do {
      n += 1
      candidate = `${m[1]}${String(n).padStart(pad, '0')}`
    } while (has.has(candidate))
    return candidate
  }
  let candidate = `${base} (копія)`
  for (let i = 2; has.has(candidate); i++) candidate = `${base} (копія ${i})`
  return candidate
}

// Sequence of names for bulk creation: a trailing number becomes the start of
// a run («Офіс 101» ×3 → 101, 102, 103, zero-padding preserved), otherwise an
// index is appended («Місце» ×3 → «Місце 1..3»). Taken names are skipped.
export function bulkCreateNames(base: string, count: number, taken: string[]): string[] {
  const trimmed = base.trim()
  if (count <= 1) return [trimmed]
  const has = new Set(taken)
  const names: string[] = []
  const m = trimmed.match(/^(.*?)(\d+)\s*$/)
  if (m) {
    const pad = m[2].length
    let n = parseInt(m[2], 10) - 1
    while (names.length < count) {
      n += 1
      const candidate = `${m[1]}${String(n).padStart(pad, '0')}`
      if (!has.has(candidate)) names.push(candidate)
    }
  } else {
    let i = 0
    while (names.length < count) {
      i += 1
      const candidate = `${trimmed} ${i}`
      if (!has.has(candidate)) names.push(candidate)
    }
  }
  return names
}

const PARKING_TYPE_LABELS: Record<string, string> = {
  underground: 'Підземний',
  covered: 'Критий',
  open: 'Просто неба',
}
export function parkingTypeLabel(t: string | null | undefined): string | null {
  return t ? PARKING_TYPE_LABELS[t] ?? null : null
}

export function calcUtilities(areaTotal: number, utilitiesRate: number): number {
  return Math.round(areaTotal * utilitiesRate)
}

// Build a safe download filename from a user-controlled name: collapse anything
// that isn't a Latin/Cyrillic letter or digit to '_', append the date and ext.
// A raw db name can carry '/', '\', control chars or emoji that break the file
// on some OSes or, worse, escape the intended directory.
export function safeFileName(name: string, ext: string): string {
  const slug = name.replace(/[^a-zA-Zа-яА-ЯіІїЇєЄ0-9]/g, '_').replace(/_+/g, '_').replace(/^_|_$/g, '') || 'export'
  return `${slug}_${new Date().toISOString().slice(0, 10)}.${ext}`
}

// Single source of truth for the rent + utilities monthly total. Mirrors the
// guard the screens used inline (rent needs a rate + useful area; utilities need
// a rate + total area) so every surface — cards, detail, /v — shows the same
// number. Accepts loose nullable numbers so it fits both Property and the /v
// preview row shapes.
export function calcRentUtils(
  areaUseful: number | null | undefined,
  areaTotal: number | null | undefined,
  rentRate: number | null | undefined,
  rentType: string | null | undefined,
  utilitiesRate: number | null | undefined,
): { rent: number; utils: number; total: number } {
  // per_m2 needs a useful area to multiply; fixed/per_day carry the rate itself,
  // so they must NOT be gated on area (a fixed monthly rent or a parking spot
  // with no m² still has a rent).
  const rt = rentType ?? 'per_m2'
  const rent = rentRate ? calcRent(areaUseful ?? 0, rentRate, rt) : 0
  // Utilities: $/m² when a total area is present, otherwise a flat charge
  // (parking utilities are flat — there's no total area to multiply).
  const utils = utilitiesRate ? (areaTotal ? calcUtilities(areaTotal, utilitiesRate) : Math.round(utilitiesRate)) : 0
  return { rent, utils, total: rent + utils }
}

export function greeting(): string {
  const hour = new Date().getHours()
  return hour < 12 ? 'Доброго ранку' : hour < 17 ? 'Добрий день' : 'Добрий вечір'
}

export function getInitials(firstName: string, lastName?: string): string {
  const f = firstName.charAt(0).toUpperCase()
  const l = lastName ? lastName.charAt(0).toUpperCase() : ''
  return f + l
}

export const DB_TYPE_LABELS: Record<string, string> = {
  business_center: 'Бізнес-центр',
  residential: 'ЖК',
  retail: 'Рітейл',
  warehouse: 'Склади',
  individual: 'Приватне',
  parking: 'Паркінг',
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

export const STATUS_COLORS: Record<string, { bg: string; color: string }> = {
  free:     { bg: 'rgba(52,199,89,.18)',   color: '#34c759' },
  occupied: { bg: 'rgba(255,159,10,.18)',  color: '#ff9f0a' },
  for_sale: { bg: 'rgba(122,179,255,.18)', color: '#7ab3ff' },
}

export const DB_COLORS: Record<string, string> = {
  purple: 'linear-gradient(135deg,#7B30EB,#5B1FD4)',
  blue: 'linear-gradient(135deg,#2AABEE,#1070B8)',
  green: 'linear-gradient(135deg,#34C759,#1A8A38)',
  orange: 'linear-gradient(135deg,#FF9500,#D06000)',
  pink: 'linear-gradient(135deg,#FF7AB8,#C42378)',
  teal: 'linear-gradient(135deg,#5AC8FA,#2A8AB0)',
}

// Cancelled by the next focus event so rapid tab-through doesn't stack scrolls.
let _scrollTimer: ReturnType<typeof setTimeout> | undefined

/**
 * onFocusCapture handler: scrolls the focused input/textarea into view once the
 * on-screen keyboard has opened. Telegram's webview overlays the keyboard without
 * resizing the layout viewport on iOS, so fields below the fold stay hidden.
 * Two-pass: immediate nearest-scroll (no jank) + delayed visual-viewport-aware
 * centering after the iOS keyboard finishes opening (~450 ms).
 */
export function scrollFocusedIntoView(e: import('react').FocusEvent<HTMLElement>): void {
  const el = e.target as HTMLElement
  const tag = el?.tagName
  if (tag !== 'INPUT' && tag !== 'TEXTAREA' && tag !== 'SELECT') return

  clearTimeout(_scrollTimer)

  // Pass 1: bring element into the layout viewport with no animation.
  // 'nearest' avoids jarring jumps when the element is already partially visible.
  el.scrollIntoView({ behavior: 'instant' as ScrollBehavior, block: 'nearest' })

  // Pass 2: once the keyboard is fully open, re-center within the visual viewport
  // (the area actually visible above the keyboard).
  _scrollTimer = setTimeout(() => {
    const vh = window.visualViewport?.height ?? window.innerHeight
    const rect = el.getBoundingClientRect()
    if (rect.top < 56 || rect.bottom > vh - 20) {
      const scrollParent = el.closest('.body') as HTMLElement | null
      if (scrollParent) {
        // Scroll so element is centered in the visual viewport, not the layout viewport.
        const elMid = rect.top + rect.height / 2
        const targetMid = vh / 2
        scrollParent.scrollBy({ top: elMid - targetMid, behavior: 'smooth' })
      } else {
        el.scrollIntoView({ behavior: 'smooth', block: 'nearest' })
      }
    }
  }, 500)
}

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

// Controlled decimal input: comma → dot, digits + a single dot only. Used
// with type="text" inputMode="decimal" — type="number" silently blanks the
// controlled value on an invalid intermediate state (second dot, trailing
// comma), «зникає введене», and lets a scroll wheel change the number.
export function sanitizeDecimal(raw: string): string {
  let s = raw.replace(/,/g, '.').replace(/[^\d.]/g, '')
  const parts = s.split('.')
  if (parts.length > 2 && parts.slice(1, -1).some(g => g.length === 3)) {
    // Pasted grouped amount («1,200,000» / «1.200.50»): 3-digit inner groups
    // are thousand separators. The tail is decimal only when it's 1-2 digits —
    // otherwise it's another group. Naively keeping the first dot would turn
    // 1,200,000 into 1.2 and silently store a wrong price.
    const tail = parts[parts.length - 1]
    s = tail.length >= 1 && tail.length <= 2
      ? parts.slice(0, -1).join('') + '.' + tail
      : parts.join('')
  } else {
    const i = s.indexOf('.')
    if (i !== -1) s = s.slice(0, i + 1) + s.slice(i + 1).replace(/\./g, '')
  }
  return s
}

export function sanitizeInt(raw: string): string {
  return raw.replace(/\D/g, '')
}

// Bare currency sign for unit labels («₴/м²») — same mapping as formatPrice.
export function currencySymbol(currency?: string | null): string {
  if (currency === 'EUR') return '€'
  if (!currency || currency === 'USD') return '$'
  return '₴'
}

export function formatPrice(amount: number, currency = 'USD'): string {
  // Через цей форматер проходять УСІ гроші застосунку, тож він мусить бути
  // невибухаючим: `undefined.toLocaleString` кидає і забирає екран у
  // ErrorBoundary, а NaN друкує «$NaN» просто в картку. Обидва варіанти гірші
  // за прочерк. Гарди на місцях виклику лишаються — це остання сітка, не
  // дозвіл передавати сюди що завгодно.
  if (!Number.isFinite(amount)) return '—'
  return `${currencySymbol(currency)}${amount.toLocaleString('uk-UA')}`
}

export function formatLeaseDate(d: string): string {
  const dt = new Date(d)
  // Нерозпізнаний рядок давав літеральне «Invalid Date» просто в картку.
  if (Number.isNaN(dt.getTime())) return '—'
  return dt.toLocaleDateString('uk-UA', { day: '2-digit', month: '2-digit', year: 'numeric' })
}

export function formatLeasePeriod(start?: string | null, end?: string | null): string | null {
  if (!start && !end) return null
  if (start && end) return `${formatLeaseDate(start)} — ${formatLeaseDate(end)}`
  if (start) return `від ${formatLeaseDate(start)}`
  return `до ${formatLeaseDate(end!)}`
}

export function formatDate(iso: string): string {
  const d = new Date(iso)
  if (Number.isNaN(d.getTime())) return '—'
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

// Which area a per-m² rate multiplies by. Owners choose per object (form
// toggle); default is 'total' (розрахункова, the renamed area_total). When the
// chosen area is missing, fall back to the other so nothing computes to zero.
export function basisArea(
  areaUseful: number | null | undefined,
  areaTotal: number | null | undefined,
  areaBasis: string | null | undefined,
): number {
  const chosen = areaBasis === 'useful' ? areaUseful : areaTotal
  const fallback = areaBasis === 'useful' ? areaTotal : areaUseful
  return chosen ?? fallback ?? 0
}

// Numeric key for floor sorting. Floors are free-text ("1", "-1", "B-1", "МП",
// "підвал"); take the leading signed integer so "-1" < "1" < "2" < "10", and
// push floors with no number (parking levels, "підвал") to the end.
export function floorSortKey(floor?: string | null): number {
  const m = floor?.match(/-?\d+/)
  return m ? parseInt(m[0], 10) : Number.POSITIVE_INFINITY
}

export function calcRent(areaUseful: number, rentRate: number, rentType: string): number {
  // per_m2 multiplies by useful area; fixed (monthly) and per_day (daily) store
  // the rate itself. calcRent returns the raw figure for that unit — for a
  // per_day spot that's the DAILY rate; monthlyRent() below scales it to a month.
  //
  // Невідома ставка — це НУЛЬ, а не NaN: сирий NaN їхав далі в підсумки (сума
  // ставала NaN цілком) і в компаратор сортування «за орендою», де будь-яке
  // порівняння з NaN дає false, тобто порядок ставав довільним.
  const rate = Number.isFinite(rentRate) ? rentRate : 0
  if (rentType === 'fixed' || rentType === 'per_day') return rate
  const area = Number.isFinite(areaUseful) ? areaUseful : 0
  return Math.round(area * rate)
}

// Monthly value of a rent, used only for income aggregations (dashboard stats,
// payment calendar). A daily parking rate is projected across ~30 days.
const DAYS_PER_MONTH = 30
export function monthlyRent(areaUseful: number, rentRate: number, rentType: string): number {
  // Власна гілка per_day не йде через calcRent, тож гард потрібен і тут: цією
  // функцією рахуються АГРЕГАТИ (дохід дашборда, підсумки календаря), а один
  // паркінг без добової ставки зробив би NaN усю суму, не свій рядок.
  if (rentType === 'per_day') {
    return Number.isFinite(rentRate) ? Math.round(rentRate * DAYS_PER_MONTH) : 0
  }
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
  areaBasis?: string | null,
): { rent: number; utils: number; total: number } {
  // per_m2 multiplies rate × the chosen basis area (корисна/розрахункова);
  // fixed/per_day carry the rate itself, so they must NOT be gated on area (a
  // fixed monthly rent or a parking spot with no m² still has a rent).
  const rt = rentType ?? 'per_m2'
  const area = basisArea(areaUseful, areaTotal, areaBasis)
  const rent = rentRate ? calcRent(area, rentRate, rt) : 0
  // Expenses (експлуатаційні) are $/m² × the basis area for objects that carry a
  // розрахункова (total) area; a flat monthly charge otherwise — parking has a
  // single area and no total, so its expenses stay flat.
  const utils = utilitiesRate ? (areaTotal ? calcUtilities(area, utilitiesRate) : Math.round(utilitiesRate)) : 0
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

// Єдине джерело стопів для кольору мітки бази. Раніше пікер (DB_COLORS) і
// сама іконка (GLASS_GRADS в Icons.tsx) малювались із РІЗНИХ палітр: «teal»
// у пікері виглядав другим блакитним і після вибору ставав бірюзовим на
// іконці — «обираєш одне, отримуєш інше». Icons.tsx деривує свої градієнти
// звідси; glow-кольори лишаються локально в Icons.
export const DB_COLOR_STOPS: Record<string, { from: string; to: string }> = {
  purple: { from: '#D4B8FF', to: '#7330E0' },
  blue:   { from: '#8CC8FF', to: '#1D52E0' },
  green:  { from: '#9FF4B4', to: '#1F9C4C' },
  orange: { from: '#FFCF8C', to: '#D9700F' },
  pink:   { from: '#FFB0DA', to: '#D62B8C' },
  teal:   { from: '#8FF8E4', to: '#0E9C92' },
}

export const DB_COLORS: Record<string, string> = Object.fromEntries(
  Object.entries(DB_COLOR_STOPS).map(([name, { from, to }]) => [name, `linear-gradient(135deg,${from},${to})`])
)

// Cancelled by the next focus event so rapid tab-through doesn't stack scrolls.
let _scrollTimer: ReturnType<typeof setTimeout> | undefined

/**
 * onFocusCapture handler: scrolls the focused input/textarea into view once the
 * on-screen keyboard has opened. Telegram's webview overlays the keyboard without
 * resizing the layout viewport on iOS, so fields below the fold stay hidden.
 * Two-pass: immediate nearest-scroll (no jank) + a delayed MINIMAL nudge after
 * the iOS keyboard finishes opening (~500 ms) that reveals the field only if it
 * is actually obscured. It deliberately does NOT re-center: force-centering every
 * focused field yanked already-visible fields to mid-screen on each focus, which
 * read as the caret "jumping" between fields while typing.
 */
export function scrollFocusedIntoView(e: import('react').FocusEvent<HTMLElement>): void {
  const el = e.target as HTMLElement
  const tag = el?.tagName
  if (tag !== 'INPUT' && tag !== 'TEXTAREA' && tag !== 'SELECT') return

  clearTimeout(_scrollTimer)

  // Pass 1: bring element into the layout viewport with no animation.
  // 'nearest' avoids jarring jumps when the element is already partially visible.
  el.scrollIntoView({ behavior: 'instant' as ScrollBehavior, block: 'nearest' })

  // Pass 2: once the keyboard is fully open, nudge by the MINIMUM needed to clear
  // the sticky header (top) or the keyboard (bottom). A field already comfortably
  // in view is left exactly where it is — no re-centering, no jump.
  _scrollTimer = setTimeout(() => {
    const vh = window.visualViewport?.height ?? window.innerHeight
    const rect = el.getBoundingClientRect()
    const TOP_GAP = 56    // keep clear of the sticky header
    const BOTTOM_GAP = 20 // small breathing room above the keyboard
    let delta = 0
    if (rect.bottom > vh - BOTTOM_GAP) delta = rect.bottom - (vh - BOTTOM_GAP)
    else if (rect.top < TOP_GAP) delta = rect.top - TOP_GAP
    if (delta === 0) return // already visible — do nothing

    // Скрол-контейнер екрана — `.body`; шита модалки — `.modal-body`. Без другого
    // селектора цей прохід мовчки нічого не знаходив усередині будь-якої з 16
    // модалок і падав на грубіший `el.scrollIntoView` нижче, який не знає про
    // TOP_GAP/BOTTOM_GAP і не координується зі sticky-кнопками модалки.
    const scrollParent = el.closest('.body, .modal-body') as HTMLElement | null
    if (scrollParent) scrollParent.scrollBy({ top: delta, behavior: 'smooth' })
    else el.scrollIntoView({ behavior: 'smooth', block: 'nearest' })
  }, 500)
}

/**
 * Пошук за КЛЮЧОВОЮ ФРАЗОЮ, а не за точним підрядком.
 *
 * Дві причини, чому підрядка мало (обидві — з реальної бази користувача):
 *  • назви довгі й зі службовими вставками — «Офіс 10 поверху ( мале крило )».
 *    Запит «офіс мале» як підрядок не збігається НІ з чим, хоч людина ввела
 *    дві правильні ознаки того самого об'єкта;
 *  • шукають не лише за назвою — за орендарем, адресою, поверхом.
 *
 * Тому: запит ріжеться на токени по пробілах, і КОЖЕН мусить зустрітись у
 * будь-якому з полів. Порядок слів не важить, зайві слова між ними — теж.
 * Порожній запит пропускає все (фільтр вимкнено).
 */
export function matchesQuery(query: string, ...fields: (string | null | undefined)[]): boolean {
  const tokens = query.toLowerCase().split(/\s+/).filter(Boolean)
  if (tokens.length === 0) return true
  const hay = fields.filter(Boolean).join(' ').toLowerCase()
  return tokens.every((t) => hay.includes(t))
}

/**
 * Найдовший токен запиту — ним звужуємо ВИБІРКУ з бази (ilike), а повний
 * багатослівний збіг лишається на `matchesQuery` уже на клієнті. Так серверний
 * запит лишається одним ilike, але не втрачає рядки через порядок слів.
 *
 * Символи, зарезервовані фільтрами PostgREST (`,`, `(`, `)`, `*`), вирізаємо:
 * назви на кшталт «Офіс ( мале крило )» інакше ламають синтаксис `or=(...)`.
 */
export function searchPattern(query: string): string {
  const tokens = query.replace(/[,()*]/g, ' ').split(/\s+/).filter(Boolean)
  return tokens.reduce((longest, t) => (t.length > longest.length ? t : longest), '')
}

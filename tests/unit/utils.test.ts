import { describe, it, expect, vi, afterEach } from 'vitest'
import {
  formatPrice, formatLeaseDate, formatLeasePeriod, formatDate,
  calcRent, calcUtilities, calcRentUtils, basisArea, floorSortKey, monthlyRent, rentUnitLabel, parkingTypeLabel,
  getInitials, greeting, withRetry, humanizeDbError, safeFileName, pluralUk, objectsWord,
  computedRentUnit, nextCopyName, bulkCreateNames, sanitizeDecimal, sanitizeInt, daysUntil,
} from '@/lib/utils'

describe('daysUntil', () => {
  const origTZ = process.env.TZ
  afterEach(() => {
    vi.useRealTimers()
    process.env.TZ = origTZ
  })
  it('lease ending "today" in a UTC+ timezone is 0, not 1 (off-by-one near local midnight)', () => {
    // dateStr — БЕЗ часу, парситься як UTC-північ; порівняння з Date.now()
    // (мить у ЛОКАЛЬНОМУ календарі) давало «через 1 день» для оренди, що
    // закінчується сьогодні, у перші 2-3 години доби для Києва (UTC+2/+3).
    process.env.TZ = 'Europe/Kyiv'
    vi.useFakeTimers()
    // 2026-01-14T23:30Z = 2026-01-15 01:30 Київ — локально вже 15-те.
    vi.setSystemTime(new Date('2026-01-14T23:30:00Z'))
    expect(daysUntil('2026-01-15')).toBe(0)
  })
  it('lease ending tomorrow (local) is 1', () => {
    process.env.TZ = 'Europe/Kyiv'
    vi.useFakeTimers()
    vi.setSystemTime(new Date('2026-01-14T23:30:00Z')) // локально 2026-01-15 01:30
    expect(daysUntil('2026-01-16')).toBe(1)
  })
})

describe('humanizeDbError', () => {
  it('maps RLS / permission errors to a no-access message', () => {
    expect(humanizeDbError(new Error('new row violates row-level security policy'))).toContain('доступу')
  })
  it('maps unique-violation (23505) to "already exists"', () => {
    expect(humanizeDbError(new Error('duplicate key value violates unique constraint'))).toContain('існує')
  })
  it('maps network failures to a connectivity message', () => {
    expect(humanizeDbError(new Error('TypeError: Failed to fetch'))).toContain('з\'єднання')
  })
  it('returns the fallback for unknown errors and never the raw text', () => {
    const raw = 'column "secret_internal_col" does not exist in relation xyz'
    const out = humanizeDbError(new Error(raw))
    expect(out).not.toContain('secret_internal_col')
  })
  it('accepts a custom fallback', () => {
    expect(humanizeDbError({}, 'кастом')).toBe('кастом')
  })
  it('does not throw on non-Error inputs', () => {
    expect(() => humanizeDbError(null)).not.toThrow()
    expect(() => humanizeDbError('plain string')).not.toThrow()
  })
})

describe('formatPrice', () => {
  it('prefixes USD with $', () => expect(formatPrice(1000, 'USD')).toContain('$'))
  it('prefixes EUR with €', () => expect(formatPrice(1000, 'EUR')).toContain('€'))
  it('falls back to ₴ for other currencies', () => expect(formatPrice(1000, 'UAH')).toContain('₴'))
  it('defaults to USD when no currency given', () => expect(formatPrice(500)).toContain('$'))
})

describe('formatLeasePeriod', () => {
  it('returns null when both dates absent', () =>
    expect(formatLeasePeriod(null, null)).toBeNull())
  it('joins both dates with a dash', () => {
    const r = formatLeasePeriod('2026-01-01', '2026-06-01')
    expect(r).toContain('—')
  })
  it('uses "від" when only start given', () =>
    expect(formatLeasePeriod('2026-01-01', null)).toMatch(/^від /))
  it('uses "до" when only end given', () =>
    expect(formatLeasePeriod(null, '2026-06-01')).toMatch(/^до /))
})

describe('formatLeaseDate', () => {
  it('formats as dd.mm.yyyy', () =>
    expect(formatLeaseDate('2026-03-09')).toMatch(/\d{2}\.\d{2}\.\d{4}/))
})

describe('formatDate', () => {
  const base = new Date('2026-06-12T12:00:00.000Z').getTime()
  it('"щойно" for < 1 min', () => {
    vi.setSystemTime(base)
    expect(formatDate(new Date(base - 10_000).toISOString())).toBe('щойно')
    vi.useRealTimers()
  })
  it('minutes for < 1 hour', () => {
    vi.setSystemTime(base)
    expect(formatDate(new Date(base - 30 * 60_000).toISOString())).toBe('30 хв тому')
    vi.useRealTimers()
  })
  it('hours for < 1 day', () => {
    vi.setSystemTime(base)
    expect(formatDate(new Date(base - 5 * 3_600_000).toISOString())).toBe('5 год тому')
    vi.useRealTimers()
  })
  it('"вчора" for 1 day', () => {
    vi.setSystemTime(base)
    expect(formatDate(new Date(base - 26 * 3_600_000).toISOString())).toBe('вчора')
    vi.useRealTimers()
  })
})

describe('calcRent', () => {
  it('multiplies area by rate for per_m2', () =>
    expect(calcRent(50, 20, 'per_m2')).toBe(1000))
  it('returns flat rate for fixed', () =>
    expect(calcRent(50, 20, 'fixed')).toBe(20))
  it('returns the raw rate for per_day (daily, no area multiply)', () =>
    expect(calcRent(50, 150, 'per_day')).toBe(150))
})

describe('monthlyRent', () => {
  it('projects a daily rate across ~30 days', () =>
    expect(monthlyRent(0, 150, 'per_day')).toBe(4500))
  it('matches calcRent for per_m2 and fixed', () => {
    expect(monthlyRent(50, 20, 'per_m2')).toBe(1000)
    expect(monthlyRent(50, 800, 'fixed')).toBe(800)
  })
})

describe('rentUnitLabel', () => {
  it('maps each rent type to its suffix', () => {
    expect(rentUnitLabel('per_m2')).toBe('/м²')
    expect(rentUnitLabel('per_day')).toBe('/добу')
    expect(rentUnitLabel('fixed')).toBe('/міс')
    expect(rentUnitLabel(null)).toBe('/міс')
  })
})

describe('computedRentUnit', () => {
  it('a computed monthly total is only ever /добу for per_day, else /міс', () => {
    expect(computedRentUnit('per_day')).toBe('/добу')
    // per_m2 is a RATE unit; once summed into a monthly total it reads /міс
    expect(computedRentUnit('per_m2')).toBe('/міс')
    expect(computedRentUnit('fixed')).toBe('/міс')
    expect(computedRentUnit(null)).toBe('/міс')
  })
})

describe('objectsWord (Ukrainian plural)', () => {
  it('one form for 1, 21, 101 (but not 11)', () => {
    expect(objectsWord(1)).toBe('об\'єкт')
    expect(objectsWord(21)).toBe('об\'єкт')
    expect(objectsWord(101)).toBe('об\'єкт')
  })
  it('few form for 2-4, 22-24 (but not 12-14)', () => {
    expect(objectsWord(2)).toBe('об\'єкти')
    expect(objectsWord(3)).toBe('об\'єкти')
    expect(objectsWord(24)).toBe('об\'єкти')
  })
  it('many form for 0, 5-20, 11-14, 25', () => {
    expect(objectsWord(0)).toBe('об\'єктів')
    expect(objectsWord(5)).toBe('об\'єктів')
    expect(objectsWord(11)).toBe('об\'єктів')
    expect(objectsWord(12)).toBe('об\'єктів')
    expect(objectsWord(14)).toBe('об\'єктів')
    expect(objectsWord(25)).toBe('об\'єктів')
  })
  it('pluralUk picks the passed forms', () =>
    expect(pluralUk(3, 'база', 'бази', 'баз')).toBe('бази'))
})

describe('sanitizeDecimal / sanitizeInt', () => {
  it('comma becomes a dot, only one dot survives', () => {
    expect(sanitizeDecimal('12,5')).toBe('12.5')
    expect(sanitizeDecimal('12.5.7')).toBe('12.57')
    expect(sanitizeDecimal('1,2,3')).toBe('1.23')
  })
  it('strips everything but digits and the dot', () => {
    expect(sanitizeDecimal('12e5')).toBe('125')
    expect(sanitizeDecimal('-40')).toBe('40')
    expect(sanitizeDecimal('₴1 800')).toBe('1800')
  })
  it('intermediate states stay visible (no blanking)', () => {
    expect(sanitizeDecimal('45.')).toBe('45.')
    expect(sanitizeDecimal('.')).toBe('.')
  })
  it('pasted grouped amounts parse as the number the user sees', () => {
    expect(sanitizeDecimal('1,200,000')).toBe('1200000')
    expect(sanitizeDecimal('1.200.000')).toBe('1200000')
    expect(sanitizeDecimal('1,200,50')).toBe('1200.50')
    expect(sanitizeDecimal('1 200 000')).toBe('1200000')
  })
  it('grouping heuristic does not break live typing', () => {
    expect(sanitizeDecimal('12.5.7')).toBe('12.57') // no 3-digit inner group → typing rule
    expect(sanitizeDecimal('12.5.')).toBe('12.5')
  })
  it('sanitizeInt keeps digits only', () => {
    expect(sanitizeInt('2 8')).toBe('28')
    expect(sanitizeInt('-5')).toBe('5')
    expect(sanitizeInt('day 7')).toBe('7')
  })
})

describe('nextCopyName', () => {
  it('increments a trailing number and keeps zero-padding', () => {
    expect(nextCopyName('Офіс 101', ['Офіс 101'])).toBe('Офіс 102')
    expect(nextCopyName('A-09', ['A-09'])).toBe('A-10')
  })
  it('skips names that are already taken', () => {
    expect(nextCopyName('Офіс 101', ['Офіс 101', 'Офіс 102', 'Офіс 103'])).toBe('Офіс 104')
  })
  it('appends «копія» when there is no trailing number', () => {
    expect(nextCopyName('Склад', ['Склад'])).toBe('Склад (копія)')
    expect(nextCopyName('Склад', ['Склад', 'Склад (копія)'])).toBe('Склад (копія 2)')
  })
})

describe('bulkCreateNames', () => {
  it('runs a numeric sequence from the entered name, padding preserved', () => {
    expect(bulkCreateNames('Офіс 101', 3, [])).toEqual(['Офіс 101', 'Офіс 102', 'Офіс 103'])
    expect(bulkCreateNames('A-08', 3, [])).toEqual(['A-08', 'A-09', 'A-10'])
  })
  it('skips taken names inside the run', () => {
    expect(bulkCreateNames('Офіс 101', 3, ['Офіс 102'])).toEqual(['Офіс 101', 'Офіс 103', 'Офіс 104'])
  })
  it('appends an index when there is no trailing number', () => {
    expect(bulkCreateNames('Місце', 3, [])).toEqual(['Місце 1', 'Місце 2', 'Місце 3'])
    expect(bulkCreateNames('Місце', 2, ['Місце 1'])).toEqual(['Місце 2', 'Місце 3'])
  })
  it('count 1 returns just the trimmed name', () => {
    expect(bulkCreateNames(' Офіс 5 ', 1, [])).toEqual(['Офіс 5'])
  })
})

describe('parkingTypeLabel', () => {
  it('translates known kinds, null otherwise', () => {
    expect(parkingTypeLabel('underground')).toBe('Підземний')
    expect(parkingTypeLabel('covered')).toBe('Критий')
    expect(parkingTypeLabel('open')).toBe('Просто неба')
    expect(parkingTypeLabel(null)).toBeNull()
    expect(parkingTypeLabel('nonsense')).toBeNull()
  })
})

describe('calcUtilities', () => {
  it('multiplies total area by utilities rate', () =>
    expect(calcUtilities(100, 5)).toBe(500))
})

describe('floorSortKey', () => {
  it('sorts floors ground-up by the leading signed number (10 after 2, basement first)', () => {
    const floors = ['10', '2', '-1', '1']
    const sorted = [...floors].sort((a, b) => floorSortKey(a) - floorSortKey(b))
    expect(sorted).toEqual(['-1', '1', '2', '10'])
  })
  it('pushes floors with no number (parking levels) to the end', () => {
    expect(floorSortKey('МП')).toBe(Number.POSITIVE_INFINITY)
    expect(floorSortKey('підвал')).toBe(Number.POSITIVE_INFINITY)
    expect(floorSortKey(undefined)).toBe(Number.POSITIVE_INFINITY)
    expect(floorSortKey('')).toBe(Number.POSITIVE_INFINITY)
  })
  it('parses the signed integer', () => {
    expect(floorSortKey('1')).toBe(1)
    expect(floorSortKey('-1')).toBe(-1)
    expect(floorSortKey('B-1')).toBe(-1)
  })
})

describe('basisArea', () => {
  it('picks the chosen area', () => {
    expect(basisArea(50, 100, 'useful')).toBe(50)
    expect(basisArea(50, 100, 'total')).toBe(100)
  })
  it('defaults to total (розрахункова) when basis is null/undefined', () => {
    expect(basisArea(50, 100, undefined)).toBe(100)
    expect(basisArea(50, 100, null)).toBe(100)
  })
  it('falls back to the other area when the chosen one is missing', () => {
    expect(basisArea(50, null, 'total')).toBe(50)   // wanted total, only useful set
    expect(basisArea(null, 100, 'useful')).toBe(100) // wanted useful, only total set
    expect(basisArea(null, null, 'total')).toBe(0)
  })
})

describe('calcRentUtils', () => {
  it('default basis is total (розрахункова): rent & expenses use area_total', () => {
    const r = calcRentUtils(50, 100, 20, 'per_m2', 5) // no basis → total
    expect(r.rent).toBe(2000)   // 100 × 20
    expect(r.utils).toBe(500)   // 100 × 5
    expect(r.total).toBe(2500)
  })
  it("basis 'useful' multiplies both by area_useful", () => {
    const r = calcRentUtils(50, 100, 20, 'per_m2', 5, 'useful')
    expect(r.rent).toBe(1000)   // 50 × 20
    expect(r.utils).toBe(250)   // 50 × 5
  })
  it("basis 'total' multiplies both by area_total", () =>
    expect(calcRentUtils(50, 100, 20, 'per_m2', 5, 'total').total).toBe(2000 + 500))
  it('flat rent (fixed) ignores area; expenses still scale on the basis area', () =>
    expect(calcRentUtils(50, 100, 800, 'fixed', 5, 'total').total).toBe(800 + 500))
  it('per_day rent carries the daily rate, not gated on area', () =>
    expect(calcRentUtils(0, null, 150, 'per_day', null).rent).toBe(150))
  it('rent is 0 when the rate is missing', () =>
    expect(calcRentUtils(50, 100, null, 'per_m2', 5).rent).toBe(0))
  it('expenses are flat (no total area) for parking, $/m² otherwise', () => {
    // parking: single area, no total → flat charge regardless of basis
    expect(calcRentUtils(13, null, 0, 'fixed', 30, 'useful').utils).toBe(30)
    expect(calcRentUtils(50, 100, 20, 'per_m2', 5).utils).toBe(500)
    expect(calcRentUtils(50, 100, 20, 'per_m2', null).utils).toBe(0)
  })
  it('total for per_day is MONTHLY-normalized, not raw-daily + monthly-utils', () => {
    // Реальний баг: total раніше рахував rent(добова ставка) + utils(місячна
    // сума) — ExportScreen (PDF/XLSX) друкував цю суміш як «Разом на місяць».
    // $150/добу паркомісце + $30/міс експлуатаційні → $4500 + $30, НЕ $150 + $30.
    const r = calcRentUtils(0, null, 150, 'per_day', 30)
    expect(r.rent).toBe(150)   // сира добова ставка — так і мусить лишитись (показ поряд із «/добу»)
    expect(r.utils).toBe(30)
    expect(r.total).toBe(4530) // 150×30 + 30, НЕ 150+30=180
  })
})

describe('safeFileName', () => {
  it('keeps Latin, Cyrillic and digits, collapses the rest to single _', () => {
    expect(safeFileName('БЦ Рубін 2', 'pdf')).toMatch(/^БЦ_Рубін_2_\d{4}-\d{2}-\d{2}\.pdf$/)
  })
  it('strips path separators and control chars that could escape the directory', () => {
    const out = safeFileName('../../etc/passwd', 'xlsx')
    expect(out).not.toContain('/')
    expect(out).not.toContain('..')
    expect(out).toMatch(/\.xlsx$/)
  })
  it('falls back to "export" when the name has no usable characters', () => {
    expect(safeFileName('!!!', 'pdf')).toMatch(/^export_\d{4}-\d{2}-\d{2}\.pdf$/)
  })
})

describe('getInitials', () => {
  it('combines first + last initial uppercased', () =>
    expect(getInitials('петро', 'іванов')).toBe('ПІ'))
  it('handles missing last name', () =>
    expect(getInitials('петро')).toBe('П'))
})

describe('greeting', () => {
  it('returns one of the three Ukrainian greetings', () =>
    expect(['Доброго ранку', 'Добрий день', 'Добрий вечір']).toContain(greeting()))
})

describe('withRetry', () => {
  it('returns immediately on success', async () => {
    const fn = vi.fn().mockResolvedValue({ data: 'ok', error: null })
    const r = await withRetry(fn)
    expect(r.data).toBe('ok')
    expect(fn).toHaveBeenCalledTimes(1)
  })

  it('does NOT retry on 4xx errors', async () => {
    const fn = vi.fn().mockResolvedValue({ data: null, error: { message: 'bad', status: 400 } })
    const r = await withRetry(fn, 3)
    expect(r.error?.status).toBe(400)
    expect(fn).toHaveBeenCalledTimes(1)
  })

  it('retries on 5xx then succeeds', async () => {
    const fn = vi.fn()
      .mockResolvedValueOnce({ data: null, error: { message: 'boom', status: 500 } })
      .mockResolvedValueOnce({ data: 'recovered', error: null })
    const r = await withRetry(fn, 3)
    expect(r.data).toBe('recovered')
    expect(fn).toHaveBeenCalledTimes(2)
  })
})

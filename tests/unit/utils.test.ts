import { describe, it, expect, vi } from 'vitest'
import {
  formatPrice, formatLeaseDate, formatLeasePeriod, formatDate,
  calcRent, calcUtilities, calcRentUtils, monthlyRent, rentUnitLabel, parkingTypeLabel,
  getInitials, greeting, withRetry, humanizeDbError, safeFileName, pluralUk, objectsWord,
  computedRentUnit,
} from '@/lib/utils'

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

describe('calcRentUtils', () => {
  it('sums rent + utilities (per_m2)', () =>
    expect(calcRentUtils(50, 100, 20, 'per_m2', 5).total).toBe(1000 + 500))
  it('sums flat rent + utilities (fixed rent ignores area)', () =>
    expect(calcRentUtils(50, 100, 800, 'fixed', 5).total).toBe(800 + 500))
  it('per_day rent carries the daily rate, not gated on area', () =>
    expect(calcRentUtils(0, null, 150, 'per_day', null).rent).toBe(150))
  it('rent is 0 when rate missing; per_m2 with no area is 0', () => {
    expect(calcRentUtils(null, 100, 20, 'per_m2', 5).rent).toBe(0)
    expect(calcRentUtils(50, 100, null, 'per_m2', 5).rent).toBe(0)
  })
  it('utils are $/m² with a total area, flat charge without one (parking)', () => {
    expect(calcRentUtils(50, 100, 20, 'per_m2', 5).utils).toBe(500)
    expect(calcRentUtils(13, null, 0, 'fixed', 30).utils).toBe(30)
    expect(calcRentUtils(50, 100, 20, 'per_m2', null).utils).toBe(0)
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

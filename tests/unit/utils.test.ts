import { describe, it, expect, vi } from 'vitest'
import {
  formatPrice, formatLeaseDate, formatLeasePeriod, formatDate,
  calcRent, calcUtilities, calcRentUtils, getInitials, greeting, withRetry,
  humanizeDbError, safeFileName,
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
  it('rent is 0 when rate or useful area missing', () => {
    expect(calcRentUtils(null, 100, 20, 'per_m2', 5).rent).toBe(0)
    expect(calcRentUtils(50, 100, null, 'per_m2', 5).rent).toBe(0)
  })
  it('utils keyed off total area, 0 when missing', () => {
    expect(calcRentUtils(50, null, 20, 'per_m2', 5).utils).toBe(0)
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

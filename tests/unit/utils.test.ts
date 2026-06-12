import { describe, it, expect, vi } from 'vitest'
import {
  formatPrice, formatArea, formatLeaseDate, formatLeasePeriod, formatDate,
  calcRent, calcUtilities, calcTotal, getInitials, freshnessLabel, withRetry,
} from '@/lib/utils'

describe('formatPrice', () => {
  it('prefixes USD with $', () => expect(formatPrice(1000, 'USD')).toContain('$'))
  it('prefixes EUR with €', () => expect(formatPrice(1000, 'EUR')).toContain('€'))
  it('falls back to ₴ for other currencies', () => expect(formatPrice(1000, 'UAH')).toContain('₴'))
  it('defaults to USD when no currency given', () => expect(formatPrice(500)).toContain('$'))
})

describe('formatArea', () => {
  it('appends м²', () => expect(formatArea(42)).toBe('42 м²'))
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

describe('calcTotal', () => {
  it('sums rent + utilities (per_m2)', () =>
    expect(calcTotal(50, 100, 20, 'per_m2', 5)).toBe(1000 + 500))
  it('sums flat rent + utilities', () =>
    expect(calcTotal(50, 100, 800, 'fixed', 5)).toBe(800 + 500))
})

describe('getInitials', () => {
  it('combines first + last initial uppercased', () =>
    expect(getInitials('петро', 'іванов')).toBe('ПІ'))
  it('handles missing last name', () =>
    expect(getInitials('петро')).toBe('П'))
})

describe('freshnessLabel', () => {
  it('today => fresh', () =>
    expect(freshnessLabel(new Date().toISOString()).cls).toBe('fresh'))
  it('5 days => stale', () => {
    const d = new Date(Date.now() - 5 * 86_400_000).toISOString()
    expect(freshnessLabel(d).cls).toBe('stale')
  })
  it('30 days => old', () => {
    const d = new Date(Date.now() - 30 * 86_400_000).toISOString()
    expect(freshnessLabel(d).cls).toBe('old')
  })
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

import { describe, it, expect, beforeAll, afterAll } from 'vitest'
import { expectedRentAt, termsAt, type RentTermsRow } from '@/lib/rentPayments'

/**
 * Умови на дату платежу (072). Історія зберігає СТАРІ умови з міткою, до якої
 * вони діяли; умови на дату D — найраніший рядок, що діяв після D, а без
 * такого — поточні умови обʼєкта.
 *
 * Пояс заморожений на Київ: межа рахується в ЛОКАЛЬНИХ днях, і саме в
 * додатному поясі UTC-день зміни відрізняється від локального вночі.
 */
const prevTZ = process.env.TZ
beforeAll(() => { process.env.TZ = 'Europe/Kyiv' })
afterAll(() => { process.env.TZ = prevTZ })

const office = {
  id: 'p1',
  rent_rate: 2000,
  rent_type: 'fixed' as const,
  area_useful: null,
  area_total: 50,
  area_basis: 'total' as const,
}

function row(over: Partial<RentTermsRow>): RentTermsRow {
  return {
    property_id: 'p1', rent_rate: 1800, rent_type: 'fixed', area_basis: 'total',
    area_useful: null, area_total: 50, valid_until: '2026-10-10T09:00:00+00:00',
    ...over,
  }
}

describe('termsAt / expectedRentAt', () => {
  it('борг ДО підняття ставки рахується за старою ставкою, після — за новою', () => {
    const history = [row({})]
    expect(expectedRentAt(office, history, '2026-08-05')).toBe(1800)
    expect(expectedRentAt(office, history, '2026-09-05')).toBe(1800)
    expect(expectedRentAt(office, history, '2026-11-05')).toBe(2000)
  })

  it('зміна в САМ день платежу діє на цей платіж', () => {
    // Вписав нову ставку 5 листопада, маючи на увазі листопад.
    const history = [row({ valid_until: '2026-11-05T10:00:00+00:00' })]
    expect(expectedRentAt(office, history, '2026-11-05')).toBe(2000)
    expect(expectedRentAt(office, history, '2026-11-04')).toBe(1800)
  })

  it('межа — ЛОКАЛЬНИЙ день: зміна о 00:30 за Києвом — це вже наступна дата', () => {
    // 22:30 UTC 4 листопада = 00:30 5 листопада за Києвом (UTC+2 узимку).
    const history = [row({ valid_until: '2026-11-04T22:30:00+00:00' })]
    expect(expectedRentAt(office, history, '2026-11-05')).toBe(2000)
  })

  it('кілька змін: кожна дата бере умови СВОГО проміжку — незалежно від порядку рядків', () => {
    // Обидва порядки: «перший, що підійшов» пройшов би на зростаючому, а
    // «останній, що підійшов» — на спадному. Правильний — найРАНІШИЙ за міткою.
    const a = row({ rent_rate: 1800, valid_until: '2026-09-20T09:00:00+00:00' })
    const b = row({ rent_rate: 1900, valid_until: '2026-10-20T09:00:00+00:00' })
    for (const history of [[a, b], [b, a]]) {
      expect(expectedRentAt(office, history, '2026-09-05')).toBe(1800)
      expect(expectedRentAt(office, history, '2026-10-05')).toBe(1900)
      expect(expectedRentAt(office, history, '2026-11-05')).toBe(2000)
    }
  })

  it('$/м²: стара площа теж зберігається, а не лише ставка', () => {
    const perM2 = { ...office, rent_type: 'per_m2' as const, rent_rate: 40, area_total: 60 }
    const history = [row({ rent_type: 'per_m2', rent_rate: 36, area_total: 50 })]
    expect(expectedRentAt(perM2, history, '2026-09-05')).toBe(1800)
    expect(expectedRentAt(perM2, history, '2026-11-05')).toBe(2400)
  })

  it('рядок без ставки пропускається: «не вписали» ≠ «оренда коштувала нуль»', () => {
    const history = [
      row({ rent_rate: null, valid_until: '2026-09-01T09:00:00+00:00' }),
    ]
    expect(expectedRentAt(office, history, '2026-08-05')).toBe(2000)
  })

  it('чужий обʼєкт і відсутня історія (бекенд без 072) — поточні умови', () => {
    expect(expectedRentAt(office, [row({ property_id: 'p2' })], '2026-08-05')).toBe(2000)
    expect(expectedRentAt(office, null, '2026-08-05')).toBe(2000)
    expect(termsAt(office, null, '2026-08-05')).toBe(office)
  })
})

import { describe, it, expect } from 'vitest'
import { expectedRent } from '../../src/lib/rentPayments'
import { calcRentUtils, basisArea, monthlyRent } from '../../src/lib/utils'
import type { Property } from '../../src/types'

/**
 * ОДИН ОБʼЄКТ — ОДНА СУМА, НА ВСІХ ПОВЕРХНЯХ.
 *
 * Дефект, заради якого це написано: `expectedRent` множила ставку на сиру
 * `area_useful`, тоді як картка, деталь, експорт і /v рахували через
 * `basisArea`. Для обʼєкта з `area_basis='total'` картка казала $1 800, а
 * календар платежів — $900; гірше, саме число календаря лягало в
 * `rent_payment_records.amount`, тобто ставало архівним записом про те,
 * скільки нібито отримали.
 *
 * Юніт-рівень тут сильніший за e2e: він порівнює саме ФОРМУЛИ, а не те, що
 * встигло відрендеритись, і не залежить від фікстур конкретного екрана.
 */

function prop(over: Partial<Property> = {}): Property {
  return {
    id: 'p1', db_id: 'd1', owner_id: 'o1', name: 'Офіс 101',
    status: 'occupied', rent_type: 'per_m2', rent_rate: 18,
    area_useful: 50, area_total: 100, area_basis: 'total',
    utilities_rate: null, has_parking: false, parking_spaces: 0,
    created_at: '2025-01-01', updated_at: '2025-01-01',
    ...over,
  } as Property
}

/** Оренда без експлуатаційних — те саме, що календар показує як суму до сплати. */
const rentOnly = (p: Property) => {
  const { total, utils } = calcRentUtils(
    p.area_useful, p.area_total, p.rent_rate, p.rent_type, p.utilities_rate, p.area_basis)
  return total - utils
}

describe('узгодженість грошей між поверхнями', () => {
  it.each([
    ['база total (дефолт)', { area_basis: 'total' as const }],
    ['база useful',         { area_basis: 'useful' as const }],
    ['база не задана',      { area_basis: undefined }],
    ['лише корисна площа',  { area_total: null, area_basis: 'total' as const }],
    ['лише розрахункова',   { area_useful: null, area_basis: 'useful' as const }],
    ['фіксована ставка',    { rent_type: 'fixed' as const, rent_rate: 25000 }],
    ['подобова',            { rent_type: 'per_day' as const, rent_rate: 900 }],
  ])('%s: календар збігається з карткою', (_label, over) => {
    const p = prop(over as Partial<Property>)
    expect(expectedRent(p), 'сума в календарі розійшлась із карткою обʼєкта')
      .toBe(rentOnly(p))
  })

  it('база розрахунку РЕАЛЬНО впливає — інакше тест вище вакуумний', () => {
    // Якщо `basisArea` колись почне ігнорувати базу, усі кейси вище збігатимуться
    // тривіально і нічого не доводитимуть.
    const useful = prop({ area_basis: 'useful' })
    const total = prop({ area_basis: 'total' })
    expect(expectedRent(useful)).not.toBe(expectedRent(total))
    expect(expectedRent(useful)).toBe(50 * 18)
    expect(expectedRent(total)).toBe(100 * 18)
  })

  it('порожня корисна площа при базі total не обнуляє суму', () => {
    // Раніше `expectedRent` брала `area_useful ?? 0`, тож обʼєкт із заповненою
    // лише розрахунковою площею давав 0 — календар не показував суми ВЗАГАЛІ,
    // а форма підтвердження відкривалась з порожнім полем.
    const p = prop({ area_useful: null, area_total: 100, area_basis: 'total' })
    expect(expectedRent(p)).toBe(1800)
  })

  it('монотонність: більша площа — більша сума (per_m2)', () => {
    const small = prop({ area_total: 50 })
    const big = prop({ area_total: 200 })
    expect(expectedRent(big)).toBeGreaterThan(expectedRent(small))
  })

  it('нульова ставка дає нуль, а не NaN', () => {
    expect(expectedRent(prop({ rent_rate: null }))).toBe(0)
    expect(Number.isFinite(expectedRent(prop({ rent_rate: null })))).toBe(true)
  })

  it('monthlyRent і basisArea узгоджені для per_day', () => {
    const p = prop({ rent_type: 'per_day', rent_rate: 900, area_basis: 'total' })
    expect(expectedRent(p)).toBe(monthlyRent(basisArea(p.area_useful, p.area_total, p.area_basis), 900, 'per_day'))
  })
})

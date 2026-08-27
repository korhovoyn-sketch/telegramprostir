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

/**
 * ЩО САМЕ ДРУКУЄ КОЖНА ПОВЕРХНЯ — не друга форма того самого виразу.
 *
 * Попередня версія цього файлу порівнювала `expectedRent(p)` з
 * `calcRentUtils(...).total - utils`. Але `total` за побудовою дорівнює
 * `monthlyRent(basisArea(...)) + utils`, тож обидві сторони скорочувались до
 * `monthlyRent(basisArea(...))` — рівність трималась би за БУДЬ-ЯКОЇ
 * реалізації, включно зі зламаною. Тобто тест був тавтологією з видом гарда.
 *
 * Тепер очікування ЗАКРІПЛЕНІ числом. Число — єдине, що не скорочується.
 */

/** Те, що показує картка обʼєкта (`DatabaseObjectsScreen.renderCard`). */
function cardShows(p: Property): number {
  const { rent, total } = calcRentUtils(
    p.area_useful, p.area_total, p.rent_rate, p.rent_type, p.utilities_rate, p.area_basis, false)
  // Добова ставка не додається до місячних експлуатаційних — картка показує
  // сиру ставку з підписом «/добу».
  return p.rent_type === 'per_day' ? rent : total
}

describe('узгодженість грошей між поверхнями', () => {
  // Фікстура: корисна 50, розрахункова 100, ставка 18/м².
  it.each([
    // підпис,                 переозначення,                                    календар, картка
    ['база total (дефолт)',    { area_basis: 'total' as const },                     1800, 1800],
    ['база useful',            { area_basis: 'useful' as const },                     900,  900],
    ['база не задана → total', { area_basis: undefined },                            1800, 1800],
    ['лише корисна площа',     { area_total: null, area_basis: 'total' as const },     900,  900],
    ['фіксована ставка',       { rent_type: 'fixed' as const, rent_rate: 25000 },    25000, 25000],
    // Подобова — ЄДИНИЙ випадок, де поверхні свідомо різняться, і це не
    // дефект: картка показує СИРУ ставку з підписом «/добу» (те, що власник
    // бере за добу), календар — місячний еквівалент до сплати (900 × 30).
    // Закріплено обидва числа саме тому, що рівності тут бути НЕ повинно.
    ['подобова',               { rent_type: 'per_day' as const, rent_rate: 900 },    27000,  900],
  ])('%s', (_label, over, wantCalendar, wantCard) => {
    const p = prop(over as Partial<Property>)
    // Календар (він же префіл підтвердження платежу і блок «Найближчі платежі»).
    expect(expectedRent(p), 'сума до сплати в календарі').toBe(wantCalendar)
    // Картка списку — те, що власник бачить першим.
    expect(cardShows(p), 'сума на картці обʼєкта').toBe(wantCard)
  })

  it('експлуатаційні входять у ТОТАЛ картки, але не в суму до сплати', () => {
    // Це не тавтологія, а справжня різниця поверхонь: календар питає «скільки
    // орендар винен ЗА ОРЕНДУ», картка показує повну місячну вартість.
    const p = prop({ area_basis: 'total', utilities_rate: 2.5 })
    expect(expectedRent(p), 'календар — лише оренда').toBe(1800)
    expect(cardShows(p), 'картка — оренда + експлуатаційні').toBe(1800 + 250)
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

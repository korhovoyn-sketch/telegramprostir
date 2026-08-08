import { describe, it, expect } from 'vitest'
import {
  formatPrice, calcRent, calcRentUtils, monthlyRent, basisArea,
  formatDate, formatLeaseDate, formatLeasePeriod,
  pluralUk, objectsWord, sanitizeDecimal, sanitizeInt, nextCopyName,
} from '@/lib/utils'

// У текст інтерфейсу не має просочуватись НІ сміття («$NaN», «undefined»), НІ
// виняток. `formatPrice(undefined)` раніше кидав `Cannot read properties of
// undefined (reading 'toLocaleString')` — а це вже не косметика, а екран у
// ErrorBoundary. Гарди на місцях виклику є, але через цей форматер проходять усі
// гроші застосунку, тож він мусить витримувати будь-що.

const GARBAGE = /NaN|undefined|null|Infinity/

/** Значення, які реально доїжджають із БД: числа, порожнеча, сміття. */
const HOSTILE = [undefined, null, NaN, Infinity, -Infinity, 0, -1] as const

describe('formatPrice не кидає і не друкує сміття', () => {
  for (const v of HOSTILE) {
    it(`formatPrice(${String(v)})`, () => {
      let out = ''
      expect(() => { out = formatPrice(v as unknown as number) }).not.toThrow()
      expect(out, `→ «${out}»`).not.toMatch(GARBAGE)
      expect(out.length, 'порожній рядок лишив би поле без значення').toBeGreaterThan(0)
    })
  }

  it('нечислове віддає прочерк, а не символ валюти без суми', () => {
    expect(formatPrice(NaN)).toBe('—')
    expect(formatPrice(Infinity)).toBe('—')
  })

  it('справжні суми не зачеплені', () => {
    expect(formatPrice(0)).toBe('$0')
    expect(formatPrice(2160)).toContain('2')
    expect(formatPrice(1500, 'EUR')).toContain('€')
    expect(formatPrice(1500, 'UAH')).toContain('₴')
  })
})

describe('розрахунки оренди на ворожому вводі', () => {
  it('нулі та NaN не дають сміття в підсумках', () => {
    for (const args of [[0, 0], [NaN, NaN]] as const) {
      const r = calcRentUtils(args[0], args[0], args[1], 'per_m2', args[1], 'total')
      const line = `${formatPrice(r.rent)} ${formatPrice(r.utils)} ${formatPrice(r.total)}`
      expect(line, `calcRentUtils(${args.join(',')}) → ${line}`).not.toMatch(GARBAGE)
    }
  })

  it('calcRent / monthlyRent / basisArea терплять відсутні поля', () => {
    const u = undefined as unknown as number
    for (const out of [
      String(calcRent(u, u, 'per_m2')),
      String(calcRent(NaN, NaN, 'fixed')),
      String(monthlyRent(u, u, 'per_day')),
      String(monthlyRent(NaN, NaN, 'per_m2')),
      String(basisArea(undefined, undefined, undefined)),
    ]) {
      expect(out).not.toMatch(GARBAGE)
    }
  })
})

describe('дати і плюрали на ворожому вводі', () => {
  it('нерозпізнана дата не друкує «Invalid Date» чи NaN', () => {
    for (const out of [formatDate('не-дата'), formatLeaseDate('не-дата')]) {
      expect(out, `→ «${out}»`).not.toMatch(/NaN|Invalid/)
    }
  })

  it('порожній період договору віддає null, а не «null — null»', () => {
    expect(formatLeasePeriod(null, null)).toBeNull()
    expect(formatLeasePeriod(undefined, undefined)).toBeNull()
  })

  it('плюрали не ламаються на NaN', () => {
    expect(pluralUk(NaN, 'об\'єкт', 'об\'єкти', 'об\'єктів')).not.toMatch(GARBAGE)
    expect(objectsWord(NaN)).not.toMatch(GARBAGE)
  })

  it('санітайзери на сміттєвому вводі віддають порожньо, не NaN', () => {
    expect(sanitizeDecimal('абв')).toBe('')
    expect(sanitizeInt('абв')).toBe('')
    expect(nextCopyName('', []), 'порожня база імені').not.toMatch(GARBAGE)
  })
})

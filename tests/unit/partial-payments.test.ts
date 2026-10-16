import { describe, it, expect } from 'vitest'
import { isPartialRecord, isPartsUnavailable, remainingFor } from '@/lib/rentPayments'

/**
 * Часткова оплата (071) — чисті правила, якими ходять календар, форма й
 * сповіщення. Арифметику ПІДСУМКУ рахує сервер (тригер, стенд
 * `verify-behaviour.sql`); тут — лише те, що клієнт виводить із готового
 * підсумку.
 */
describe('remainingFor', () => {
  it('рахує від ЗАМОРОЖЕНОЇ суми періоду, а не від поточної ставки', () => {
    // Ставку підняли до 2500 після першого надходження — старий борг не
    // сміє вирости заднім числом.
    expect(remainingFor({ amount: 1000, amount_due: 1800 }, 2500)).toBe(800)
  })

  it('без заморожених даних (бекенд без 071) — від поточної очікуваної', () => {
    expect(remainingFor({ amount: 1000, amount_due: null }, 1800)).toBe(800)
    expect(remainingFor(null, 1800)).toBe(1800)
  })

  it('переплата — нуль, а не відʼємний залишок', () => {
    expect(remainingFor({ amount: 2000, amount_due: 1800 }, 1800)).toBe(0)
  })

  it('копійки не розповзаються в 0.30000000000000004', () => {
    expect(remainingFor({ amount: 0.1, amount_due: 0.4 }, 0)).toBe(0.3)
  })
})

describe('isPartialRecord', () => {
  it('частково — лише статус partial І гроші в ньому', () => {
    expect(isPartialRecord({ status: 'partial', amount: 1000 })).toBe(true)
    // Статус без суми — не «отримано частину», а збій даних: не обіцяємо грошей.
    expect(isPartialRecord({ status: 'partial', amount: 0 })).toBe(false)
    expect(isPartialRecord({ status: 'paid', amount: 1800 })).toBe(false)
    expect(isPartialRecord(null)).toBe(false)
  })
})

describe('isPartsUnavailable', () => {
  it('впізнає обидві форми «таблиці немає» PostgREST', () => {
    expect(isPartsUnavailable({ code: 'PGRST205', message: "Could not find the table 'public.rent_payment_parts' in the schema cache" })).toBe(true)
    expect(isPartsUnavailable({ code: '42P01', message: 'relation "public.rent_payment_parts" does not exist' })).toBe(true)
  })

  it('не плутає з іншими збоями — інакше збій мережі тихо вмикав би старий режим', () => {
    expect(isPartsUnavailable({ code: 'XX000', message: 'internal failure' })).toBe(false)
    expect(isPartsUnavailable({ message: 'Failed to fetch' })).toBe(false)
    expect(isPartsUnavailable(null)).toBe(false)
  })
})

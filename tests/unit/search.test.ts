import { describe, it, expect } from 'vitest'
import { matchesQuery, searchPattern } from '@/lib/utils'

// Репорт: «вводиш ключову фразу — не підтягує нічого». Дві причини були в тому,
// що пошук робив ОДИН підрядок ПО ОДНОМУ полю (назві).

describe('matchesQuery', () => {
  it('порожній запит пропускає все — фільтр вимкнено', () => {
    expect(matchesQuery('', 'Офіс 101')).toBe(true)
    expect(matchesQuery('   ', 'Офіс 101')).toBe(true)
  })

  it('слова запиту можуть стояти в різних місцях назви', () => {
    const name = 'Офіс 10 поверху ( мале крило )'
    // Саме цей випадок і давав «нічого»: точного підрядка немає.
    expect(name.toLowerCase().includes('офіс мале')).toBe(false)
    expect(matchesQuery('офіс мале', name)).toBe(true)
    expect(matchesQuery('мале офіс', name)).toBe(true)
    expect(matchesQuery('крило 10', name)).toBe(true)
  })

  it('КОЖЕН токен обов\'язковий — один зайвий убиває збіг', () => {
    expect(matchesQuery('офіс горище', 'Офіс 10 поверху')).toBe(false)
  })

  it('шукає по всіх переданих полях, не лише в першому', () => {
    const p = ['Офіс 101', 'ТОВ «Ромашка»', '2', 'вул. Хрещатик, 1']
    expect(matchesQuery('ромашка', ...p)).toBe(true)
    expect(matchesQuery('хрещатик', ...p)).toBe(true)
    expect(matchesQuery('ромашка хрещатик', ...p), 'токени з РІЗНИХ полів').toBe(true)
  })

  it('null/undefined поля не ламають пошук', () => {
    expect(matchesQuery('офіс', 'Офіс 101', null, undefined)).toBe(true)
    expect(matchesQuery('офіс', null, undefined)).toBe(false)
  })

  it('регістр не важить в обидві сторони', () => {
    expect(matchesQuery('ОФІС', 'офіс 101')).toBe(true)
    expect(matchesQuery('офіс', 'ОФІС 101')).toBe(true)
  })
})

describe('searchPattern', () => {
  it('віддає найдовший токен — ним звужується вибірка з БД', () => {
    expect(searchPattern('офіс мале крило')).toBe('крило')
    expect(searchPattern('  10  поверху ')).toBe('поверху')
  })

  it('вирізає символи, зарезервовані фільтрами PostgREST', () => {
    // Кома розділяє умови в or=(...), дужки — межі; незачищена назва «( мале
    // крило )» зламала б синтаксис запиту.
    expect(searchPattern('( мале, крило )')).toBe('крило')
    expect(searchPattern('*')).toBe('')
    expect(searchPattern(',,,')).toBe('')
  })

  it('порожній запит → порожній патерн (виклику до БД не буде)', () => {
    expect(searchPattern('')).toBe('')
    expect(searchPattern('   ')).toBe('')
  })
})

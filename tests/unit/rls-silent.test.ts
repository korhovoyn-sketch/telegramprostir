import { describe, it, expect } from 'vitest'
import { assertAffected, NoRowsAffectedError } from '../../src/lib/dbWrite'
import { humanizeDbError } from '../../src/lib/utils'

// Джерельний гард на клас «мовчазний провал під RLS».
//
// PostgREST не вважає заблокований запис помилкою: `.delete()`/`.update()`,
// що не пройшли політику, повертають ПОРОЖНІЙ набір і NULL у `error`. Тобто
// «видалив» і «не мав права» на дроті нерозрізненні, і клієнт за замовчуванням
// рапортує успіх.
//
// Це коштувало даних: deleteDatabase і batchDeleteProperties спершу стирали
// файли зі storage, а рядок видаляли потім — заблокований DELETE давав тост
// «Базу видалено», база лишалась жива, фото були знищені безповоротно.

describe('assertAffected', () => {
  it('пропускає, коли зачеплено рівно стільки рядків, скільки просили', () => {
    const rows = [{ id: 'a' }, { id: 'b' }]
    expect(assertAffected(rows, 2, 'видалення')).toBe(rows)
  })

  it('падає на порожньому наборі — це і є заблокований RLS', () => {
    expect(() => assertAffected([], 1, 'видалення бази')).toThrow(NoRowsAffectedError)
  })

  it('падає на null (жодного рядка не повернулось)', () => {
    expect(() => assertAffected(null, 1, 'видалення')).toThrow(NoRowsAffectedError)
    expect(() => assertAffected(undefined, 1, 'видалення')).toThrow(NoRowsAffectedError)
  })

  it('ЧАСТКОВЕ застосування — теж провал', () => {
    // Мовчки лишити половину пакета незміненою гірше, ніж сказати про це:
    // користувач бачив би «10 обʼєктів — Вільно», а звільнилось три.
    expect(() => assertAffected([{ id: 'a' }], 3, 'зміну статусу')).toThrow(NoRowsAffectedError)
  })

  it('нуль очікуваних рядків не вважається провалом', () => {
    // Порожній пакет — законний no-op, а не помилка доступу.
    expect(assertAffected([], 0, 'порожній пакет')).toEqual([])
  })

  it('несе код 42501, щоб не сплутати з мережевою помилкою', () => {
    const err = new NoRowsAffectedError('видалення')
    expect(err.code).toBe('42501')
    expect(err.name).toBe('NoRowsAffectedError')
  })
})

describe('humanizeDbError знає цей клас', () => {
  it('перетворює його на «немає доступу», а не на загальний фолбек', () => {
    // Текст помилки українською й НЕ містить жодного англомовного маркера
    // ('row-level security', 'permission denied'), тож текстові гілки її не
    // ловлять — розпізнавання йде за іменем класу.
    const msg = humanizeDbError(new NoRowsAffectedError('видалення бази'))
    expect(msg).toBe('Немає доступу до цих даних.')
    expect(msg, 'не має падати у загальний фолбек').not.toContain('Спробуйте ще раз')
  })
})

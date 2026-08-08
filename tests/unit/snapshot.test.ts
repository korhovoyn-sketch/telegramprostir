import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import { readSnapshot, writeSnapshot } from '@/lib/snapshot'

// SWR-кеш списків: холодний старт малює з localStorage, мережа доганяє тихо.
// Два інваріанти, порушення яких показує користувачу чужі/мертві дані.

const A = 'user-a'
const B = 'user-b'

beforeEach(() => localStorage.clear())
afterEach(() => vi.useRealTimers())

describe('snapshot', () => {
  it('читає те саме, що записали', () => {
    writeSnapshot('dbs', A, [{ id: '1', name: 'БЦ Рубін' }])
    expect(readSnapshot('dbs', A)).toEqual([{ id: '1', name: 'БЦ Рубін' }])
  })

  it('порожньо, коли кешу немає', () => {
    expect(readSnapshot('dbs', A)).toBeNull()
  })

  it('кеш ізольований ПО КОРИСТУВАЧУ — інший акаунт на тому ж пристрої не бачить чужого', () => {
    writeSnapshot('dbs', A, [{ id: '1', name: 'База А' }])
    expect(readSnapshot('dbs', B)).toBeNull()

    writeSnapshot('dbs', B, [{ id: '2', name: 'База Б' }])
    expect(readSnapshot('dbs', A)).toEqual([{ id: '1', name: 'База А' }])
    expect(readSnapshot('dbs', B)).toEqual([{ id: '2', name: 'База Б' }])
  })

  it('кеш ізольований по імені списку', () => {
    writeSnapshot('dbs', A, ['бази'])
    writeSnapshot('props:db1', A, ['об\'єкти'])
    expect(readSnapshot('dbs', A)).toEqual(['бази'])
    expect(readSnapshot('props:db1', A)).toEqual(['об\'єкти'])
  })

  it('старіше за добу НЕ віддається — денний знімок гірший за скелетон', () => {
    vi.useFakeTimers()
    vi.setSystemTime(new Date('2026-08-01T10:00:00Z'))
    writeSnapshot('dbs', A, ['стале'])

    vi.setSystemTime(new Date('2026-08-02T09:59:00Z')) // 23 год 59 хв
    expect(readSnapshot('dbs', A), 'у межах TTL — ще валідне').toEqual(['стале'])

    vi.setSystemTime(new Date('2026-08-02T10:00:01Z')) // доба + 1 с
    expect(readSnapshot('dbs', A)).toBeNull()
  })

  it('пошкоджений JSON не валить екран', () => {
    localStorage.setItem('snap_v1:user-a:dbs', '{зламано')
    expect(readSnapshot('dbs', A)).toBeNull()
  })

  it('запис без мітки часу трактується як невалідний', () => {
    localStorage.setItem('snap_v1:user-a:dbs', JSON.stringify({ data: ['без t'] }))
    expect(readSnapshot('dbs', A)).toBeNull()
  })

  it('перезапис оновлює і дані, і мітку часу', () => {
    vi.useFakeTimers()
    vi.setSystemTime(new Date('2026-08-01T10:00:00Z'))
    writeSnapshot('dbs', A, ['старе'])

    vi.setSystemTime(new Date('2026-08-02T09:00:00Z'))
    writeSnapshot('dbs', A, ['нове'])

    // Ще доба від ДРУГОГО запису — значення живе.
    vi.setSystemTime(new Date('2026-08-03T08:59:00Z'))
    expect(readSnapshot('dbs', A)).toEqual(['нове'])
  })

  it('заблокований localStorage (private mode) не кидає', () => {
    const spy = vi.spyOn(Storage.prototype, 'setItem').mockImplementation(() => {
      throw new Error('QuotaExceededError')
    })
    expect(() => writeSnapshot('dbs', A, ['x'])).not.toThrow()
    spy.mockRestore()
  })
})

import { describe, it, expect } from 'vitest'
import { fetchAllRows, PAGE_SIZE } from '@/lib/fetchAll'

// Модель сервера: `max_rows` обрізає КОЖНУ відповідь мовчки, а `count`
// (як `Content-Range` при `count: 'exact'`) віддає повну кількість.
function server(total: number, opts: { maxRows?: number; withCount?: boolean } = {}) {
  const rows = Array.from({ length: total }, (_, i) => i)
  const calls: [number, number][] = []
  const page = async (from: number, to: number, first: boolean) => {
    calls.push([from, to])
    const cap = Math.min(to - from + 1, opts.maxRows ?? Infinity)
    return {
      data: rows.slice(from, from + cap),
      error: null,
      count: opts.withCount !== false && first ? total : null,
    }
  }
  return { page, calls }
}

describe('fetchAllRows', () => {
  it('дочитує все понад серверну межу', async () => {
    const s = server(1200)
    const got = await fetchAllRows(s.page)
    expect(got).toHaveLength(1200)
    expect(new Set(got).size).toBe(1200)
  })

  it('межа сервера МЕНША за сторінку — короткі сторінки не означають кінця', async () => {
    const s = server(1200, { maxRows: 500 })
    expect(await fetchAllRows(s.page)).toHaveLength(1200)
  })

  it('усе влізло — рівно ОДИН запит', async () => {
    const s = server(37)
    expect(await fetchAllRows(s.page)).toHaveLength(37)
    expect(s.calls).toHaveLength(1)
  })

  it('без лічильника — повні сторінки ведуть далі, коротка завершує', async () => {
    const s = server(PAGE_SIZE + 5, { withCount: false })
    expect(await fetchAllRows(s.page)).toHaveLength(PAGE_SIZE + 5)
  })

  it('лічильник більший за дані (рядки зникли між запитами) — без вічного циклу', async () => {
    const page = async (from: number, to: number, first: boolean) => ({
      data: from === 0 ? [1, 2, 3] : [], error: null, count: first ? 10 : null,
    })
    expect(await fetchAllRows(page)).toEqual([1, 2, 3])
  })

  it('помилка будь-якої сторінки — виняток, а не неповна сума', async () => {
    let n = 0
    const page = async () => (++n === 1
      ? { data: Array(PAGE_SIZE).fill(0), error: null, count: 2000 }
      : { data: null, error: new Error('boom') })
    await expect(fetchAllRows(page)).rejects.toThrow('boom')
  })
})

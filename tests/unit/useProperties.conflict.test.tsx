import { describe, it, expect, beforeEach, vi } from 'vitest'
import { renderHook, act } from '@testing-library/react'

/**
 * ОПТИМІСТИЧНА КОНКУРЕНТНІСТЬ ФОРМИ РЕДАГУВАННЯ.
 *
 * Форма шле в PATCH усі ~25 полів зі стану, знятого при відкритті. Два актори
 * на одному обʼєкті — і пізніше збереження МОВЧКИ повертає чужі зміни у
 * полях, яких не торкалось (редактор здав обʼєкт, власник правив лише опис —
 * оренда зникає, а тригер 067 закриває її в архіві).
 *
 * Тому запис іде лише якщо `updated_at` рядка збігається з тим, що форма
 * прочитала. 0 рядків від PostgREST — це ДВІ різні речі, і на дроті вони
 * нерозрізненні: рядок змінили (конфлікт) або запис заблокувала RLS. Розрізняє
 * тільки наступне читання: бачимо рядок з ІНШОЮ міткою — конфлікт; не бачимо
 * або мітка та сама — відмова, а не конфлікт.
 */

const h = vi.hoisted(() => ({
  /** Що віддає PATCH: рядок або «0 рядків» (PGRST116). */
  patch: { ok: true } as { ok: boolean },
  /** Що віддає наступне читання `updated_at` (null — RLS не пустила). */
  current: null as { updated_at: string } | null,
  /** Усі фільтри `.eq()` останнього PATCH: колонка → значення. */
  eqs: [] as [string, string][],
  reads: 0,
}))

vi.mock('@/lib/supabase', () => {
  const noRows = { data: null, error: { code: 'PGRST116', message: 'The result contains 0 rows' } }
  return {
    PROPERTY_COLUMNS: 'id',
    PROPERTY_WITH_PHOTOS: 'id',
    supabase: {
      from: () => ({
        update: () => {
          const chain = {
            eq: (c: string, v: string) => { h.eqs.push([c, v]); return chain },
            select: () => chain,
            single: async () => (h.patch.ok
              ? { data: { id: 'p1', name: 'Новий', updated_at: 'T-NEW', photos: [] }, error: null }
              : noRows),
          }
          return chain
        },
        select: () => ({
          eq: () => ({
            maybeSingle: async () => { h.reads++; return { data: h.current, error: null } },
          }),
        }),
      }),
    },
  }
})

vi.mock('@/lib/snapshot', () => ({ readSnapshot: () => null, writeSnapshot: () => {} }))

import { useProperties } from '@/hooks/useProperties'
import { useAppStore } from '@/store/appStore'

const SINCE = '2026-11-19T10:00:00.123456+00:00'

describe('useProperties.updateProperty: перевірка за updated_at', () => {
  beforeEach(() => {
    h.patch = { ok: true }
    h.current = null
    h.eqs = []
    h.reads = 0
    useAppStore.setState({ toast: null })
  })

  it('PATCH несе передумову updated_at РЯДКОМ, як його віддав сервер', async () => {
    const { result } = renderHook(() => useProperties('db1'))
    let ok = false
    await act(async () => {
      ok = await result.current.updateProperty('p1', { name: 'Новий' }, { ifUnchangedSince: SINCE })
    })
    expect(ok).toBe(true)
    // Мікросекунди мусять дожити: розбір у Date обрізав би їх до мілісекунд, і
    // рівність на сервері не зійшлась би НІКОЛИ.
    expect(h.eqs).toContainEqual(['updated_at', SINCE])
    expect(h.eqs).toContainEqual(['id', 'p1'])
  })

  it('без опції запис іде як раніше — інші екрани (оренда, звільнення) не зачеплені', async () => {
    const { result } = renderHook(() => useProperties('db1'))
    await act(async () => { await result.current.updateProperty('p1', { name: 'Новий' }) })
    expect(h.eqs.map(([c]) => c)).toEqual(['id'])
  })

  it('рядок змінили: конфлікт віддається викликачу з НОВОЮ міткою, без тоста помилки', async () => {
    h.patch = { ok: false }
    h.current = { updated_at: 'T-OTHER' }
    const onConflict = vi.fn()
    const { result } = renderHook(() => useProperties('db1'))
    let ok = true
    await act(async () => {
      ok = await result.current.updateProperty('p1', { name: 'Новий' }, { ifUnchangedSince: SINCE, onConflict })
    })
    expect(ok).toBe(false)
    expect(onConflict).toHaveBeenCalledWith('T-OTHER')
    // Тост конфлікту — справа викликача (йому потрібна дія «Перезаписати»);
    // загальна «Помилка» тут була б хибною: збою немає, є чужа правка.
    expect(useAppStore.getState().toast).toBeNull()
  })

  it('0 рядків, а мітка та сама — це ВІДМОВА (RLS), а не конфлікт', async () => {
    // Антивакуум до попереднього тесту: без цієї гілки будь-яка відмова
    // читалась би як «обʼєкт змінили», і користувач перезаписував би там, де
    // запису взагалі не дозволено.
    h.patch = { ok: false }
    h.current = { updated_at: SINCE }
    const onConflict = vi.fn()
    const { result } = renderHook(() => useProperties('db1'))
    let ok = true
    await act(async () => {
      ok = await result.current.updateProperty('p1', { name: 'Новий' }, { ifUnchangedSince: SINCE, onConflict })
    })
    expect(ok).toBe(false)
    expect(onConflict).not.toHaveBeenCalled()
    expect(useAppStore.getState().toast?.type).toBe('error')
  })

  it('рядка не видно взагалі (видалили чи забрали доступ) — теж не конфлікт', async () => {
    h.patch = { ok: false }
    h.current = null
    const onConflict = vi.fn()
    const { result } = renderHook(() => useProperties('db1'))
    await act(async () => {
      await result.current.updateProperty('p1', { name: 'Новий' }, { ifUnchangedSince: SINCE, onConflict })
    })
    expect(h.reads).toBe(1)
    expect(onConflict).not.toHaveBeenCalled()
    expect(useAppStore.getState().toast?.type).toBe('error')
  })
})

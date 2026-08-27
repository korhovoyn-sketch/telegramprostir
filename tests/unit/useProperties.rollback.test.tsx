import { describe, it, expect, beforeEach, vi } from 'vitest'
import { renderHook, act, waitFor } from '@testing-library/react'

/**
 * ВІДКАТ ЧІПАЄ ЛИШЕ СВІЙ РЯДОК, а не знімок усього списку.
 *
 * Було: `const prevList = propertiesRef.current` перед оптимістичною правкою і
 * `setProperties(prevList)` у catch. Два мутейти в польоті — і невдача одного
 * повертає список у стан ДО другого, включно зі змінами, які на сервері вже
 * ЗАКОМІЧЕНІ: користувач бачить відкат того, що збереглося.
 *
 * **Досяжність через сьогоднішній UI СПРОСТОВАНО, і це тут головне.** Обидва
 * оптимістичні виклики живуть на `PropertyDetailScreen`, а той тримає РІВНО
 * один обʼєкт (`loadSingleProperty` робить `setProperties([mapped])`), тож
 * «увесь список» і «мій рядок» там збігаються. Отже це гард на КОНТРАКТ хука,
 * а не звіт про живий баг: список із двох рядків зʼявиться тієї миті, коли
 * оптимістичний перемикач статусу поставлять на екран СПИСКУ — найприродніше
 * наступне розширення.
 */

const h = vi.hoisted(() => ({
  /** id → як має завершитись PATCH цього рядка. */
  outcome: new Map<string, { ok: boolean; delayMs: number }>(),
}))

vi.mock('@/lib/supabase', () => {
  // Список сідаємо СПРАВЖНІМ завантаженням — хук не віддає setProperties, і
  // це правильно: тест не має права ставити стан, недосяжний через його API.
  const listChain = {
    select: () => listChain,
    eq: () => listChain,
    order: () => listChain,
    then: (res: (v: unknown) => void) =>
      res({ data: [{ id: 'a', db_id: 'db1', owner_id: 'u1', name: 'a', status: 'free', photos: [] },
                   { id: 'b', db_id: 'db1', owner_id: 'u1', name: 'b', status: 'free', photos: [] }],
            error: null }),
  }
  return {
    PROPERTY_COLUMNS: 'id',
    PROPERTY_WITH_PHOTOS: 'id',
    supabase: {
      from: () => ({
        select: listChain.select,
        update: () => ({
          eq: (_c: string, id: string) => ({
            select: () => ({
              single: async () => {
                const o = h.outcome.get(id) ?? { ok: true, delayMs: 0 }
                await new Promise((r) => setTimeout(r, o.delayMs))
                return o.ok
                  ? { data: { id, status: 'occupied', photos: [] }, error: null }
                  : { data: null, error: { message: 'RLS' } }
              },
            }),
          }),
        }),
      }),
    },
  }
})

vi.mock('@/lib/snapshot', () => ({ readSnapshot: () => null, writeSnapshot: () => {} }))

import { useProperties } from '@/hooks/useProperties'
import { useAppStore } from '@/store/appStore'

describe('useProperties: оптимістичний відкат', () => {
  beforeEach(() => {
    h.outcome.clear()
    useAppStore.setState({ toast: null })
  })

  it('невдача одного рядка НЕ скасовує успішну зміну сусіднього', async () => {
    const { result } = renderHook(() => useProperties('db1'))
    // Список із ДВОХ рядків — саме те, чого не буває на екрані деталі.
    await act(async () => { await result.current.loadProperties('db1') })
    await waitFor(() => expect(result.current.properties).toHaveLength(2))

    h.outcome.set('a', { ok: false, delayMs: 40 })  // повільний і ПАДАЄ
    h.outcome.set('b', { ok: true, delayMs: 0 })    // швидкий і успішний

    await act(async () => {
      const pa = result.current.updateProperty('a', { status: 'occupied' }, { optimistic: true, silent: true })
      const pb = result.current.updateProperty('b', { status: 'occupied' }, { optimistic: true, silent: true })
      await Promise.all([pa, pb])
    })

    const byId = Object.fromEntries(result.current.properties.map((p) => [p.id, p.status]))
    expect(byId.a, 'рядок, чий запис ВПАВ, мусить відкотитись').toBe('free')
    expect(byId.b, 'рядок, чий запис УСПІШНИЙ, відкочувати не можна').toBe('occupied')
  })
})

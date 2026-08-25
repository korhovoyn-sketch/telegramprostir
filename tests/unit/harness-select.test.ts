import { describe, it, expect } from 'vitest'



/**
 * ПРОЄКЦІЯ `select=` У ХАРНЕСІ — САМА ПОТРЕБУЄ ГАРДА.
 *
 * Вона тепер стоїть між кожною фікстурою і кожним екраном у 300+ тестах. Якщо
 * її парсер помиляється, наслідок гірший за відсутність: тести почнуть падати
 * на неіснуючих дефектах або, навпаки, тихо пропускати реальні. Тому логіка
 * перевіряється прямо тут, на тих формах `select`, які застосунок справді шле.
 */

import { parseSelect, project } from '../e2e/helpers/selectProjection'

const run = (row: unknown, sel: string) => project(row, parseSelect(sel))

describe('проєкція select= у харнесі', () => {
  const ROW = {
    id: '1', name: 'Офіс', parking_type: 'underground', ev_charger: true,
    share_token: 'secret', photos: [{ id: 'p1', storage_path: 'a.jpg', sort_order: 0 }],
  }

  it('лишає лише запитані скалярні колонки', () => {
    expect(run(ROW, 'id,name')).toEqual({ id: '1', name: 'Офіс' })
  })

  it('ПРИБИРАЄ колонку, якої немає в select — це і є сенс усієї проєкції', () => {
    const out = run(ROW, 'id,name') as Record<string, unknown>
    expect(out.parking_type, 'непрошена колонка просочилась — гард сліпий').toBeUndefined()
    expect(out.share_token, 'токен просочився без запиту').toBeUndefined()
  })

  it('вбудоване відношення з аліасом проєктується вглиб', () => {
    const out = run(ROW, 'id,photos:property_photos(id,storage_path)') as Record<string, unknown>
    expect(out.photos).toEqual([{ id: 'p1', storage_path: 'a.jpg' }])
  })

  it('кома всередині дужок не розриває відношення', () => {
    const out = run(ROW, 'photos:property_photos(id,storage_path,sort_order),name') as Record<string, unknown>
    expect(Object.keys(out).sort()).toEqual(['name', 'photos'])
    expect((out.photos as Record<string, unknown>[])[0]).toHaveProperty('sort_order')
  })

  it('масив рядків проєктується поелементно', () => {
    expect(run([ROW, ROW], 'id')).toEqual([{ id: '1' }, { id: '1' }])
  })

  it('агрегат (count) лишається як є', () => {
    const row = { id: '1', collection_properties: [{ count: 3 }] }
    expect(run(row, 'id,collection_properties(count)')).toEqual(row)
  })

  it('`*` разом із вбудованим: скаляри всі, відношення лише запитані', () => {
    const out = run(ROW, '*,photos:property_photos(id)') as Record<string, unknown>
    expect(out.parking_type).toBe('underground')
    expect(out.photos).toEqual([{ id: 'p1' }])
  })

  it('відсутнє в рядку поле не вигадується', () => {
    expect(run({ id: '1' }, 'id,nope')).toEqual({ id: '1' })
  })
})

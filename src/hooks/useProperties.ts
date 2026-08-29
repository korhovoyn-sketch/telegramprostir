'use client'

import { useState, useCallback, useEffect, useRef } from 'react'
import { supabase } from '@/lib/supabase'
import { humanizeDbError, objectsWord, withSortedPhotos } from '@/lib/utils'
import { assertAffected } from '@/lib/dbWrite'
import { readSnapshot, writeSnapshot } from '@/lib/snapshot'
import { useAppStore } from '@/store/appStore'
import type { Property, PropertyStatus } from '@/types'

// Scalar column list + the photos relation, shared across every select so the
// four query sites can't drift apart (and none falls back to select('*')).
//
// КОЛОНКА, ЯКОЇ ТУТ НЕМА, — ЦЕ КОЛОНКА, ЯКУ РЕДАГУВАННЯ СТИРАЄ. `parking_type`
// і `ev_charger` бракувало: форма префілиться з рядка ЦЬОГО select-а, тож вони
// приходили `undefined` → поля скидались у порожнє → PATCH писав `null`, і
// тост казав «Збережено». Створення при цьому працювало, тобто дефект бив саме
// по редагуванню вже заповненого паркінга.
const PROPERTY_COLUMNS = `
  id, db_id, owner_id, name, floor, status,
  area_useful, area_total, area_basis, folder_id, rent_type, rent_rate, utilities_rate,
  has_parking, parking_spaces, parking_type, ev_charger, description,
  address, utilities,
  sale_price, tenant_name, landlord_name, lease_start_date, lease_end_date,
  sort_order, created_at, updated_at
`
/**
 * Наступний `sort_order` — від МАКСИМУМУ наявних, а не від їхньої кількості.
 *
 * Третє входження цього рецепта (форма обʼєкта, перенос у базу, імпорт), тож
 * він тут, а не скопійований учетверте. Довжина списку годиться лише поки
 * порядок ніхто не міняв: після ручного «Змінити порядок» значення стають
 * 100, 500, 9000 — і нові рядки, пораховані від `length`, ВКЛИНЮЮТЬСЯ в
 * середину, а то й колідують із наявними.
 */
export const nextSortBase = (properties: { sort_order?: number | null }[]): number =>
  Math.max(0, ...properties.map((p) => p.sort_order ?? 0))

export const PROPERTY_WITH_PHOTOS = `${PROPERTY_COLUMNS}, photos:property_photos(id, storage_path, sort_order)`

// loadProperties/loadSingleProperty additionally pull the view relation so the
// card can show a view count; create/update don't need it (a fresh row has none).
const PROPERTY_SELECT = `${PROPERTY_WITH_PHOTOS}, views:property_views(id)`

// Deploy-order safety: колонки, яких може ще не бути в базі, бо їхня міграція
// не накочена. PostgREST на невідому колонку віддає 400 на ВЕСЬ запит, тож без
// ретраю список обʼєктів просто не завантажився б.
//
// СПИСОК, а не пара констант на кожну колонку: `folder_id` (043) отримав свою
// пару, і повторювати той самий рецепт для `landlord_name` (064) означало б
// завести четверту й пʼяту константу, а далі шосту. Ретрай усе одно один —
// він знімає ВСІ необовʼязкові колонки одразу, бо розрізняти, якої саме
// бракує, ні до чого: обидві опційні й обидві зайві на старому бекенді.
const OPTIONAL_COLUMNS = ['folder_id', 'landlord_name'] as const
const stripOptional = (sel: string) =>
  OPTIONAL_COLUMNS.reduce((acc, c) => acc.replace(`${c}, `, ''), sel)
const PROPERTY_SELECT_PRE043 = stripOptional(PROPERTY_SELECT)
const PROPERTY_WITH_PHOTOS_PRE043 = stripOptional(PROPERTY_WITH_PHOTOS)
// `.select().single()` мусить повернути обʼєкт, але проксі/мок може віддати
// масив. Без розгортання рядок у списку став би масивом — і екран падав із
// «Cannot read properties of undefined» замість того, щоб просто оновитись.
function one<T>(data: unknown): T {
  return (Array.isArray(data) ? data[0] : data) as T
}

const isMissingFolderColumn = (e: unknown): boolean => {
  const err = e as { code?: string; message?: string } | null
  return err?.code === '42703'
    || OPTIONAL_COLUMNS.some((c) => new RegExp(c, 'i').test(err?.message ?? ''))
}

export function useProperties(dbId?: string) {
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [properties, setProperties] = useState<Property[]>([])
  const { user, showToast, navigate, backThenReplace } = useAppStore()

  // Mirror of `properties` for reading inside stable callbacks — screens
  // re-run their load effect off the callback identity, so loadProperties
  // must not depend on the list itself.
  const propertiesRef = useRef(properties)
  useEffect(() => { propertiesRef.current = properties }, [properties])

  // db_id, для якого `properties` — ПОВНИЙ список (а не один рядок із
  // loadSingleProperty). Тільки такий стан можна писати в SWR-кеш.
  const fullListDbIdRef = useRef<string | null>(null)

  // Кеш мусить переживати мутації, а не лише завантаження. Доки цього не було,
  // після збереження в кеші лишалося СТАРЕ значення: наступний екран малював
  // його першим, а форма редагування з нього ж робила префіл — користувач бачив
  // «зміни не зберігаються». Ефект тримає кеш синхронним з будь-якою мутацією,
  // тож новий мутатор не може про це забути.
  useEffect(() => {
    if (!user || properties.some((p) => p._stale)) return
    const full = fullListDbIdRef.current
    if (full) { writeSnapshot(`props:${full}`, user.id, properties); return }
    // Екран деталей тримає ОДИН рядок (loadSingleProperty), але теж його мутує
    // (здати/звільнити, ставки). Вливаємо рядок у кеш списку його бази, щоб
    // список не намалював стару картку.
    for (const p of properties) {
      if (!p.db_id) continue
      const key = `props:${p.db_id}`
      const cached = readSnapshot<Property[]>(key, user.id)
      const i = cached?.findIndex((c) => c.id === p.id) ?? -1
      if (!cached || i === -1) continue
      const next = [...cached]
      next[i] = { ...cached[i], ...p }
      writeSnapshot(key, user.id, next)
    }
  }, [properties, user])

  const loadProperties = useCallback(async (id?: string) => {
    const targetDbId = id || dbId
    if (!targetDbId) return

    // Stale-while-revalidate: screens remount on every navigation, so without
    // this every visit opens on a skeleton. Paint the last known list
    // instantly and refresh silently in the background.
    let painted = propertiesRef.current.length > 0
    if (!painted && user) {
      const cached = readSnapshot<Property[]>(`props:${targetDbId}`, user.id)
      if (cached?.length) {
        fullListDbIdRef.current = targetDbId
        setProperties(cached.map((p) => ({ ...p, _stale: true })))
        painted = true
      }
    }
    if (!painted) setLoading(true)
    setError(null)
    try {
      const primary = await supabase
        .from('properties')
        .select(PROPERTY_SELECT)
        .eq('db_id', targetDbId)
        .order('sort_order', { ascending: true })
        .order('created_at', { ascending: true })

      let rows = primary.data as unknown as Record<string, unknown>[] | null
      let err = primary.error
      if (err && isMissingFolderColumn(err)) {
        const fb = await supabase
          .from('properties')
          .select(PROPERTY_SELECT_PRE043)
          .eq('db_id', targetDbId)
          .order('sort_order', { ascending: true })
          .order('created_at', { ascending: true })
        rows = fb.data as unknown as Record<string, unknown>[] | null
        err = fb.error
      }
      if (err) throw err
      const mapped = (rows ?? []).map((p) => {
        const { views, ...rest } = p as Record<string, unknown>
        return withSortedPhotos({ ...rest, _view_count: (views as unknown[])?.length ?? 0 } as { photos?: { sort_order?: number | null }[] | null })
      })
      fullListDbIdRef.current = targetDbId
      setProperties(mapped as unknown as Property[])
    } catch (e) {
      const msg = humanizeDbError(e)
      setError(msg)
      showToast({ type: 'error', title: 'Помилка завантаження', subtitle: msg })
    } finally {
      setLoading(false)
    }
  }, [dbId, user, showToast])

  const loadSingleProperty = useCallback(async (propertyId: string) => {
    setLoading(true)
    setError(null)
    try {
      const primary = await supabase
        .from('properties')
        .select(PROPERTY_SELECT)
        .eq('id', propertyId)
        .single()

      let row = primary.data as unknown as Record<string, unknown> | null
      let err = primary.error
      if (err && isMissingFolderColumn(err)) {
        const fb = await supabase
          .from('properties')
          .select(PROPERTY_SELECT_PRE043)
          .eq('id', propertyId)
          .single()
        row = fb.data as unknown as Record<string, unknown> | null
        err = fb.error
      }
      if (err) throw err
      const { views, ...rest } = row as Record<string, unknown>
      const mapped = withSortedPhotos({ ...rest, _view_count: (views as unknown[])?.length ?? 0 } as unknown as Property)
      // Один рядок — не повний список бази: кеш списку з нього писати НЕ можна.
      fullListDbIdRef.current = null
      setProperties([mapped])
    } catch (e) {
      const msg = humanizeDbError(e)
      setError(msg)
      showToast({ type: 'error', title: 'Помилка завантаження', subtitle: msg })
    } finally {
      setLoading(false)
    }
  }, [showToast])

  const createProperty = useCallback(async (
    payload: Omit<Property, 'id' | 'owner_id' | 'created_at' | 'updated_at' | 'photos'>
  ) => {
    if (!user) return
    setLoading(true)
    try {
      // Дані належать власнику БАЗИ: коли створює член команди, owner_id має
      // бути власників, інакше RLS-власницькі перевірки далі по системі
      // почнуть «губити» обʼєкт (і WITH CHECK редакторської політики це
      // однаково вимагає).
      const dbOwner = useAppStore.getState().databases.find(d => d.id === payload.db_id)?.owner_id
      const row = { ...payload, owner_id: dbOwner ?? user.id }
      const primary = await supabase
        .from('properties')
        .insert(row)
        .select(PROPERTY_WITH_PHOTOS)
        .single()

      let created = primary.data as unknown as Property | null
      let err = primary.error
      if (err && isMissingFolderColumn(err)) {
        const pre043 = { ...row }
        // Знімаємо ВСІ необовʼязкові колонки, а не лише ту, на яку впав запит:
        // на бекенді без 043 і без 064 бракує обох, і зняття однієї дало б
        // другий 400 — цього разу вже без ретраю.
        delete pre043.folder_id
        delete pre043.landlord_name
        const fb = await supabase
          .from('properties')
          .insert(pre043)
          .select(PROPERTY_WITH_PHOTOS_PRE043)
          .single()
        created = fb.data as unknown as Property | null
        err = fb.error
      }
      if (err) throw err
      setProperties((prev) => [created as Property, ...prev])
      showToast({ type: 'success', title: 'Обʼєкт додано' })
      backThenReplace('db-objects', { dbId: payload.db_id })
      return true
    } catch (e) {
      showToast({ type: 'error', title: 'Помилка', subtitle: humanizeDbError(e) })
      return false
    } finally {
      setLoading(false)
    }
  }, [user, showToast, backThenReplace])

  // Bulk create — one INSERT for the whole batch (e.g. 10 parking spots at
  // once), so it's a single round-trip and either all rows land or none.
  const createProperties = useCallback(async (
    payloads: Omit<Property, 'id' | 'owner_id' | 'created_at' | 'updated_at' | 'photos'>[]
  ): Promise<boolean> => {
    if (!user || payloads.length === 0) return false
    setLoading(true)
    try {
      const dbOwner = useAppStore.getState().databases.find(d => d.id === payloads[0].db_id)?.owner_id
      const rows = payloads.map(p => ({ ...p, owner_id: dbOwner ?? user.id }))
      const primary = await supabase
        .from('properties')
        .insert(rows)
        .select(PROPERTY_WITH_PHOTOS)

      let created = primary.data as unknown as Property[] | null
      let err = primary.error
      if (err && isMissingFolderColumn(err)) {
        const pre043 = rows.map((r) => { const c = { ...r }; delete c.folder_id; return c })
        const fb = await supabase
          .from('properties')
          .insert(pre043)
          .select(PROPERTY_WITH_PHOTOS_PRE043)
        created = fb.data as unknown as Property[] | null
        err = fb.error
      }
      if (err) throw err
      setProperties((prev) => [...((created ?? []) as Property[]), ...prev])
      showToast({ type: 'success', title: `Додано ${payloads.length} ${objectsWord(payloads.length)}` })
      backThenReplace('db-objects', { dbId: payloads[0].db_id })
      return true
    } catch (e) {
      showToast({ type: 'error', title: 'Помилка', subtitle: humanizeDbError(e) })
      return false
    } finally {
      setLoading(false)
    }
  }, [user, showToast, backThenReplace])

  const updateProperty = useCallback(async (
    id: string,
    payload: Partial<Property>,
    opts?: { optimistic?: boolean; silent?: boolean },
  ): Promise<boolean> => {
    // Optimistic path: apply locally right away, sync in the background,
    // roll back on failure. Used for one-tap status changes (free/rent) so
    // the UI never blocks on the network.
    if (opts?.optimistic) {
      // Відкат ЛИШЕ свого рядка, а не знімок УСЬОГО списку. Зі знімком два
      // паралельні мутейти затирали одне одного: B стартує вже після
      // оптимістичної правки A, тож `prevList` у B її містить — і невдача A
      // повертала список у стан, де змін B немає, включно з тими, що вже
      // ЗАКОМІЧЕНІ на сервері. На LTE це досяжно двома тапами поспіль.
      const prevItem = propertiesRef.current.find((p) => p.id === id)
      setProperties((prev) => prev.map((p) => (p.id === id ? ({ ...p, ...payload } as Property) : p)))
      try {
        const { data, error } = await supabase
          .from('properties')
          .update({ ...payload, updated_at: new Date().toISOString() })
          .eq('id', id)
          .select(PROPERTY_WITH_PHOTOS)
          .single()
        if (error) throw error
        // Сортування ОБОВʼЯЗКОВЕ і тут: цей — оптимістичний — шлях досягається
        // зі «Здати в оренду», «Звільнити обʼєкт» і undo, тобто зі звичайного
        // перемикання статусу. Без нього несортований масив їде прямо в стор і
        // у SWR-снапшот, а `photos[0]` на героєві обʼєкта — це обкладинка:
        // перемикання статусу мовчки міняло б її. Сусідній рядок нижче фікс
        // отримав, цей — ні; клас закриває гард `photo-order.test.ts`.
        const updated = withSortedPhotos(one<Property>(data))
        setProperties((prev) => prev.map((p) => (
          p.id === id ? ({ ...updated, _view_count: (p as Property & { _view_count?: number })._view_count } as Property) : p
        )))
        if (!opts.silent) showToast({ type: 'success', title: 'Збережено' })
        return true
      } catch (e) {
        if (prevItem) setProperties((prev) => prev.map((p) => (p.id === id ? prevItem : p)))
        showToast({ type: 'error', title: 'Не збереглося — повернуто як було', subtitle: humanizeDbError(e) })
        return false
      }
    }

    setLoading(true)
    try {
      const { data, error } = await supabase
        .from('properties')
        .update({ ...payload, updated_at: new Date().toISOString() })
        .eq('id', id)
        .select(PROPERTY_WITH_PHOTOS)
        .single()

      if (error) throw error
      const updated = withSortedPhotos(one<Property>(data))
      setProperties((prev) => prev.map((p) => (p.id === id ? updated : p)))
      if (!opts?.silent) showToast({ type: 'success', title: 'Збережено' })
      return true
    } catch (e) {
      showToast({ type: 'error', title: 'Помилка', subtitle: humanizeDbError(e) })
      return false
    } finally {
      setLoading(false)
    }
  }, [showToast])

  const deleteProperty = useCallback(async (id: string, dbId: string) => {
    setLoading(true)
    try {
      // Спершу ЧИТАЄМО шляхи (після каскаду їх не дістати), потім видаляємо
      // рядок і доводимо це, і лише тоді чистимо storage — див. lib/dbWrite.ts.
      const [{ data: photos }, { data: docs }] = await Promise.all([
        supabase.from('property_photos').select('storage_path').eq('property_id', id),
        supabase.from('property_files').select('storage_path').eq('property_id', id),
      ])

      const { data: deleted, error } = await supabase
        .from('properties')
        .delete()
        .eq('id', id)
        .select('id')
      if (error) throw error
      assertAffected(deleted, 1, 'видалення обʼєкта')

      if (photos && photos.length > 0) {
        await supabase.storage.from('photos').remove(photos.map((p) => p.storage_path))
      }
      if (docs && docs.length > 0) {
        await supabase.storage.from('property-files').remove(docs.map((d) => d.storage_path))
      }

      setProperties((prev) => prev.filter((p) => p.id !== id))
      showToast({ type: 'success', title: 'Обʼєкт видалено' })
      // backThenReplace, не navigate: видалення відкривається ЛИШЕ з форми
      // редагування, куди заходять з property-detail того ж обʼєкта — просте
      // navigate лишило б і деталі, і форму цього вже неіснуючого обʼєкта в
      // history, і Back після видалення повертав би на мертвий екран.
      backThenReplace('db-objects', { dbId })
    } catch (e) {
      showToast({ type: 'error', title: 'Помилка', subtitle: humanizeDbError(e) })
    } finally {
      setLoading(false)
    }
  }, [showToast, backThenReplace])

  const batchDeleteProperties = useCallback(async (ids: string[]) => {
    if (ids.length === 0) return
    setLoading(true)
    try {
      // Читаємо шляхи → видаляємо рядки й доводимо це → лише тоді чистимо
      // storage. Зворотний порядок знищував фото навіть тоді, коли RLS не дав
      // видалити жодного рядка (див. lib/dbWrite.ts).
      const [{ data: photos }, { data: docs }] = await Promise.all([
        supabase.from('property_photos').select('storage_path').in('property_id', ids),
        supabase.from('property_files').select('storage_path').in('property_id', ids),
      ])

      const { data: deleted, error } = await supabase
        .from('properties')
        .delete()
        .in('id', ids)
        .select('id')
      if (error) throw error
      assertAffected(deleted, ids.length, 'видалення обʼєктів')

      if (photos && photos.length > 0) {
        await supabase.storage.from('photos').remove(photos.map(p => p.storage_path))
      }
      if (docs && docs.length > 0) {
        await supabase.storage.from('property-files').remove(docs.map(d => d.storage_path))
      }
      setProperties(prev => prev.filter(p => !ids.includes(p.id)))
      showToast({ type: 'success', title: `Видалено ${ids.length} ${objectsWord(ids.length)}` })
    } catch (e) {
      showToast({ type: 'error', title: 'Помилка видалення', subtitle: humanizeDbError(e) })
    } finally {
      setLoading(false)
    }
  }, [showToast])

  const batchUpdateStatus = useCallback(async (ids: string[], status: PropertyStatus) => {
    if (ids.length === 0) return
    try {
      // «Вільно» мусить прибрати й ОРЕНДАРЯ з датами — рівно як одиночний шлях
      // (`handleFreeProperty`). Інакше обʼєкт лишався «вільним» із живим
      // орендарем і договором, і ця суміш їхала в експорт та в публічну /v.
      const cleared = status === 'free'
        ? { tenant_name: null, lease_start_date: null, lease_end_date: null }
        : {}
      const { data: updated, error } = await supabase
        .from('properties')
        .update({ status, ...cleared, updated_at: new Date().toISOString() })
        .in('id', ids)
        .select('id')
      if (error) throw error
      assertAffected(updated, ids.length, 'зміну статусу')
      setProperties(prev => prev.map(p => ids.includes(p.id) ? { ...p, status, ...cleared } : p))
      const label: Record<PropertyStatus, string> = { free: 'Вільно', occupied: 'Зайнято', for_sale: 'Продаж' }
      showToast({ type: 'success', title: `${ids.length} ${objectsWord(ids.length)} — ${label[status]}` })
    } catch (e) {
      showToast({ type: 'error', title: 'Помилка', subtitle: humanizeDbError(e) })
    }
  }, [showToast])

  // Move one or more objects into a folder (folderId = null → ungroup).
  const moveToFolder = useCallback(async (ids: string[], folderId: string | null) => {
    if (ids.length === 0) return
    // Той самий per-item відкат, що в `updateProperty`: повертаємо `folder_id`
    // лише зачепленим рядкам, не чіпаючи сусідні оптимістичні правки.
    const prevFolders = new Map(propertiesRef.current.map((p) => [p.id, p.folder_id]))
    setProperties(prev => prev.map(p => ids.includes(p.id) ? { ...p, folder_id: folderId } : p))
    try {
      const { data: moved, error } = await supabase
        .from('properties')
        .update({ folder_id: folderId, updated_at: new Date().toISOString() })
        .in('id', ids)
        .select('id')
      if (error) throw error
      assertAffected(moved, ids.length, 'переміщення в папку')
      showToast({
        type: 'success',
        title: folderId
          ? `${ids.length} ${objectsWord(ids.length)} переміщено`
          : `${ids.length} ${objectsWord(ids.length)} без папки`,
      })
    } catch (e) {
      setProperties(prev => prev.map(p => (
        ids.includes(p.id) ? { ...p, folder_id: prevFolders.get(p.id) ?? null } : p
      )))
      showToast({ type: 'error', title: 'Не вдалося перемістити', subtitle: humanizeDbError(e) })
    }
  }, [showToast])

  // Перенести обʼєкти в ІНШУ базу. Три речі, які мусять статися разом:
  //  • folder_id скидається — папка належить базі-джерелу, інакше обʼєкт у новій
  //    базі посилався б на чужу папку і зник би з її списку;
  //  • owner_id стає власником БАЗИ-приймача (той самий інваріант, що в create:
  //    RLS WITH CHECK редакторської політики це вимагає, і редактор не має
  //    привласнювати рядки собі);
  //  • sort_order дописується в кінець приймача, інакше перенесені вклинюються
  //    в середину за старими номерами.
  const moveToDatabase = useCallback(async (
    ids: string[],
    targetDbId: string,
    targetOwnerId: string,
    targetName: string,
  ): Promise<boolean> => {
    if (ids.length === 0) return false
    const prevList = propertiesRef.current
    setProperties((prev) => prev.filter((p) => !ids.includes(p.id)))
    try {
      const { data: moved, error } = await supabase
        .from('properties')
        .update({ db_id: targetDbId, owner_id: targetOwnerId, folder_id: null, updated_at: new Date().toISOString() })
        .in('id', ids)
        .select('id')
      if (error) throw error
      assertAffected(moved, ids.length, 'перенесення в іншу базу')

      // Порядок — окремим, НЕобовʼязковим кроком: сам перенос уже стався одним
      // запитом (усе або нічого), а невдале перенумерування зіпсує лише порядок.
      try {
        const { data: tail } = await supabase
          .from('properties')
          .select('sort_order')
          .eq('db_id', targetDbId)
          .order('sort_order', { ascending: false })
          .limit(1)
        const base = Math.max(0, (tail?.[0]?.sort_order as number | undefined) ?? 0)
        await Promise.all(ids.map((id, i) =>
          supabase.from('properties').update({ sort_order: base + (i + 1) * 100 }).eq('id', id)))
      } catch { /* порядок — не критично */ }

      showToast({
        type: 'success',
        title: `${ids.length} ${objectsWord(ids.length)} у базі «${targetName}»`,
        actionLabel: 'Відкрити',
        onAction: () => navigate('db-objects', { dbId: targetDbId }),
      })
      return true
    } catch (e) {
      setProperties(prevList)
      showToast({ type: 'error', title: 'Не вдалося перенести', subtitle: humanizeDbError(e) })
      return false
    }
  }, [showToast, navigate])

  const reorderProperty = useCallback(async (id: string, direction: 'up' | 'down') => {
    const idx = properties.findIndex(p => p.id === id)
    if (idx === -1) return
    const neighborIdx = direction === 'up' ? idx - 1 : idx + 1
    if (neighborIdx < 0 || neighborIdx >= properties.length) return

    try {
      // If any item lacks a real sort_order, initialise all before swapping
      let base = properties
      if (properties.some(p => !p.sort_order)) {
        base = properties.map((p, i) => ({ ...p, sort_order: (i + 1) * 100 }))
        await Promise.all(
          base.map(p => supabase.from('properties').update({ sort_order: p.sort_order }).eq('id', p.id))
        )
      }

      const a = base[idx]
      const b = base[neighborIdx]

      // Optimistic swap
      const next = base
        .map(p =>
          p.id === a.id ? { ...p, sort_order: b.sort_order } :
          p.id === b.id ? { ...p, sort_order: a.sort_order } : p
        )
        .sort((x, y) => (x.sort_order ?? 0) - (y.sort_order ?? 0) || x.created_at.localeCompare(y.created_at))
      setProperties(next)

      // `.select('id')` + assertAffected, як і в кожної сусідньої мутації цього
      // хука: під RLS заблокований UPDATE повертає порожній набір і NULL у
      // `error`, тобто «переставив» і «не мав права» на дроті нерозрізненні.
      // Без цього редактор, чий доступ відкликали посеред роботи, бачив би
      // переставлений список, який мовчки повертається на місце при наступному
      // завантаженні. Це була ЄДИНА мутація тут без такого доведення.
      const [swapA, swapB] = await Promise.all([
        supabase.from('properties').update({ sort_order: b.sort_order }).eq('id', a.id).select('id'),
        supabase.from('properties').update({ sort_order: a.sort_order }).eq('id', b.id).select('id'),
      ])
      if (swapA.error) throw swapA.error
      if (swapB.error) throw swapB.error
      assertAffected(swapA.data, 1, 'зміну порядку')
      assertAffected(swapB.data, 1, 'зміну порядку')
    } catch (e) {
      setProperties(properties) // rollback
      showToast({ type: 'error', title: 'Не вдалося зберегти порядок', subtitle: humanizeDbError(e) })
    }
  }, [properties, showToast])

  const deletePhoto = useCallback(async (photoId: string, storagePath: string) => {
    try {
      // Рядок ПЕРШИМ і з доказом, файл — після. Сусіди в цьому ж файлі
      // (`deleteProperty`, `batchDeleteProperties`) давно на цьому порядку;
      // `deletePhoto` лишалась єдиним винятком. Зворотний порядок знищував
      // знімок навіть тоді, коли політика не пускала видалити рядок, — і
      // власник діставав вічно биту картинку без жодної помилки.
      const { data, error } = await supabase
        .from('property_photos').delete().eq('id', photoId).select('id')
      if (error) throw error
      assertAffected(data, 1, 'видалення фото')
      // Стан оновлюємо ОДРАЗУ після доведеного видалення рядка: саме рядок є
      // джерелом правди для застосунку, і він уже знесений. Якщо кинути тут
      // виняток через storage, фото лишиться намальованим при мертвому рядку.
      setProperties((prev) => prev.map((p) => ({
        ...p,
        photos: p.photos?.filter((ph) => ph.id !== photoId),
      })))

      // Storage-аналог `assertAffected`, і саме ДОВЖИНА, а не `error`.
      // `storage.remove()` на схований політикою обʼєкт повертає ПОРОЖНІЙ
      // масив і `error: null` — тобто «стер» і «не мав права» тут так само
      // нерозрізненні, як у PostgREST під RLS (правило 8). Попередня редакція
      // перевіряла `error` і мала коментар, що ловить мовчазну відмову; не
      // ловила.
      //
      // Бакет `photos` ПУБЛІЧНИЙ, тож осиротілий файл лишається доступним за
      // своїм URL — тут це не «нешкідливий сміттєвий файл» (пор. правило 9,
      // писане про приватний бакет), а знімок, який власник вважає видаленим.
      // Тому кажемо прямо, замість мовчати.
      const { data: removed, error: rmErr } = await supabase.storage
        .from('photos').remove([storagePath])
      if (rmErr || (removed?.length ?? 0) !== 1) {
        showToast({
          type: 'error',
          title: 'Фото прибрано, але файл лишився',
          subtitle: 'Спробуйте ще раз пізніше — знімок може бути доступним за прямим посиланням',
        })
      }
    } catch (e) {
      showToast({ type: 'error', title: 'Помилка видалення фото', subtitle: humanizeDbError(e) })
      throw e
    }
  }, [showToast])

  return {
    loading,
    error,
    properties,
    loadProperties,
    loadSingleProperty,
    createProperty,
    createProperties,
    updateProperty,
    reorderProperty,
    batchDeleteProperties,
    batchUpdateStatus,
    moveToFolder,
    moveToDatabase,
    deleteProperty,
    deletePhoto,
  }
}

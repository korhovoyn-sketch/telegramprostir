'use client'

import { useState, useCallback } from 'react'
import { supabase } from '@/lib/supabase'
import { useAppStore } from '@/store/appStore'
import { monthlyRent, basisArea, humanizeDbError } from '@/lib/utils'
import { assertAffected } from '@/lib/dbWrite'
import { readSnapshot, writeSnapshot } from '@/lib/snapshot'
import type { Database } from '@/types'

// Single source of truth for the databases column list — keeps loadDatabases,
// createDatabase and updateDatabase from drifting apart.
const DB_COLUMNS = 'id,owner_id,name,address,type,color,share_token,share_expires_at,created_at,updated_at'
/**
 * Те саме БЕЗ токена шарингу — для баз, де користувач лише РЕДАКТОР.
 *
 * `share_token` — це публічний /v-лінк власника. Шаринг бази owner-only за
 * задумом (див. Team editors), тож редактор із цим токеном роздавав би доступ,
 * якого йому не давали, а відкликання membership цього не скасувало б:
 * ротації токенів при цьому ніхто не робить. Гірше — `writeSnapshot` кладе
 * рядок у localStorage редактора, де він переживає відкликання геть.
 */
const DB_COLUMNS_MEMBER = 'id,owner_id,name,address,type,color,created_at,updated_at'

export function useDatabases() {
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const { user, setDatabases, databases, showToast, backThenReplace } = useAppStore()
  const setMemberDbIds = useAppStore(st => st.setMemberDbIds)

  const loadDatabases = useCallback(async () => {
    if (!user) return

    // Stale-while-revalidate: on a cold start paint the last known list
    // immediately and refresh silently — the skeleton shows only when there
    // is truly nothing to draw. State is read via getState() so the callback
    // identity stays stable (screens re-run their effect off it).
    let painted = useAppStore.getState().databases.length > 0
    if (!painted) {
      const cached = readSnapshot<Database[]>('databases', user.id)
      if (cached?.length) {
        setDatabases(cached)
        painted = true
      }
    }
    if (!painted) setLoading(true)
    setError(null)
    try {
      // Власні бази + бази, де користувач — член команди (editor).
      // Двома запитами: PostgREST не вміє OR із підзапитом, а окремий запит
      // по membership-ах дає ще й ids для canEdit-шлюзів у сторі.
      const [{ data, error }, memberRes] = await Promise.all([
        supabase
          .from('databases')
          .select(`${DB_COLUMNS}, properties(status, rent_rate, area_useful, area_total, area_basis, rent_type)`)
          .eq('owner_id', user.id)
          .order('created_at', { ascending: false }),
        supabase
          .from('db_members')
          .select('db_id')
          .eq('user_id', user.id)
          .eq('status', 'active'),
      ])

      if (error) throw error

      // На бекенді без міграції 041 запит по db_members падає — команда тоді
      // просто вимкнена, власні бази працюють як раніше.
      const memberIds = (memberRes.error ? [] : (memberRes.data ?? []))
        .map((r: { db_id: string }) => r.db_id)
        .filter((id: string) => !(data ?? []).some((d) => (d as { id: string }).id === id))
      setMemberDbIds(memberIds)

      let memberRows: typeof data = []
      if (memberIds.length > 0) {
        const { data: mData, error: mErr } = await supabase
          .from('databases')
          .select(`${DB_COLUMNS_MEMBER}, properties(status, rent_rate, area_useful, area_total, area_basis, rent_type)`)
          .in('id', memberIds)
          .order('created_at', { ascending: false })
        // Тихо ковтати цю помилку не можна: членство Є, але самі рядки баз не
        // прийшли — користувач побачив би, що бази команди просто зникли, без
        // жодного пояснення. Власні бази при цьому валити не варто, тож
        // повідомляємо тостом і малюємо те, що вдалось дістати.
        if (mErr) {
          showToast({
            type: 'error',
            title: 'Бази команди не завантажились',
            subtitle: humanizeDbError(mErr),
          })
        }
        // Каст свідомий: у member-рядках НЕМА `share_token`/`share_expires_at`,
        // і саме цього ми й домагались. Далі `_member: true` гейтить шаринг у
        // UI, тож відсутні поля ніде не читаються.
        memberRows = (mData ?? []) as unknown as typeof memberRows
      }

      const dbs = [
        ...(data || []),
        ...(memberRows || []).map((d) => ({ ...(d as Record<string, unknown>), _member: true })),
      ].map((d) => {
        const row = d as Record<string, unknown>
        type PropRow = { status: string; rent_rate?: number; area_useful?: number; area_total?: number; area_basis?: string; rent_type?: string }
        const props = (row.properties as PropRow[]) ?? []
        const monthlyIncome = props
          .filter(p => p.status === 'occupied' && p.rent_rate)
          .reduce((sum, p) => {
            if (!p.rent_rate) return sum
            return sum + monthlyRent(basisArea(p.area_useful, p.area_total, p.area_basis), p.rent_rate, p.rent_type ?? 'per_m2')
          }, 0)
        return {
          ...row,
          properties: undefined,
          _property_count:  props.length,
          _free_count:      props.filter(p => p.status === 'free').length,
          _occupied_count:  props.filter(p => p.status === 'occupied').length,
          _monthly_income:  monthlyIncome,
        }
      })

      setDatabases(dbs as unknown as Database[])
      writeSnapshot('databases', user.id, dbs)
    } catch (e) {
      const msg = humanizeDbError(e)
      setError(msg)
      showToast({ type: 'error', title: 'Помилка завантаження', subtitle: msg })
    } finally {
      setLoading(false)
    }
  }, [user, setDatabases, setMemberDbIds, showToast])

  // `opts.navigate: false` — коли база створюється ЯК КРОК іншої дії (перенос
  // обраних обʼєктів у нову базу): тоді екран лишається на місці, а викликач
  // сам вирішує, куди вести після переносу.
  const createDatabase = useCallback(async (
    payload: Omit<Database, 'id' | 'owner_id' | 'share_token' | 'created_at' | 'updated_at'>,
    opts?: { navigate?: boolean },
  ): Promise<Database | null> => {
    if (!user) return null
    setLoading(true)
    try {
      const { data, error } = await supabase
        .from('databases')
        .insert({ ...payload, owner_id: user.id })
        .select(DB_COLUMNS)
        .single()

      if (error) throw error

      setDatabases([data as Database, ...databases])
      showToast({ type: 'success', title: 'Базу створено' })
      if (opts?.navigate !== false) backThenReplace('db-objects', { dbId: data.id })
      return data as Database
    } catch (e) {
      showToast({ type: 'error', title: 'Помилка', subtitle: humanizeDbError(e) })
      return null
    } finally {
      setLoading(false)
    }
  }, [user, databases, setDatabases, showToast, backThenReplace])

  const updateDatabase = useCallback(async (id: string, payload: Partial<Database>) => {
    setLoading(true)
    try {
      // `.single()` уже сам падає, коли рядків нуль (PGRST116), тож окремий
      // assertAffected тут зайвий — мовчазного провалу на цьому шляху немає.
      const { data, error } = await supabase
        .from('databases')
        .update({ ...payload, updated_at: new Date().toISOString() })
        .eq('id', id)
        .select(DB_COLUMNS)
        .single()

      if (error) throw error

      setDatabases(databases.map((d) => (d.id === id ? { ...d, ...data } : d)))
      showToast({ type: 'success', title: 'Базу оновлено' })
    } catch (e) {
      showToast({ type: 'error', title: 'Помилка', subtitle: humanizeDbError(e) })
    } finally {
      setLoading(false)
    }
  }, [databases, setDatabases, showToast])

  const deleteDatabase = useCallback(async (id: string) => {
    setLoading(true)
    try {
      // ПОРЯДОК ТУТ — ЧАСТИНА КОНТРАКТУ, не стильова дрібниця.
      //
      // Спершу лише ЧИТАЄМО шляхи файлів (рядки ще на місці — після каскаду їх
      // вже не дістати), потім видаляємо рядок бази і ДОВОДИМО, що він зник, і
      // лише тоді знищуємо файли.
      //
      // Раніше було навпаки, і це коштувало даних: заблокований RLS DELETE
      // повертає 0 рядків БЕЗ помилки, тож застосунок рапортував «Базу
      // видалено», база лишалась жива — а всі її фото були вже стерті.
      // Осиротілий файл при цьому не є витоком (політики читання привʼязані до
      // рядків, яких уже немає), тож новий порядок строго безпечніший.
      const { data: props } = await supabase
        .from('properties')
        .select('id')
        .eq('db_id', id)

      let paths: { photos: string[]; docs: string[] } = { photos: [], docs: [] }
      if (props && props.length > 0) {
        const propIds = props.map((p) => p.id)
        const [{ data: photos }, { data: docs }] = await Promise.all([
          supabase.from('property_photos').select('storage_path').in('property_id', propIds),
          supabase.from('property_files').select('storage_path').in('property_id', propIds),
        ])
        paths = {
          photos: (photos ?? []).map((p) => p.storage_path),
          docs: (docs ?? []).map((d) => d.storage_path),
        }
      }

      const { data: deleted, error } = await supabase
        .from('databases')
        .delete()
        .eq('id', id)
        .select('id')
      if (error) throw error
      assertAffected(deleted, 1, 'видалення бази')

      // Рядок доведено видалений — тепер прибирання файлів безпечне.
      if (paths.photos.length > 0) {
        await supabase.storage.from('photos').remove(paths.photos)
      }
      if (paths.docs.length > 0) {
        await supabase.storage.from('property-files').remove(paths.docs)
      }

      setDatabases(databases.filter((d) => d.id !== id))
      showToast({ type: 'success', title: 'Базу видалено' })
      // backThenReplace, не navigate: поточний екран (db-objects тієї ж бази)
      // інакше лишався б у history — Back після видалення повертав би на
      // спінер бази, якої вже нема (той самий клас, що і в deleteProperty).
      backThenReplace('db-list')
    } catch (e) {
      showToast({ type: 'error', title: 'Помилка', subtitle: humanizeDbError(e) })
    } finally {
      setLoading(false)
    }
  }, [databases, setDatabases, showToast, backThenReplace])

  return { loading, error, databases, loadDatabases, createDatabase, updateDatabase, deleteDatabase }
}

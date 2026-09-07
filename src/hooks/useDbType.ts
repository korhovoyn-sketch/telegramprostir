'use client'

import { useEffect, useState } from 'react'
import { useAppStore } from '@/store/appStore'
import { supabase } from '@/lib/supabase'

/**
 * ТИП БАЗИ — НАДІЙНО, а не «зі стору, якщо пощастило».
 *
 * `appStore.databases` наповнює ЛИШЕ `DatabaseListScreen`. На холодному вході
 * по deep-лінку (`prop_`, гість, редактор команди) стор порожній, тож
 * `databases.find(...)?.type === 'parking'` мовчки давав `false`.
 *
 * Доти це псувало самі лише ПІДПИСИ. Відколи від типу бази залежить ГЕЙТ
 * ЕКСПЛУАТАЦІЙНИХ (`utilities_rate` — колонка з ДВОМА одиницями: пласка сума
 * для паркінга, ставка $/м² для решти), той самий промах дає ХИБНУ ЦИФРУ:
 * паркомісце 15 м² з пласкими $30 показує $450.
 *
 * Рецепт написаний учетверте (деталь обʼєкта, форма, здача в оренду, імпорт) —
 * тому хук, а не пʼята копія. Читає один рядок за id: RLS сама вирішує
 * видимість для будь-якої ролі.
 *
 * `landlord_name` тягнеться тим же запитом, але ОПЦІЙНО: без міграції 064
 * PostgREST віддає 400 на ВЕСЬ запит, і разом із іменем орендодавця впав би
 * тип бази — тобто той самий грошовий гейт, який цей хук і рятує. Тому на
 * помилку йде ретрай уже без цієї колонки (той самий патерн, що
 * `OPTIONAL_COLUMNS` у `useProperties`).
 */
export function useDbType(dbId: string | null | undefined) {
  const { databases } = useAppStore()
  const storedRow = databases.find((d) => d.id === dbId)
  const storedType = storedRow?.type
  const [fetched, setFetched] = useState<{ type: string; landlord_name?: string | null } | null>(null)

  useEffect(() => {
    if (!dbId || storedType) return
    let stale = false
    const apply = (data: { type: string; landlord_name?: string | null } | null) => {
      if (!stale && data) setFetched(data)
    }
    supabase.from('databases').select('id,type,landlord_name').eq('id', dbId).maybeSingle()
      .then(async ({ data, error }) => {
        if (error) {
          const { data: pre } = await supabase.from('databases').select('id,type').eq('id', dbId).maybeSingle()
          apply(pre as { type: string } | null)
          return
        }
        apply(data as { type: string; landlord_name?: string | null } | null)
      })
    return () => { stale = true }
  }, [dbId, storedType])

  const dbType = storedType ?? fetched?.type
  const dbLandlord = storedType ? (storedRow?.landlord_name ?? null) : (fetched?.landlord_name ?? null)
  return { dbType, dbLandlord, isParking: dbType === 'parking' }
}

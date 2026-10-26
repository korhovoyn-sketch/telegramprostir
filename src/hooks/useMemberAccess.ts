'use client'

import { useEffect } from 'react'
import { supabase } from '@/lib/supabase'
import { useAppStore } from '@/store/appStore'

/**
 * Чи є поточний користувач редактором КОМАНДИ цієї бази — з будь-якого входу.
 *
 * `memberDbIds` у сторі наповнюють лише два домашні екрани (`useDatabases` на
 * «Моїх базах» і дашборд рієлтора). Тож редактор, що потрапив у базу ПОВЗ них,
 * отримував екран без прав: заміряно на deep link `team_` — тост «Ви в команді!
 * Редагування доступне», а на екрані ні «Додати обʼєкт», ні меню бази. Причина
 * в тому, що клейм кличе `navigateRoot('db-list')` і одразу `navigate`, тож
 * список баз не встигає змонтуватись, а гість-редактор його не має взагалі.
 *
 * Тому екран, що вміє бути точкою входу, питає про членство сам — тим самим
 * правилом, що й self-heal рядка бази: одиночний select, видимість вирішує RLS
 * (`members_self_select` віддає людині ЛИШЕ її власні рядки). Знайдене пишеться
 * в стор, тож наступні екрани не перепитують.
 *
 * `rowOwnerId` — власник рядка, який екран уже завантажив. Поки він невідомий,
 * не питаємо (права й так не показуються, доки рядка немає), а власник своєї
 * бази членом не буває — для нього запиту немає зовсім.
 *
 * Збій запиту НЕ показуємо: це додаткове джерело прав, а не дані екрана. Без
 * нього лишається рівно та поведінка, що була (права з домашнього екрана), а
 * запис і так гейтить RLS, тож мовчазна відмова не відкриває нічого зайвого.
 */
export function useMemberAccess(dbId: string | undefined, rowOwnerId: string | null | undefined): boolean {
  const userId = useAppStore((s) => s.user?.id)
  const known = useAppStore((s) => !!dbId && s.memberDbIds.includes(dbId))

  useEffect(() => {
    if (!dbId || !userId || known) return
    if (!rowOwnerId || rowOwnerId === userId) return
    let stale = false
    supabase
      .from('db_members')
      .select('db_id')
      .eq('db_id', dbId)
      .eq('user_id', userId)
      .eq('status', 'active')
      .eq('role', 'editor')
      .limit(1)
      .then(({ data, error }) => {
        if (stale || error || !data || data.length === 0) return
        const cur = useAppStore.getState().memberDbIds
        if (!cur.includes(dbId)) useAppStore.getState().setMemberDbIds([...cur, dbId])
      })
    return () => { stale = true }
  }, [dbId, userId, rowOwnerId, known])

  return known
}

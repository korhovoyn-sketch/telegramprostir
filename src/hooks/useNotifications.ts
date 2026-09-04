'use client'

import { useState, useCallback } from 'react'
import { supabase } from '@/lib/supabase'
import { humanizeDbError } from '@/lib/utils'
import { assertAffected } from '@/lib/dbWrite'
import { useAppStore } from '@/store/appStore'
import type { Notification } from '@/types'

/**
 * Квиток завантаження — МОДУЛЬНИЙ, і це принципово.
 *
 * `loadNotifications` викликають ДВОЄ: глобальний лічильник бейджа в
 * `page.tsx` (на `requestIdleCallback`, тобто в непередбачуваний момент) і сам
 * екран сповіщень. Обидва пишуть у стор увесь список, тож виграє той, хто
 * відповів ОСТАННІМ — а не той, чиї дані свіжіші. Живий наслідок: користувач
 * відкриває екран, той позначає все прочитаним, і через мить бейдж повертається,
 * бо доїхала відповідь на запит, ВИПУЩЕНИЙ РАНІШЕ, де `is_read` ще false.
 *
 * Всередині екрана цей клас уже лікували порядком `load().then(markAllAsRead)` —
 * але порядок захищає лише від власного запиту, не від чужого. Тому квиток
 * живе на рівні модуля (переживає перемонтування) і його ЗБІЛЬШУЄ кожна
 * локальна мутація: запит, випущений до неї, права комітити вже не має.
 */
let loadTicket = 0

export function useNotifications() {
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const { user, setNotifications, notifications, markAllRead, showToast } = useAppStore()

  const loadNotifications = useCallback(async () => {
    if (!user) return
    const ticket = ++loadTicket
    setLoading(true)
    setError(null)
    try {
      const { data, error } = await supabase
        .from('notifications')
        .select('id,user_id,type,title,body,is_read,data,created_at')
        .eq('user_id', user.id)
        .order('created_at', { ascending: false })
        .limit(50)

      if (error) throw error
      // Застарілий у дорозі — мовчки викидаємо. Тост тут був би шкідливий: з
      // погляду користувача нічого не сталось.
      if (ticket !== loadTicket) return
      setNotifications((data || []) as Notification[])
    } catch (e) {
      // Тост живе кілька секунд, а порожній список лишається на екрані — і
      // читається як ВПЕВНЕНА відповідь «сповіщень немає». Тому збій мусить
      // мати СТАН, а не лише повідомлення: той самий клас уже виправляли для
      // списку доступів і аналітики шарингу.
      // БЕЗ тікет-гарда, і це свідомо: `loadTicket` модульний, тож глобальний
      // лічильник бейджа з page.tsx зсуває його між випуском запиту екрана і
      // його провалом — і помилка тихо не виставлялась. Застарілу помилку
      // виправляє наступний успіх: кожне завантаження стартує з setError(null).
      setError(humanizeDbError(e))
      showToast({ type: 'error', title: 'Помилка', subtitle: humanizeDbError(e) })
    } finally {
      setLoading(false)
    }
  }, [user, setNotifications, showToast])

  const markRead = useCallback(async (id: string) => {
    try {
      // rls-ok: сповіщення — похідні дані; наступний loadNotifications перечитає правду з сервера, а зайва секунда «прочитано» нікому не шкодить
      const { error } = await supabase.from('notifications').update({ is_read: true }).eq('id', id)
      if (error) throw error
      loadTicket++
      const fresh = useAppStore.getState().notifications
      setNotifications(fresh.map((n) => (n.id === id ? { ...n, is_read: true } : n)))
    } catch (e) {
      showToast({ type: 'error', title: 'Помилка', subtitle: humanizeDbError(e) })
    }
  }, [setNotifications, showToast])

  const markAllAsRead = useCallback(async () => {
    if (!user) return
    try {
      const { error } = await supabase
        // rls-ok: пакетне «прочитати все» — похідний стан; заблокована відмова
        // видно вже на наступному завантаженні, дані при цьому не втрачаються
        .from('notifications')
        .update({ is_read: true })
        .eq('user_id', user.id)
        .eq('is_read', false)
      if (error) throw error
      loadTicket++
      markAllRead()
    } catch (e) {
      showToast({ type: 'error', title: 'Помилка', subtitle: humanizeDbError(e) })
    }
  }, [user, markAllRead, showToast])

  const deleteNotification = useCallback(async (id: string) => {
    const snapshot = useAppStore.getState().notifications
    // Оптимістичне видалення теж анулює запити в дорозі — інакше відповідь,
    // випущена до тапу, поверне видалений рядок на екран.
    loadTicket++
    setNotifications(snapshot.filter((n) => n.id !== id))
    try {
      // ПОПЕРЕДНЯ причина тут була ХИБНА: писалось, що рядок «відновиться
      // наступним прогоном send-reminders». Не відновиться —
      // `get_due_reminders_today` має дедуп `NOT EXISTS … DATE_TRUNC('month')`,
      // тобто цього місяця його вже не створять. Наслідок від цього не
      // страшніший, але причина мусить описувати те, що справді стається.
      // rls-ok: похідні дані; мовчазна відмова лише поверне рядок при наступному завантаженні списку, джерело (розклад) недоторкане
      const { error } = await supabase.from('notifications').delete().eq('id', id)
      if (error) throw error
    } catch (e) {
      setNotifications(snapshot)
      showToast({ type: 'error', title: 'Помилка', subtitle: humanizeDbError(e) })
    }
  }, [setNotifications, showToast])

  /**
   * Прибрати ВСІ сповіщення.
   *
   * Раніше список чистився лише по одному хрестику, а `rent_reminder` і
   * `lease_reminder` капають щомісяця — через рік це сорок тапів.
   *
   * UNDO ТУТ НЕМОЖЛИВИЙ, і це не лінощі: міграція 035 дає клієнту SELECT,
   * UPDATE і DELETE, але INSERT-політики на `notifications` НЕМАЄ взагалі
   * (таблицю наповнює виключно `send-reminders` під service-role). Повернути
   * видалений рядок RLS просто не дасть, тож єдиний чесний захист — питати
   * ДО, а не пропонувати відкат ПІСЛЯ. Питає викликач через `confirmAction`.
   *
   * Видаляємо за СПИСКОМ ID, а не `.eq('user_id', …)`: інакше під ніж
   * потрапили б і рядки, що приїхали realtime-пушем уже після того, як
   * користувач подивився на список і вирішив його очистити.
   */
  const deleteAllNotifications = useCallback(async () => {
    const snapshot = useAppStore.getState().notifications
    if (snapshot.length === 0) return
    const ids = snapshot.map((n) => n.id)
    loadTicket++
    setNotifications([])
    try {
      const { data, error } = await supabase
        .from('notifications').delete().in('id', ids).select('id')
      if (error) throw error
      assertAffected(data, ids.length, 'очищення сповіщень')
      showToast({ type: 'success', title: 'Сповіщення очищено' })
    } catch (e) {
      setNotifications(snapshot)
      showToast({ type: 'error', title: 'Помилка', subtitle: humanizeDbError(e) })
    }
  }, [setNotifications, showToast])

  const subscribeToNotifications = useCallback(() => {
    if (!user) return () => {}
    const channel = supabase
      .channel('notifications_' + user.id)
      .on(
        'postgres_changes',
        {
          event: 'INSERT',
          schema: 'public',
          table: 'notifications',
          filter: `user_id=eq.${user.id}`,
        },
        (payload) => {
          const newNotif = payload.new as Notification
          const store = useAppStore.getState()
          const current = store.notifications
          // Дедуп за id: realtime-пуш може прийти, поки летить loadNotifications,
          // і тоді той самий рядок опинявся у списку двічі — React лаявся на
          // повторний key, а лічильник непрочитаних рахував його двічі.
          if (current.some((n) => n.id === newNotif.id)) return
          store.setNotifications([newNotif, ...current])
        }
      )
      .subscribe((status) => {
        // Без цього колбека `CHANNEL_ERROR`/`TIMED_OUT`/`CLOSED` глушились
        // повністю: сокет падав, сповіщення переставали приходити, і жодного
        // сліду про це не було. Webview Telegram постійно йде у фон, тож це не
        // рідкісний випадок, а звичайний.
        if (status === 'CHANNEL_ERROR' || status === 'TIMED_OUT') {
          console.warn('[notifications] realtime-канал відпав:', status)
          // Рефетч замість мовчазної втрати: рядки, вставлені поки сокет був
          // мертвий, realtime уже не догнати — їх дістане звичайний запит.
          //
          // РИЗИК, НАЗВАНИЙ І НЕ ЗАКРИТИЙ: supabase-js перепідключає канал сам
          // і без кінця, тож клієнт, у якого сокет не встає, може крутити
          // «падіння → запит → падіння». Обмежити це легко (рефетч лише після
          // втрати ЖИВОГО каналу + підлога по часу), але звідси цикл ПЕРЕВІРИТИ
          // НЕМОЖЛИВО: у харнесі вебсокета немає, і гілка не виконується
          // жодного разу. Спроба «полагодити наосліп» тут уже відкочена — ціна
          // в неї реальна (пропущені рядки у вікні підлоги), а доказ
          // відсутній. Рішення — за заміром на живому клієнті.
          void loadNotifications()
        }
      })

    return () => {
      supabase.removeChannel(channel)
    }
  }, [user, loadNotifications])

  return { loading, error, notifications, loadNotifications, markRead, markAllAsRead, deleteNotification, deleteAllNotifications, subscribeToNotifications }
}

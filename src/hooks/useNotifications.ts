'use client'

import { useState, useCallback } from 'react'
import { supabase } from '@/lib/supabase'
import { humanizeDbError } from '@/lib/utils'
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
  const { user, setNotifications, notifications, markAllRead, showToast } = useAppStore()

  const loadNotifications = useCallback(async () => {
    if (!user) return
    const ticket = ++loadTicket
    setLoading(true)
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
      showToast({ type: 'error', title: 'Помилка', subtitle: humanizeDbError(e) })
    } finally {
      setLoading(false)
    }
  }, [user, setNotifications, showToast])

  const markRead = useCallback(async (id: string) => {
    try {
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
      const { error } = await supabase.from('notifications').delete().eq('id', id)
      if (error) throw error
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
          void loadNotifications()
        }
      })

    return () => {
      supabase.removeChannel(channel)
    }
  }, [user, loadNotifications])

  return { loading, notifications, loadNotifications, markRead, markAllAsRead, deleteNotification, subscribeToNotifications }
}

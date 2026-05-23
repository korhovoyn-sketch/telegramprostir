'use client'

import { useState, useCallback } from 'react'
import { supabase } from '@/lib/supabase'
import { useAppStore } from '@/store/appStore'
import type { Notification } from '@/types'

export function useNotifications() {
  const [loading, setLoading] = useState(false)
  const { user, setNotifications, notifications, markAllRead, showToast } = useAppStore()

  const loadNotifications = useCallback(async () => {
    if (!user) return
    setLoading(true)
    try {
      const { data, error } = await supabase
        .from('notifications')
        .select('*')
        .eq('user_id', user.id)
        .order('created_at', { ascending: false })
        .limit(50)

      if (error) throw error
      setNotifications((data || []) as Notification[])
    } catch (e) {
      showToast({ type: 'error', title: 'Помилка', subtitle: (e as Error).message })
    } finally {
      setLoading(false)
    }
  }, [user, setNotifications, showToast])

  const markRead = useCallback(async (id: string) => {
    await supabase.from('notifications').update({ is_read: true }).eq('id', id)
    setNotifications(
      notifications.map((n) => (n.id === id ? { ...n, is_read: true } : n))
    )
  }, [notifications, setNotifications])

  const markAllAsRead = useCallback(async () => {
    if (!user) return
    await supabase
      .from('notifications')
      .update({ is_read: true })
      .eq('user_id', user.id)
      .eq('is_read', false)
    markAllRead()
  }, [user, markAllRead])

  const deleteNotification = useCallback(async (id: string) => {
    await supabase.from('notifications').delete().eq('id', id)
    setNotifications(notifications.filter((n) => n.id !== id))
  }, [notifications, setNotifications])

  return { loading, notifications, loadNotifications, markRead, markAllAsRead, deleteNotification }
}

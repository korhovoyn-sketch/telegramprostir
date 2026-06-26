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
        .select('id,user_id,type,title,body,is_read,data,created_at')
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
    try {
      const { error } = await supabase.from('notifications').update({ is_read: true }).eq('id', id)
      if (error) throw error
      const fresh = useAppStore.getState().notifications
      setNotifications(fresh.map((n) => (n.id === id ? { ...n, is_read: true } : n)))
    } catch (e) {
      showToast({ type: 'error', title: 'Помилка', subtitle: (e as Error).message })
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
      markAllRead()
    } catch (e) {
      showToast({ type: 'error', title: 'Помилка', subtitle: (e as Error).message })
    }
  }, [user, markAllRead, showToast])

  const deleteNotification = useCallback(async (id: string) => {
    try {
      const { error } = await supabase.from('notifications').delete().eq('id', id)
      if (error) throw error
      const fresh = useAppStore.getState().notifications
      setNotifications(fresh.filter((n) => n.id !== id))
    } catch (e) {
      showToast({ type: 'error', title: 'Помилка', subtitle: (e as Error).message })
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
          store.setNotifications([newNotif, ...current])
        }
      )
      .subscribe()

    return () => {
      supabase.removeChannel(channel)
    }
  }, [user])

  return { loading, notifications, loadNotifications, markRead, markAllAsRead, deleteNotification, subscribeToNotifications }
}

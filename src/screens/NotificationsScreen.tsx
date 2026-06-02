'use client'

import { useEffect, useState } from 'react'
import { useAppStore } from '@/store/appStore'
import { useNotifications } from '@/hooks/useNotifications'
import TabBar from '@/components/ui/TabBar'
import { formatDate } from '@/lib/utils'
import type { Notification } from '@/types'

type NotifTab = 'all' | 'views' | 'chats' | 'system'

export default function NotificationsScreen() {
  const unreadCount = useAppStore((s) => s.unreadCount)
  const { notifications, loading, loadNotifications, markRead, markAllAsRead, subscribeToNotifications } = useNotifications()
  const [tab, setTab] = useState<NotifTab>('all')

  useEffect(() => {
    loadNotifications()
    const cleanup = subscribeToNotifications()
    return cleanup
  }, [loadNotifications, subscribeToNotifications])

  const filtered = notifications.filter((n) => {
    if (tab === 'all') return true
    if (tab === 'views') return n.type === 'view'
    if (tab === 'chats') return n.type === 'chat'
    if (tab === 'system') return n.type === 'system'
    return true
  })

  const groupedByDate = filtered.reduce((acc, n) => {
    const d = Math.floor((Date.now() - new Date(n.created_at).getTime()) / 86400000)
    const key = d === 0 ? 'Сьогодні' : d === 1 ? 'Вчора' : d < 7 ? 'Цього тижня' : 'Раніше'
    if (!acc[key]) acc[key] = []
    acc[key].push(n)
    return acc
  }, {} as Record<string, Notification[]>)

  const NOTIF_ICON: Record<string, string> = {
    view: '👁️',
    chat: '💬',
    favorite: '❤️',
    system: '⚙️',
    export: '📄',
  }

  return (
    <div className="scr bg-teal">
      <div className="hdr">
        <div className="hdr-sp" />
        <div className="hdr-t">
          Сповіщення
          {unreadCount > 0 && (
            <div className="hdr-t-sub">{unreadCount} нових</div>
          )}
        </div>
        {unreadCount > 0 ? (
          <button
            className="hdr-a txt"
            onClick={markAllAsRead}
            style={{ background: 'none', border: 'var(--bd)' }}
          >
            Прочитано
          </button>
        ) : (
          <div className="hdr-sp" />
        )}
      </div>

      <div className="body">
        {/* Tabs */}
        <div className="notif-tabs">
          {([
            { id: 'all', label: `Всі${unreadCount > 0 ? ` (${unreadCount})` : ''}` },
            { id: 'views', label: 'Перегляди' },
            { id: 'chats', label: 'Повідомлення' },
            { id: 'system', label: 'Система' },
          ] as { id: NotifTab; label: string }[]).map((t) => (
            <div
              key={t.id}
              className={`notif-tab ${tab === t.id ? 'on' : ''}`}
              onClick={() => setTab(t.id)}
            >
              {t.label}
            </div>
          ))}
        </div>

        {loading ? (
          <div className="loader-wrap"><div className="loader" /></div>
        ) : filtered.length === 0 ? (
          <div className="empty-state" style={{ paddingTop: 32 }}>
            <div className="empty-ic">🔔</div>
            <div className="empty-h">Немає сповіщень</div>
            <div className="empty-s">Тут з&apos;являться сповіщення про перегляди та події</div>
          </div>
        ) : (
          Object.entries(groupedByDate).map(([group, items]) => (
            <div key={group}>
              <div className="notif-grp">{group}</div>
              <div className="notif-l glass-s" style={{ margin: '0 12px 12px' }}>
                {items.map((n) => (
                  <div
                    key={n.id}
                    className={`notif-i ${!n.is_read ? 'unread' : ''}`}
                    onClick={() => { if (!n.is_read) markRead(n.id) }}
                  >
                    <div className="notif-ic glass-s">
                      {NOTIF_ICON[n.type] ?? '🔔'}
                    </div>
                    <div className="notif-mn">
                      <div className="notif-n">{n.title}</div>
                      {n.body && <div className="notif-s">{n.body}</div>}
                    </div>
                    <span className="notif-t">{formatDate(n.created_at)}</span>
                  </div>
                ))}
              </div>
            </div>
          ))
        )}

        <div style={{ height: 80 }} />
      </div>

      <TabBar />
    </div>
  )
}

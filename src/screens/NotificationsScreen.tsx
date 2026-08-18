'use client'

import { useEffect, useState } from 'react'
import { useAppStore } from '@/store/appStore'
import { hapticSelection, hapticImpact, hapticNotify } from '@/lib/telegram'
import { useNotifications } from '@/hooks/useNotifications'
import { useLeaseAlerts, type LeaseAlert } from '@/hooks/useLeaseAlerts'
import { useUpcomingPayments, type PaymentAlert } from '@/hooks/useUpcomingPayments'
import TabBar from '@/components/ui/TabBar'
import { SkeletonList } from '@/components/ui/SkeletonLoader'
import { IconX } from '@/components/Icons'
import { formatDate, daysSince, pluralUk, formatLeaseDate, formatPrice } from '@/lib/utils'
import type { Notification } from '@/types'

// Вкладки описують ЛИШЕ те, що застосунок реально вміє створювати.
//
// Раніше тут були ще 'views' | 'chats' | 'system' — і жоден із цих типів не мав
// у проді виробника: рядки в `notifications` пише ВИКЛЮЧНО edge-функція
// `send-reminders`, і лише з `type='rent_reminder'` (тригерів у БД немає,
// клієнтський INSERT заборонений RLS після міграції 035). Тобто три вкладки
// були назавжди порожні, а e2e цього не бачив, бо мок-фікстури підсовували
// `type:'view'` вручну.
type NotifTab = 'all' | 'lease' | 'payments'

export default function NotificationsScreen() {
  const unreadCount = useAppStore((s) => s.unreadCount)
  const navigate = useAppStore((s) => s.navigate)
  const { notifications, loading, loadNotifications, markRead, markAllAsRead, deleteNotification, subscribeToNotifications } = useNotifications()
  const { alerts: leaseAlerts, loadLeaseAlerts } = useLeaseAlerts()
  const { alerts: payAlerts, loadUpcomingPayments } = useUpcomingPayments()
  const user = useAppStore((s) => s.user)
  const [tab, setTab] = useState<NotifTab>('all')

  useEffect(() => {
    // Порядок тут ОБОВʼЯЗКОВИЙ, і це не косметика. `markAllAsRead` ставить
    // прочитане локально одразу, а не-дочекана `loadNotifications` потім
    // перезаписувала весь список серверними рядками, де `is_read` ще false —
    // бейдж повертався, а рядки малювались непрочитаними, хоч у БД вони вже
    // прочитані. Класика «пізня відповідь перетирає новіший стан».
    void loadNotifications().then(markAllAsRead)
    const cleanup = subscribeToNotifications()
    return cleanup
  }, [loadNotifications, subscribeToNotifications, markAllAsRead])

  useEffect(() => { loadLeaseAlerts() }, [loadLeaseAlerts])
  useEffect(() => { loadUpcomingPayments() }, [loadUpcomingPayments])

  // Показуємо у «Всі» і в окремій вкладці «Договори».
  const showLease = tab === 'all' || tab === 'lease'
  // Те саме для платежів: найближчі — це СТАН розкладу, а не рядок у
  // `notifications`, тож блок закріплений, як і лізинговий.
  const showPay = tab === 'all' || tab === 'payments'

  function leaseText(a: LeaseAlert): string {
    if (a.days < 0) {
      const d = Math.abs(a.days)
      return `Договір закінчився ${d} ${pluralUk(d, 'день', 'дні', 'днів')} тому`
    }
    if (a.days === 0) return 'Договір закінчується сьогодні'
    return `Залишилось ${a.days} ${pluralUk(a.days, 'день', 'дні', 'днів')}`
  }

  function payText(a: PaymentAlert): string {
    if (a.days < 0) {
      const d = Math.abs(a.days)
      return `Прострочено на ${d} ${pluralUk(d, 'день', 'дні', 'днів')}`
    }
    if (a.days === 0) return 'Оплата сьогодні'
    return `Через ${a.days} ${pluralUk(a.days, 'день', 'дні', 'днів')}`
  }

  const filtered = notifications.filter((n) => {
    if (tab === 'all') return true
    // «Договори» — це САМЕ блок лізингових алертів (він малюється окремо через
    // `showLease`), а не рядки сповіщень. Раніше гілки для 'lease' не було
    // взагалі, тож фільтр падав у фінальний `return true` і вкладка показувала
    // ВСІ сповіщення поспіль — тобто не фільтрувала нічого.
    if (tab === 'lease') return false
    if (tab === 'payments') return n.type === 'rent_reminder'
    return true
  })

  const groupedByDate = filtered.reduce((acc, n) => {
    const d = daysSince(n.created_at)
    const key = d === 0 ? 'Сьогодні' : d === 1 ? 'Вчора' : d < 7 ? 'Цього тижня' : 'Раніше'
    if (!acc[key]) acc[key] = []
    acc[key].push(n)
    return acc
  }, {} as Record<string, Notification[]>)

  function handleNotifTap(n: Notification) {
    if (!n.is_read) markRead(n.id)
    const d = n.data as Record<string, string> | null
    const propertyId = d?.property_id
    if (n.type === 'rent_reminder' && propertyId) {
      hapticImpact('light')
      navigate('payment-calendar', { propertyId })
    } else if ((n.type === 'view' || n.type === 'favorite') && propertyId) {
      hapticImpact('light')
      navigate('sharing-analytics', { propertyId })
    }
  }

  // `rent_reminder` — єдиний тип, який реально створюється (send-reminders).
  // Решта лишається на випадок, якщо зʼявиться виробник: рядок із незнайомим
  // типом і далі малюється з дефолтним 🔔, а не ламає екран.
  const NOTIF_ICON: Record<string, string> = {
    rent_reminder: '💸',
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
            { id: 'lease', label: `Договори${leaseAlerts.length > 0 ? ` (${leaseAlerts.length})` : ''}` },
            { id: 'payments', label: `Платежі${payAlerts.length > 0 ? ` (${payAlerts.length})` : ''}` },
          ] as { id: NotifTab; label: string }[]).map((t) => (
            <div
              key={t.id}
              className={`notif-tab ${tab === t.id ? 'on' : ''}`}
              onClick={() => { hapticSelection(); setTab(t.id) }}
            >
              {t.label}
            </div>
          ))}
        </div>

        {/* НАЙБЛИЖЧІ ПЛАТЕЖІ. Такий самий закріплений блок, як лізинговий, і з
            тієї ж причини: це СТАН розкладу, а не подія. Рядок у `notifications`
            зʼявився б лише в день нагадування (і лише якщо відпрацював крон),
            тож вкладка «Платежі» була порожня решту місяця — саме на це
            скаржився власник. Перед договорами, бо гроші — первинна робота. */}
        {showPay && payAlerts.length > 0 && (
          <>
            <div className="over">Найближчі платежі</div>
            <div className="notif-l glass-s" style={{ margin: '0 12px 12px' }}>
              {payAlerts.map((a) => (
                <button
                  key={a.propertyId}
                  type="button"
                  className={`notif-i unread lvl-${a.level}`}
                  onClick={() => { hapticImpact('light'); navigate('payment-calendar', { propertyId: a.propertyId, dbId: a.dbId }) }}
                >
                  <div className="notif-ic glass-s">{a.level === 'overdue' ? '⛔' : a.level === 'critical' ? '⏰' : '💸'}</div>
                  <div className="notif-mn">
                    <div className="notif-n">{a.name}</div>
                    <div className="notif-s">
                      {a.tenantName ? `${a.tenantName} · ` : ''}{payText(a)}
                    </div>
                  </div>
                  {a.amount > 0 && (
                    <span className="notif-t">{formatPrice(a.amount, user?.currency)}</span>
                  )}
                </button>
              ))}
            </div>
          </>
        )}

        {/* Кінець договору — стан, а не подія, тож окремим закріпленим блоком
            НАД датованими групами, і без кнопки видалення: поки термін
            наближається, сповіщення мусить лишатись на екрані. */}
        {showLease && leaseAlerts.length > 0 && (
          <>
            <div className="over">Терміни договорів</div>
            <div className="notif-l glass-s" style={{ margin: '0 12px 12px' }}>
              {leaseAlerts.map((a) => (
                <button
                  key={a.propertyId}
                  type="button"
                  className={`notif-i unread lvl-${a.level}`}
                  onClick={() => { hapticImpact('light'); navigate('property-detail', { propertyId: a.propertyId, dbId: a.dbId }) }}
                >
                  <div className="notif-ic glass-s">{a.level === 'overdue' ? '⛔' : a.level === 'critical' ? '⏰' : '📅'}</div>
                  <div className="notif-mn">
                    <div className="notif-n">{a.name}</div>
                    <div className="notif-s">
                      {a.tenantName ? `${a.tenantName} · ` : ''}{leaseText(a)}
                    </div>
                  </div>
                  <span className="notif-t">{formatLeaseDate(a.leaseEnd)}</span>
                </button>
              ))}
            </div>
          </>
        )}

        {loading ? (
          <SkeletonList count={5} />
        ) : filtered.length === 0
            && !(showLease && leaseAlerts.length > 0)
            && !(showPay && payAlerts.length > 0) ? (
          <div className="empty-state" style={{ paddingTop: 32 }}>
            <div className="empty-ic">🔔</div>
            <div className="empty-h">Немає сповіщень</div>
            <div className="empty-s">Тут з&apos;являться перегляди, події та попередження про кінець договору</div>
          </div>
        ) : (
          Object.entries(groupedByDate).map(([group, items]) => (
            <div key={group}>
              <div className="over">{group}</div>
              <div className="notif-l glass-s" style={{ margin: '0 12px 12px' }}>
                {items.map((n) => (
                  <div
                    key={n.id}
                    className={`notif-i ${!n.is_read ? 'unread' : ''}`}
                    style={{ cursor: (n.type === 'rent_reminder' || n.type === 'view' || n.type === 'favorite') && (n.data as Record<string, string> | null)?.property_id ? 'pointer' : undefined }}
                    onClick={() => handleNotifTap(n)}
                  >
                    <div className="notif-ic glass-s">
                      {NOTIF_ICON[n.type] ?? '🔔'}
                    </div>
                    <div className="notif-mn">
                      <div className="notif-n">{n.title}</div>
                      {n.body && <div className="notif-s">{n.body}</div>}
                    </div>
                    <span className="notif-t">{formatDate(n.created_at)}</span>
                    <button
                      className="notif-del"
                      aria-label="Видалити сповіщення"
                      onClick={(e) => { e.stopPropagation(); hapticNotify('warning'); deleteNotification(n.id) }}
                    >
                      <IconX size={14} />
                    </button>
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

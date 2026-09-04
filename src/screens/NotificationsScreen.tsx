'use client'

import { useEffect, useState } from 'react'
import { useAppStore } from '@/store/appStore'
import { hapticSelection, hapticImpact, hapticNotify } from '@/lib/telegram'
import { useNotifications } from '@/hooks/useNotifications'
import { useLeaseAlerts, type LeaseAlert } from '@/hooks/useLeaseAlerts'
import { useUpcomingPayments, type PaymentAlert } from '@/hooks/useUpcomingPayments'
import { useViewerActivity } from '@/hooks/useViewerActivity'
import TabBar from '@/components/ui/TabBar'
import { SkeletonList } from '@/components/ui/SkeletonLoader'
import { IconX, IconTrash, IconBell, IconEye, IconMessage, IconHeartFilled, IconAdjustments, IconFile, IconCurrencyDollar, IconBan, IconClock, IconCalendar, IconKey } from '@/components/Icons'
import { confirmAction } from '@/lib/confirm'
import { offlineGuard } from '@/lib/offline'
import { formatDate, daysSince, pluralUk, objectsWord, formatLeaseDate, formatPrice } from '@/lib/utils'
import type { Notification } from '@/types'

// Вкладки описують ЛИШЕ те, що застосунок реально вміє створювати.
//
// Раніше тут були ще 'views' | 'chats' | 'system' — і жоден із цих типів не мав
// у проді виробника: рядки в `notifications` пише ВИКЛЮЧНО edge-функція
// `send-reminders` (тригерів у БД немає, клієнтський INSERT заборонений RLS
// після міграції 035). Тобто три вкладки були назавжди порожні, а e2e цього не
// бачив, бо мок-фікстури підсовували `type:'view'` вручну.
//
// Виробників тепер ДВА, обидва в тій самій функції: `rent_reminder` (розклад
// платежів) і `lease_reminder` (кінець договору, міграція 065).
type NotifTab = 'all' | 'lease' | 'payments'

export default function NotificationsScreen() {
  const unreadCount = useAppStore((s) => s.unreadCount)
  const navigate = useAppStore((s) => s.navigate)
  const { notifications, loading, loadNotifications, markRead, markAllAsRead, deleteNotification, deleteAllNotifications, subscribeToNotifications } = useNotifications()
  const { alerts: leaseAlerts, loadLeaseAlerts } = useLeaseAlerts()
  const { alerts: payAlerts, loadUpcomingPayments } = useUpcomingPayments()
  const { viewers, loadViewerActivity } = useViewerActivity()
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
  useEffect(() => { loadViewerActivity() }, [loadViewerActivity])
  useEffect(() => { loadUpcomingPayments() }, [loadUpcomingPayments])

  // Показуємо у «Всі» і в окремій вкладці «Договори».
  const showLease = tab === 'all' || tab === 'lease'
  // Те саме для платежів: найближчі — це СТАН розкладу, а не рядок у
  // `notifications`, тож блок закріплений, як і лізинговий.
  const showPay = tab === 'all' || tab === 'payments'
  // ВЛАСНОЇ ВКЛАДКИ В БЛОКА НЕМА, і це замір, а не смак: четверта вкладка при
  // 375px обрізала підпис «Перегляди» на 7px (спіймав `control-text-fit`).
  // Розтягнути смугу чи зменшити шрифт означало б відкотити вже ухвалене
  // рішення про таби — 44px і `flex:1` на всю ширину. Блок і так закріплений
  // НАД датованими групами, тож окрема вкладка додала б небагато.
  //
  // Прапорець профілю — єдиний вимикач. `!== false`, а не `=== true`: колонка
  // може прийти undefined на старому бекенді, і тоді розділ мусить бути
  // УВІМКНЕНИЙ, а не тихо зниклим.
  const showViews = user?.notification_views !== false && tab === 'all'

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
    // «Договори» має ДВА джерела, і вони про різне: похідний блок лізингових
    // алертів (СТАН — малюється окремо через `showLease`, зникає сам, щойно
    // договір продовжили) і рядки `lease_reminder` (ПОДІЯ — разове
    // повідомлення на кожному порозі, надіслане в Telegram, 065). До 065
    // рядків не існувало взагалі, і тут стояв голий `false`.
    if (tab === 'lease') return n.type === 'lease_reminder'
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
    } else if (n.type === 'lease_reminder' && propertyId) {
      // Нагадування про договір веде на сам обʼєкт: продовжити чи звільнити —
      // рішення там, а не в календарі платежів.
      hapticImpact('light')
      navigate('property-detail', { propertyId })
    } else if ((n.type === 'view' || n.type === 'favorite') && propertyId) {
      hapticImpact('light')
      navigate('sharing-analytics', { propertyId })
    }
  }

  // Реально створюються два типи — `rent_reminder` і `lease_reminder`, обидва
  // з `send-reminders`. Решта лишається на випадок, якщо зʼявиться виробник:
  // рядок із незнайомим типом і далі малюється з дефолтним 🔔, а не ламає екран.
  const NOTIF_ICON: Record<string, React.ReactNode> = {
    rent_reminder: <IconCurrencyDollar size={18} color="var(--ok-fg)" />,
    lease_reminder: <IconKey size={18} color="var(--violet)" />,
    view: <IconEye size={18} color="var(--info)" />,
    chat: <IconMessage size={18} color="var(--info)" />,
    favorite: <IconHeartFilled size={18} color="var(--pink)" />,
    system: <IconAdjustments size={18} color="var(--t3)" />,
    export: <IconFile size={18} color="var(--t3)" />,
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
                  <div className="notif-ic glass-s">{a.level === 'overdue'
                      ? <IconBan size={18} color="var(--err)" />
                      : a.level === 'critical'
                        ? <IconClock size={18} color="var(--warn)" />
                        : <IconCurrencyDollar size={18} color="var(--ok-fg)" />}</div>
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

        {/* Хто переглядав — теж СТАН періоду, а не подія, і теж похідний блок.
            Рядок НЕ клікабельний свідомо: глядач не є ціллю навігації (аналітика
            в застосунку — по базі/обʼєкту/підбірці, не по людині), а кнопка, що
            нікуди не веде, гірша за звичайний рядок. Тому `<div>`, а не
            `<button>`: правило про кнопки стосується КЛІКАБЕЛЬНИХ елементів. */}
        {showViews && viewers.length > 0 && (
          <>
            <div className="over">Хто переглядав</div>
            <div className="notif-l glass-s" style={{ margin: '0 12px 12px' }}>
              {viewers.map((v) => (
                <div key={v.viewerId} className="notif-i">
                  <div className="notif-ic glass-s"><IconEye size={18} color="var(--info-fg)" /></div>
                  <div className="notif-mn">
                    <div className="notif-n">{v.viewerName}</div>
                    <div className="notif-s">
                      {[
                        v.properties > 0 ? `${v.properties} ${objectsWord(v.properties)}` : null,
                        v.databases > 0
                          ? `${v.databases} ${pluralUk(v.databases, 'відкриття', 'відкриття', 'відкриттів')} бази`
                          : null,
                      ].filter(Boolean).join(' · ')}
                    </div>
                  </div>
                  <span className="notif-t">{formatDate(v.lastAt)}</span>
                </div>
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
                  <div className="notif-ic glass-s">{a.level === 'overdue'
                      ? <IconBan size={18} color="var(--err)" />
                      : a.level === 'critical'
                        ? <IconClock size={18} color="var(--warn)" />
                        : <IconCalendar size={18} color="var(--t3)" />}</div>
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
            && !(showPay && payAlerts.length > 0)
            && !(showViews && viewers.length > 0) ? (
          <div className="empty-state" style={{ paddingTop: 32 }}>
            <div className="empty-ic">🔔</div>
            <div className="empty-h">Немає сповіщень</div>
            <div className="empty-s">Тут зʼявляться перегляди, події та попередження про кінець договору</div>
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
                    style={{ cursor: (n.type === 'rent_reminder' || n.type === 'lease_reminder' || n.type === 'view' || n.type === 'favorite') && (n.data as Record<string, string> | null)?.property_id ? 'pointer' : undefined }}
                    onClick={() => handleNotifTap(n)}
                  >
                    <div className="notif-ic glass-s">
                      {NOTIF_ICON[n.type] ?? <IconBell size={18} color="var(--t3)" />}
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

        {/* ОЧИСТИТИ ВСІ. Раніше список чистився лише по одному хрестику, а
            `rent_reminder`/`lease_reminder` капають щомісяця — через рік це
            сорок тапів.

            Підтвердження обовʼязкове саме тут: undo неможливий у принципі —
            міграція 035 дає клієнту SELECT/UPDATE/DELETE, але INSERT-політики
            на `notifications` немає взагалі, тож повернути видалене RLS не
            дасть. Питаємо ДО, бо відкотити ПІСЛЯ нічим.

            Кнопка стоїть під списком, а не в хедері: там уже живе «Прочитано»,
            і дві дії поруч при 375px не вміщуються без обрізання. */}
        {notifications.length > 0 && (
          <div style={{ display: 'flex', justifyContent: 'center', padding: '4px 12px 8px' }}>
            <button
              className="acc-act revoke"
              onClick={async () => {
                const ok = await confirmAction({
                  title: 'Очистити сповіщення?',
                  message: `${notifications.length} ${pluralUk(notifications.length, 'сповіщення', 'сповіщення', 'сповіщень')} буде видалено назавжди — повернути їх неможливо.`,
                  confirmLabel: 'Очистити',
                  destructive: true,
                })
                if (!ok || offlineGuard()) return
                hapticNotify('warning')
                void deleteAllNotifications()
              }}
            >
              <IconTrash size={14} />Очистити всі
            </button>
          </div>
        )}

        <div style={{ height: 80 }} />
      </div>

      <TabBar />
    </div>
  )
}

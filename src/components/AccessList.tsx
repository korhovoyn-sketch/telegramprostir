'use client'

import { useEffect, useState } from 'react'
import { useAppStore } from '@/store/appStore'
import { offlineGuard } from '@/lib/offline'
import { confirmAction } from '@/lib/confirm'
import { supabase } from '@/lib/supabase'
import { assertAffected } from '@/lib/dbWrite'
import { humanizeDbError, pluralUk } from '@/lib/utils'
import Header from '@/components/ui/Header'
import { SkeletonList } from '@/components/ui/SkeletonLoader'
import RetryState from '@/components/ui/RetryState'
import { IconPlus, IconLink, IconBan, IconUser, IconUsers, IconCopy, IconChevronRight, IconTrash } from '@/components/Icons'
import { copyLink } from '@/lib/share'
import { buildDeepLink, openTelegramShare, hapticNotify } from '@/lib/telegram'

/**
 * СПІЛЬНИЙ СПИСОК ДОСТУПІВ — гості і команда.
 *
 * До цього `ManageGuestsScreen` і `TeamScreen` були дзеркальними копіями, і
 * саме тому КОЖЕН дефект аудиту доступів був подвійним: відкликання без доказу
 * запису, збій завантаження у вигляді порожнього списку, мертвий лінк, який
 * можна надіслати, зона дотику 26px. Це вже третій випадок класу — перший
 * породив `InviteSheet`, який дедуплікував лише шит створення.
 *
 * Обидва `ScreenName` лишаються (`manage-guests`, `team`) — екрани стали
 * тонкими обгортками, тож маршрути, ліниві чанки й тести не зачеплені.
 */

export type AccessKind = 'guest' | 'team'

/** Спільна форма рядка: обидві таблиці різні, читає їх екран однаково. */
interface AccessRow {
  id: string
  invite_token: string
  label: string | null
  /** Імʼя людини, що прийняла запрошення (`member_name` / `guest_name`). */
  person: string | null
  status: 'pending' | 'active' | 'revoked'
  claimed_at: string | null
  created_at: string
}

interface KindCopy {
  table: 'guest_links' | 'db_members'
  /** Колонка з іменем того, хто прийняв — може не існувати до міграції. */
  nameCol: 'guest_name' | 'member_name'
  columns: string
  tokenPrefix: 'guest_' | 'team_'
  bg: string
  title: (isProperty: boolean) => string
  addLabel: string
  emptyIcon: string
  emptyTitle: string
  emptyHint: string
  fallbackName: string
  shareText: (isProperty: boolean) => string
  revokeMessage: (name: string) => string
  statusLabel: Record<string, string>
  note?: string
  /** Чи можна ділитись лінком у цьому стані (в команді — лише поки очікує). */
  canShare: (status: AccessRow['status']) => boolean
}

const BASE_GUEST = 'id,owner_id,property_id,db_id,invite_token,label,guest_user_id,status,claimed_at,created_at'
const BASE_TEAM = 'id,db_id,user_id,role,invite_token,label,status,claimed_at,created_at'

const COPY: Record<AccessKind, KindCopy> = {
  guest: {
    table: 'guest_links', nameCol: 'guest_name', columns: BASE_GUEST,
    tokenPrefix: 'guest_', bg: 'bg-blue',
    title: (isProp) => (isProp ? 'Гості обʼєкта' : 'Гості бази'),
    addLabel: 'Запросити гостя',
    emptyIcon: '👤', emptyTitle: 'Немає запрошень',
    emptyHint: 'Натисніть + щоб запросити гостя',
    fallbackName: 'Гість',
    shareText: (isProp) => (isProp ? 'Запрошення до перегляду обʼєкта' : 'Запрошення до перегляду бази'),
    revokeMessage: (n) => `Гість «${n}» втратить доступ. Цю дію не можна скасувати.`,
    statusLabel: { pending: 'Очікує', active: 'Активний', revoked: 'Відкликано' },
    canShare: (s) => s !== 'revoked',
  },
  team: {
    table: 'db_members', nameCol: 'member_name', columns: BASE_TEAM,
    tokenPrefix: 'team_', bg: 'bg-teal',
    title: () => 'Команда бази',
    addLabel: 'Запросити в команду',
    emptyIcon: '👥', emptyTitle: 'Команди поки немає',
    emptyHint: 'Натисніть + щоб запросити помічника',
    fallbackName: 'Запрошення',
    shareText: () => 'Запрошення до команди бази нерухомості',
    revokeMessage: (n) => `«${n}» втратить право редагувати базу.`,
    statusLabel: { pending: 'Очікує', active: 'В команді', revoked: 'Відкликано' },
    note: 'Члени команди можуть створювати і редагувати обʼєкти, фото, файли та платежі цієї бази. Поділитися базою, керувати гостями і командою може лише власник. Власник бачить, які обʼєкти учасник відкривав — про це варто сказати людині, коли запрошуєте.',
    // Прийнятий інвайт ділити нема сенсу — токен уже спожитий.
    canShare: (s) => s === 'pending',
  },
}

const STATUS_COLOR: Record<string, string> = {
  pending: 'var(--warn)',
  active: 'var(--ok-light)',
  revoked: 'var(--t4)',
}

export default function AccessList({ kind }: { kind: AccessKind }) {
  const { screenParams, showToast, navigate } = useAppStore()
  const c = COPY[kind]

  const isProperty = kind === 'guest' && !!screenParams.propertyId
  const dbId = screenParams.dbId as string | undefined
  const propertyId = screenParams.propertyId as string | undefined
  const targetId = kind === 'guest' ? (propertyId ?? dbId) : dbId

  const [rows, setRows] = useState<AccessRow[]>([])
  const [loading, setLoading] = useState(true)
  const [revoking, setRevoking] = useState<string | null>(null)
  // Помилка завантаження МУСИТЬ мати власний стан. Без нього збій мережі малював
  // порожній стан — тобто ВПЕВНЕНУ відповідь «доступів немає» на питання «які
  // доступи я роздав». Тост зникає за секунди, порожній стан лишається.
  const [loadErr, setLoadErr] = useState<string | null>(null)
  // Відкликані згорнуті: вони накопичуються назавжди і виштовхували б живі
  // доступи за фолд рівно тоді, коли базою користуються найактивніше.
  const [showRevoked, setShowRevoked] = useState(false)

  async function load() {
    if (!targetId) return
    setLoading(true)
    const filterCol = kind === 'guest' ? (isProperty ? 'property_id' : 'db_id') : 'db_id'
    const run = (columns: string) => supabase
      .from(c.table)
      .select(columns)
      .eq(filterCol, targetId)
      .order('created_at', { ascending: false })

    try {
      // Спершу з колонкою імені, і ретрай без неї на 42703 — той самий патерн,
      // що `useProperties` тримає для `folder_id`: фронт деплоїться незалежно
      // від міграції, тож select невідомої колонки поклав би ВЕСЬ екран (400),
      // а не лише приховав імена.
      let res = await run(`${c.columns},${c.nameCol}`)
      if (res.error && (res.error as { code?: string }).code === '42703') {
        res = await run(c.columns)
      }
      if (res.error) throw res.error
      const raw = (res.data ?? []) as unknown as Record<string, unknown>[]
      setRows(raw.map((r) => ({
        id: String(r.id),
        invite_token: String(r.invite_token),
        label: (r.label as string | null) ?? null,
        person: (r[c.nameCol] as string | null) ?? null,
        status: r.status as AccessRow['status'],
        claimed_at: (r.claimed_at as string | null) ?? null,
        created_at: String(r.created_at),
      })))
      setLoadErr(null)
    } catch (e) {
      setLoadErr(humanizeDbError(e))
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    load()
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [targetId, kind])

  function nameOf(r: AccessRow) {
    return r.person || r.label || c.fallbackName
  }

  async function handleRevoke(r: AccessRow) {
    const ok = await confirmAction({
      title: 'Відкликати доступ?',
      message: c.revokeMessage(nameOf(r)),
      confirmLabel: 'Відкликати',
      destructive: true,
    })
    if (!ok || offlineGuard()) return
    setRevoking(r.id)
    try {
      // `.select('id')` + `assertAffected` — не формальність: під RLS
      // заблокований UPDATE повертає ПОРОЖНІЙ набір і NULL у `error`, тож без
      // доказу екран малював бейдж «Відкликано», а доступ лишався ЖИВИМ. Це
      // найгірший інстанс класу: мовчазна брехня про БЕЗПЕКУ.
      const { data, error } = await supabase
        .from(c.table)
        .update({ status: 'revoked' })
        .eq('id', r.id)
        .select('id')
      if (error) throw error
      assertAffected(data, 1, 'відкликання доступу')
      setRows(prev => prev.map(x => x.id === r.id ? { ...x, status: 'revoked' as const } : x))
      hapticNotify('success')
      // Тост обовʼязковий саме ТУТ: відкликаний рядок їде у згорнуту секцію,
      // тобто зникає з очей. Доти фідбеком був сам бейдж «Відкликано» на
      // місці — без нього дія завершувалась мовчазним зникненням рядка, що
      // читається як «щось пішло не так», а не як успіх.
      showToast({ type: 'success', title: 'Доступ відкликано', subtitle: nameOf(r) })
    } catch (e) {
      showToast({ type: 'error', title: 'Помилка', subtitle: humanizeDbError(e) })
    } finally {
      setRevoking(null)
    }
  }

  // Відкликані рядки накопичуються НАЗАВЖДИ: відкликання лише міняє статус, а
  // видалення доти не було взагалі. За рік активного користування база збирає
  // десятки мертвих доступів — згорнута секція ховає їх з очей, але не з
  // даних. Прибирати можна ЛИШЕ відкликані: живий доступ зникає через
  // `handleRevoke`, інакше кнопка «прибрати» тихо ставала б другим шляхом
  // позбавлення доступу — без підтвердження про наслідки.
  async function handleDelete(r: AccessRow) {
    const ok = await confirmAction({
      title: 'Прибрати запис?',
      message: `Запис про «${nameOf(r)}» зникне зі списку. Доступ уже відкликано, тож на права це не впливає.`,
      confirmLabel: 'Прибрати',
      destructive: true,
    })
    if (!ok || offlineGuard()) return
    setRevoking(r.id)
    try {
      // Той самий доказ, що й у відкликанні (правило 8): під RLS заблокований
      // DELETE віддає порожній набір і NULL у `error`, тобто «зробив» і «не мав
      // права» на дроті нерозрізненні.
      const { data, error } = await supabase
        .from(c.table)
        .delete()
        .eq('id', r.id)
        .select('id')
      if (error) throw error
      assertAffected(data, 1, 'видалення запису доступу')
      setRows(prev => prev.filter(x => x.id !== r.id))
      hapticNotify('success')
    } catch (e) {
      showToast({ type: 'error', title: 'Помилка', subtitle: humanizeDbError(e) })
    } finally {
      setRevoking(null)
    }
  }

  async function handleCopy(url: string) {
    const ok = await copyLink(url)
    showToast(ok
      ? { type: 'success', title: 'Посилання скопійовано' }
      : { type: 'error', title: 'Не вдалося скопіювати' })
  }

  const active = rows.filter(r => r.status !== 'revoked')
  const revoked = rows.filter(r => r.status === 'revoked')

  function renderRow(r: AccessRow) {
    const url = buildDeepLink(`${c.tokenPrefix}${r.invite_token}`)
    // Мертвий лінк («#» — коли не задано юзернейм бота) не можна ані копіювати,
    // ані надсилати: власник дізнався б про поломку від одержувача. Той самий
    // клас уже давав прод-інцидент із TELEGRAM_APP_NAME.
    const usable = /^https?:\/\//.test(url)
    const Ic = kind === 'guest' ? IconUser : IconUsers
    const dim = r.status === 'revoked'
    return (
      <div key={r.id} className="glass-s acc-card" style={{ opacity: dim ? .72 : 1 }}>
        <div style={{ display: 'flex', alignItems: 'flex-start', gap: 10 }}>
          <div className="acc-av" style={{ background: kind === 'guest' ? 'var(--info-bg)' : 'var(--ok-bg)' }}>
            <Ic size={16} color={kind === 'guest' ? 'var(--info)' : 'var(--ok)'} />
          </div>
          <div style={{ flex: 1, minWidth: 0 }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 3 }}>
              <span className="acc-name">{nameOf(r)}</span>
              <span className="acc-badge" style={{ background: `${STATUS_COLOR[r.status]}22`, color: STATUS_COLOR[r.status] }}>
                {c.statusLabel[r.status] ?? r.status}
              </span>
            </div>
            <div className="acc-meta">
              {/* Підпис власника лишається ПОРЯД з іменем, а не замість нього:
                  «Орендар, кв. 5» каже, за що доступ, а імʼя — кому. */}
              {r.person && r.label ? `${r.label} · ` : ''}
              {r.claimed_at
                ? `Прийнято ${new Date(r.claimed_at).toLocaleDateString('uk-UA')}`
                : `Створено ${new Date(r.created_at).toLocaleDateString('uk-UA')}`}
            </div>
            {r.status === 'revoked' && (
              <div style={{ display: 'flex', gap: 6, marginTop: 8 }}>
                <button className="acc-act revoke" disabled={revoking === r.id} onClick={() => handleDelete(r)}>
                  <IconTrash size={14} />Прибрати
                </button>
              </div>
            )}
            {r.status !== 'revoked' && (
              <div style={{ display: 'flex', gap: 6, marginTop: 8 }}>
                {/* Дії з лінком — ІКОНКОВІ, і це вимушено, а не стилістично:
                    три текстові підписи в рядку при 375px вилазять за свої
                    кнопки на 22–31px (заміряно `Range` по вмісту). Підпис
                    лишається в найважливішої дії — незворотного відкликання. */}
                {c.canShare(r.status) && (
                  <>
                    <button className="acc-act share icon" disabled={!usable}
                      aria-label="Скопіювати посилання" onClick={() => handleCopy(url)}>
                      <IconCopy size={16} />
                    </button>
                    <button className="acc-act share icon" disabled={!usable}
                      aria-label="Надіслати посилання"
                      onClick={() => openTelegramShare(url, c.shareText(isProperty))}>
                      <IconLink size={16} />
                    </button>
                  </>
                )}
                <button className="acc-act revoke" disabled={revoking === r.id} onClick={() => handleRevoke(r)}>
                  <IconBan size={14} />Відкликати
                </button>
              </div>
            )}
          </div>
        </div>
      </div>
    )
  }

  return (
    <div className={`scr ${c.bg}`}>
      <Header
        title={c.title(isProperty)}
        backLabel="Назад"
        right={
          <button
            className="hdr-a"
            aria-label={c.addLabel}
            onClick={() => navigate('create-invite', { kind, dbId, propertyId })}
            style={{ background: 'none', border: 'var(--bd)' }}
          >
            <IconPlus size={16} />
          </button>
        }
      />

      <div className="body" style={{ animation: 'cascadeIn .2s ease both' }}>
        {c.note && <div className="acc-note">{c.note}</div>}

        {loading ? (
          <SkeletonList count={3} />
        ) : loadErr ? (
          <RetryState onRetry={load} subtitle={loadErr} />
        ) : rows.length === 0 ? (
          <div className="empty-state" style={{ paddingTop: 48 }}>
            <div className="empty-ic">{c.emptyIcon}</div>
            <div className="empty-h">{c.emptyTitle}</div>
            <div className="empty-s">{c.emptyHint}</div>
          </div>
        ) : (
          <div style={{ paddingTop: 6 }}>
            {active.map(renderRow)}

            {/* Порожньо може бути і тут — коли ВСІ доступи відкликані. Без цього
                рядка екран виглядав би так, ніби список не завантажився. */}
            {active.length === 0 && (
              <div className="empty-state" style={{ paddingTop: 24, paddingBottom: 8 }}>
                <div className="empty-h">Активних доступів немає</div>
              </div>
            )}

            {revoked.length > 0 && (
              <>
                <button type="button" className="acc-toggle" onClick={() => setShowRevoked(v => !v)}
                  aria-expanded={showRevoked}>
                  <span>
                    {showRevoked ? 'Сховати відкликані' : 'Відкликані'} ({revoked.length}{' '}
                    {pluralUk(revoked.length, 'доступ', 'доступи', 'доступів')})
                  </span>
                  <IconChevronRight size={16} className="acc-chev" />
                </button>
                {showRevoked && revoked.map(renderRow)}
              </>
            )}
          </div>
        )}

        <div style={{ height: 24 }} />
      </div>
    </div>
  )
}

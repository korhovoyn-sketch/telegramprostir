'use client'

import { useEffect, useState } from 'react'
import { useAppStore } from '@/store/appStore'
import { offlineGuard } from '@/lib/offline'
import { confirmAction } from '@/lib/confirm'
import { supabase } from '@/lib/supabase'
import { assertAffected } from '@/lib/dbWrite'
import { humanizeDbError } from '@/lib/utils'
import Header from '@/components/ui/Header'
import { SkeletonList } from '@/components/ui/SkeletonLoader'
import RetryState from '@/components/ui/RetryState'
import { IconPlus, IconLink, IconBan, IconUsers, IconCopy } from '@/components/Icons'
import { buildDeepLink, openTelegramShare, hapticNotify } from '@/lib/telegram'
import { copyLink } from '@/lib/share'
import type { DbMember } from '@/types'

const STATUS_LABEL: Record<string, string> = {
  pending: 'Очікує',
  active: 'В команді',
  revoked: 'Відкликано',
}
const STATUS_COLOR: Record<string, string> = {
  pending: 'var(--warn)',
  active: 'var(--ok-light)',
  revoked: 'var(--t4)',
}

// Керування командою бази (owner-only — редактори цей екран не бачать).
// Дзеркалить ManageGuestsScreen: інвайт-рядок → deep link team_<token> →
// claim_team_invite (useDeepLink) → редактор з повним CRUD по об'єктах бази.
export default function TeamScreen() {
  const { screenParams, showToast, navigate } = useAppStore()
  const dbId = screenParams.dbId as string | undefined
  const [members, setMembers] = useState<DbMember[]>([])
  const [loading, setLoading] = useState(true)
  const [revoking, setRevoking] = useState<string | null>(null)
  // Помилка завантаження МУСИТЬ мати власний стан. Без нього збій мережі
  // малював «Немає запрошень» — тобто відповідь «доступів немає» на питання
  // «чи є доступи», і власник не мав жодного натяку, що список просто не
  // доїхав. Тост зникає за секунди, порожній стан лишається на екрані.
  const [loadErr, setLoadErr] = useState<string | null>(null)

  async function load() {
    if (!dbId) return
    setLoading(true)
    try {
      const { data, error } = await supabase
        .from('db_members')
        .select('id,db_id,user_id,role,invite_token,label,member_name,status,claimed_at,created_at')
        .eq('db_id', dbId)
        .order('created_at', { ascending: false })
      if (error) throw error
      setMembers((data ?? []) as DbMember[])
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
  }, [dbId])

  async function handleRevoke(member: DbMember) {
    const ok = await confirmAction({
      title: 'Відкликати доступ?',
      message: `«${member.member_name || member.label || 'Учасник'}» втратить право редагувати базу.`,
      confirmLabel: 'Відкликати',
      destructive: true,
    })
    if (!ok || offlineGuard()) return
    const id = member.id
    setRevoking(id)
    try {
      // `.select('id')` + `assertAffected` — не формальність: під RLS
      // заблокований UPDATE повертає ПОРОЖНІЙ набір і NULL у `error`, тож без
      // доказу екран малював бейдж «Відкликано», а доступ лишався ЖИВИМ.
      // Це найгірший можливий інстанс класу: мовчазна брехня про БЕЗПЕКУ.
      const { data, error } = await supabase
        .from('db_members')
        .update({ status: 'revoked' })
        .eq('id', id)
        .select('id')
      if (error) throw error
      assertAffected(data, 1, 'відкликання доступу')
      setMembers(prev => prev.map(m => m.id === id ? { ...m, status: 'revoked' as const } : m))
      hapticNotify('success')
    } catch (e) {
      showToast({ type: 'error', title: 'Помилка', subtitle: humanizeDbError(e) })
    } finally {
      setRevoking(null)
    }
  }

  async function handleCopy(link: string) {
    const ok = await copyLink(link)
    showToast(ok
      ? { type: 'success', title: 'Посилання скопійовано' }
      : { type: 'error', title: 'Не вдалося скопіювати' })
  }

  return (
    <div className="scr bg-teal">
      <Header
        title="Команда бази"
        backLabel="Назад"
        right={
          <button
            className="hdr-a"
            aria-label="Запросити в команду"
            onClick={() => navigate('create-invite', { kind: 'team', dbId })}
            style={{ background: 'none', border: 'var(--bd)' }}
          >
            <IconPlus size={16} />
          </button>
        }
      />

      <div className="body" style={{ animation: 'cascadeIn .2s ease both' }}>
        <div style={{ margin: '8px 12px 12px', padding: '10px 12px', borderRadius: 'var(--r-sm)', background: 'var(--glass-1)', fontSize: 'var(--fs-cap1)', color: 'var(--t3)', lineHeight: 1.5 }}>
          Члени команди можуть створювати і редагувати об&apos;єкти, фото, файли та
          платежі цієї бази. Поділитися базою, керувати гостями і командою може
          лише власник.
        </div>

        {loading ? (
          <SkeletonList count={3} />
        ) : loadErr ? (
          <RetryState onRetry={load} subtitle={loadErr} />
        ) : members.length === 0 ? (
          <div className="empty-state" style={{ paddingTop: 48 }}>
            <div className="empty-ic">👥</div>
            <div className="empty-h">Команди поки немає</div>
            <div className="empty-s">Натисніть + щоб запросити помічника</div>
          </div>
        ) : (
          <div style={{ paddingTop: 4 }}>
            {members.map((m) => (
              <div key={m.id} className="glass-s" style={{ margin: '0 12px 10px', borderRadius: 'var(--r-md)', padding: '12px 14px' }}>
                <div style={{ display: 'flex', alignItems: 'flex-start', gap: 10 }}>
                  <div style={{ width: 36, height: 36, borderRadius: '50%', background: 'var(--ok-bg)', display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0, marginTop: 2 }}>
                    <IconUsers size={16} color="var(--ok)" />
                  </div>
                  <div style={{ flex: 1, minWidth: 0 }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 3 }}>
                      <span style={{ fontSize: 'var(--fs-note)', fontWeight: 'var(--fw-semi)', color: 'var(--t1)', flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                        {m.member_name || m.label || 'Запрошення'}
                      </span>
                      <span style={{ fontSize: 'var(--fs-cap2)', fontWeight: 'var(--fw-semi)', padding: '2px 8px', borderRadius: 'var(--r-pill)', background: `${STATUS_COLOR[m.status]}22`, color: STATUS_COLOR[m.status], flexShrink: 0 }}>
                        {STATUS_LABEL[m.status] ?? m.status}
                      </span>
                    </div>
                    <div style={{ fontSize: 'var(--fs-cap2)', color: 'var(--t4)' }}>
                      {m.member_name && m.label ? `${m.label} · ` : ''}
                      {m.claimed_at
                        ? `Приєднання ${new Date(m.claimed_at).toLocaleDateString('uk-UA')}`
                        : `Створено ${new Date(m.created_at).toLocaleDateString('uk-UA')}`}
                    </div>
                    {m.status !== 'revoked' && (
                      <div style={{ display: 'flex', gap: 6, marginTop: 8 }}>
                        {m.status === 'pending' && (() => {
                          const link = buildDeepLink(`team_${m.invite_token}`)
                          // Мертвий лінк («#» — коли не задано юзернейм бота)
                          // не можна давати ані копіювати, ані надсилати: той
                          // самий клас, що вже давав прод-інцидент із
                          // TELEGRAM_APP_NAME, і `CreateInviteScreen` його вже
                          // ловить — цей екран лишався єдиною діркою.
                          const usable = /^https?:\/\//.test(link)
                          return (
                            <>
                              <button className="acc-act share" disabled={!usable}
                                onClick={() => handleCopy(link)}>
                                <IconCopy size={14} />Копіювати
                              </button>
                              <button className="acc-act share" disabled={!usable}
                                onClick={() => openTelegramShare(link, 'Запрошення до команди бази нерухомості')}>
                                <IconLink size={14} />Надіслати
                              </button>
                            </>
                          )
                        })()}
                        <button className="acc-act revoke" disabled={revoking === m.id}
                          onClick={() => handleRevoke(m)}>
                          <IconBan size={14} />Відкликати
                        </button>
                      </div>
                    )}
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}

        <div style={{ height: 24 }} />
      </div>
    </div>
  )
}

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
import { IconPlus, IconLink, IconBan, IconUser, IconCopy } from '@/components/Icons'
import { buildDeepLink, openTelegramShare , hapticNotify } from '@/lib/telegram'
import { copyLink } from '@/lib/share'
import type { GuestLink } from '@/types'

const STATUS_LABEL: Record<string, string> = {
  pending: 'Очікує',
  active: 'Активний',
  revoked: 'Відкликано',
}
const STATUS_COLOR: Record<string, string> = {
  pending: 'var(--warn)',
  active: 'var(--ok-light)',
  revoked: 'var(--t4)',
}

export default function ManageGuestsScreen() {
  const { screenParams, showToast, navigate } = useAppStore()
  const [links, setLinks] = useState<GuestLink[]>([])
  const [loading, setLoading] = useState(true)
  const [revoking, setRevoking] = useState<string | null>(null)
  // Помилка завантаження МУСИТЬ мати власний стан. Без нього збій мережі
  // малював «Немає запрошень» — тобто відповідь «доступів немає» на питання
  // «чи є доступи», і власник не мав жодного натяку, що список просто не
  // доїхав. Тост зникає за секунди, порожній стан лишається на екрані.
  const [loadErr, setLoadErr] = useState<string | null>(null)

  const isProperty = !!screenParams.propertyId
  const targetId = screenParams.propertyId ?? screenParams.dbId
  const targetTitle = isProperty ? 'Гості об\'єкта' : 'Гості бази'

  async function load() {
    if (!targetId) return
    setLoading(true)
    try {
      const { data, error } = await supabase
        .from('guest_links')
        .select('id,owner_id,property_id,db_id,invite_token,label,guest_user_id,status,claimed_at,created_at')
        .eq(isProperty ? 'property_id' : 'db_id', targetId)
        .order('created_at', { ascending: false })
      if (error) throw error
      setLinks((data ?? []) as GuestLink[])
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
  }, [targetId])

  async function handleRevoke(link: GuestLink) {
    const ok = await confirmAction({
      title: 'Відкликати доступ?',
      message: `Гість «${link.label ?? 'Гість'}» втратить доступ. Цю дію не можна скасувати.`,
      confirmLabel: 'Відкликати',
      destructive: true,
    })
    if (!ok || offlineGuard()) return
    const id = link.id
    setRevoking(id)
    try {
      // `.select('id')` + `assertAffected` — не формальність: під RLS
      // заблокований UPDATE повертає ПОРОЖНІЙ набір і NULL у `error`, тож без
      // доказу екран малював бейдж «Відкликано», а доступ лишався ЖИВИМ.
      // Це найгірший можливий інстанс класу: мовчазна брехня про БЕЗПЕКУ.
      const { data, error } = await supabase
        .from('guest_links')
        .update({ status: 'revoked' })
        .eq('id', id)
        .select('id')
      if (error) throw error
      assertAffected(data, 1, 'відкликання доступу')
      setLinks(prev => prev.map(l => l.id === id ? { ...l, status: 'revoked' as const } : l))
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

  function handleShareLink(link: string) {
    const text = isProperty ? 'Запрошення до перегляду об\'єкта' : 'Запрошення до перегляду бази'
    openTelegramShare(link, text)
  }

  return (
    <div className="scr bg-blue">
      <Header
        title={targetTitle}
        backLabel="Назад"
        right={
          <button
            className="hdr-a"
            aria-label="Запросити гостя"
            onClick={() => navigate('create-invite', {
              kind: 'guest',
              dbId: screenParams.dbId as string | undefined,
              propertyId: screenParams.propertyId as string | undefined,
            })}
            style={{ background: 'none', border: 'var(--bd)' }}
          >
            <IconPlus size={16} />
          </button>
        }
      />

      <div className="body" style={{ animation: 'cascadeIn .2s ease both' }}>
        {loading ? (
          <SkeletonList count={3} />
        ) : loadErr ? (
          <RetryState onRetry={load} subtitle={loadErr} />
        ) : links.length === 0 ? (
          <div className="empty-state" style={{ paddingTop: 48 }}>
            <div className="empty-ic">👤</div>
            <div className="empty-h">Немає запрошень</div>
            <div className="empty-s">Натисніть + щоб запросити гостя</div>
          </div>
        ) : (
          <div style={{ paddingTop: 8 }}>
            {links.map((link) => (
              <div key={link.id} className="glass-s" style={{ margin: '0 12px 10px', borderRadius: 'var(--r-md)', padding: '12px 14px' }}>
                <div style={{ display: 'flex', alignItems: 'flex-start', gap: 10 }}>
                  <div style={{ width: 36, height: 36, borderRadius: '50%', background: 'var(--info-bg)', display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0, marginTop: 2 }}>
                    <IconUser size={16} color="var(--info)" />
                  </div>
                  <div style={{ flex: 1, minWidth: 0 }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 3 }}>
                      <span style={{ fontSize: 'var(--fs-note)', fontWeight: 'var(--fw-semi)', color: 'var(--t1)', flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                        {link.label ?? 'Гість'}
                      </span>
                      <span style={{ fontSize: 'var(--fs-cap2)', fontWeight: 'var(--fw-semi)', padding: '2px 8px', borderRadius: 'var(--r-pill)', background: `${STATUS_COLOR[link.status]}22`, color: STATUS_COLOR[link.status], flexShrink: 0 }}>
                        {STATUS_LABEL[link.status] ?? link.status}
                      </span>
                    </div>
                    <div style={{ fontSize: 'var(--fs-cap2)', color: 'var(--t4)' }}>
                      {link.claimed_at
                        ? `Прийнято ${new Date(link.claimed_at).toLocaleDateString('uk-UA')}`
                        : `Створено ${new Date(link.created_at).toLocaleDateString('uk-UA')}`}
                    </div>
                    {link.status !== 'revoked' && (() => {
                      const url = buildDeepLink(`guest_${link.invite_token}`)
                      // Мертвий лінк («#» — коли не задано юзернейм бота) не
                      // можна ані копіювати, ані надсилати: власник дізнався б
                      // про поломку від одержувача. Той самий гард уже стоїть у
                      // `CreateInviteScreen`; цей екран лишався діркою.
                      const usable = /^https?:\/\//.test(url)
                      return (
                        <div style={{ display: 'flex', gap: 6, marginTop: 8 }}>
                          <button className="acc-act share" disabled={!usable}
                            onClick={() => handleCopy(url)}>
                            <IconCopy size={14} />Копіювати
                          </button>
                          <button className="acc-act share" disabled={!usable}
                            onClick={() => handleShareLink(url)}>
                            <IconLink size={14} />Надіслати
                          </button>
                          <button className="acc-act revoke" disabled={revoking === link.id}
                            onClick={() => handleRevoke(link)}>
                            <IconBan size={14} />Відкликати
                          </button>
                        </div>
                      )
                    })()}
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

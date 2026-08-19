'use client'

import { useEffect, useState } from 'react'
import { useAppStore } from '@/store/appStore'
import { offlineGuard } from '@/lib/offline'
import { confirmAction } from '@/lib/confirm'
import { supabase } from '@/lib/supabase'
import { humanizeDbError } from '@/lib/utils'
import Header from '@/components/ui/Header'
import { SkeletonList } from '@/components/ui/SkeletonLoader'
import { IconPlus, IconLink, IconBan, IconUser } from '@/components/Icons'
import { buildDeepLink, openTelegramShare , hapticNotify } from '@/lib/telegram'
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
    } catch (e) {
      showToast({ type: 'error', title: 'Помилка завантаження', subtitle: humanizeDbError(e) })
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
      const { error } = await supabase
        .from('guest_links')
        .update({ status: 'revoked' })
        .eq('id', id)
      if (error) throw error
      setLinks(prev => prev.map(l => l.id === id ? { ...l, status: 'revoked' as const } : l))
      hapticNotify('success')
    } catch (e) {
      showToast({ type: 'error', title: 'Помилка', subtitle: humanizeDbError(e) })
    } finally {
      setRevoking(null)
    }
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
                    {link.status !== 'revoked' && (
                      <div style={{ display: 'flex', gap: 6, marginTop: 8 }}>
                        <button
                          style={{ flex: 1, padding: '6px 0', borderRadius: 'var(--r-sm)', background: 'var(--info-bg)', border: 'none', fontSize: 'var(--fs-cap1)', fontWeight: 'var(--fw-semi)', color: 'var(--info)', cursor: 'pointer', display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 4 }}
                          onClick={() => handleShareLink(buildDeepLink(`guest_${link.invite_token}`))}
                        >
                          <IconLink size={12} />Поділитись
                        </button>
                        <button
                          style={{ flex: 1, padding: '6px 0', borderRadius: 'var(--r-sm)', background: 'var(--err-bg)', border: 'none', fontSize: 'var(--fs-cap1)', fontWeight: 'var(--fw-semi)', color: 'var(--err-fg)', cursor: 'pointer', display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 4, opacity: revoking === link.id ? .6 : 1 }}
                          disabled={revoking === link.id}
                          onClick={() => handleRevoke(link)}
                        >
                          <IconBan size={12} />Відкликати
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

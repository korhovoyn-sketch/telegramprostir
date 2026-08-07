'use client'

import { useEffect, useState, useRef } from 'react'
import { useAppStore } from '@/store/appStore'
import { offlineGuard } from '@/lib/offline'
import { supabase } from '@/lib/supabase'
import { humanizeDbError } from '@/lib/utils'
import Header from '@/components/ui/Header'
import Modal from '@/components/ui/Modal'
import { SkeletonList } from '@/components/ui/SkeletonLoader'
import { IconPlus, IconLink, IconBan, IconUsers } from '@/components/Icons'
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
  const { user, screenParams, showToast } = useAppStore()
  const dbId = screenParams.dbId as string | undefined
  const [members, setMembers] = useState<DbMember[]>([])
  const [loading, setLoading] = useState(true)
  const [showCreateModal, setShowCreateModal] = useState(false)
  const [creating, setCreating] = useState(false)
  const [labelText, setLabelText] = useState('')
  const [newLink, setNewLink] = useState<string | null>(null)
  const [revoking, setRevoking] = useState<string | null>(null)
  const [revokeTarget, setRevokeTarget] = useState<DbMember | null>(null)
  const labelInputRef = useRef<HTMLInputElement>(null)

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
    } catch (e) {
      showToast({ type: 'error', title: 'Помилка завантаження', subtitle: humanizeDbError(e) })
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    load()
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [dbId])

  useEffect(() => {
    if (!showCreateModal) return
    const t = setTimeout(() => labelInputRef.current?.focus(), 400)
    return () => clearTimeout(t)
  }, [showCreateModal])

  async function handleCreate() {
    if (!user || !dbId) return
    if (offlineGuard()) return
    setCreating(true)
    try {
      const { data, error } = await supabase
        .from('db_members')
        .insert({ db_id: dbId, label: labelText.trim() || null })
        .select('invite_token')
        .single()
      if (error) throw error
      const token = (data as { invite_token: string }).invite_token
      setLabelText('')
      setShowCreateModal(false)
      setNewLink(buildDeepLink(`team_${token}`))
      await load()
    } catch (e) {
      showToast({ type: 'error', title: 'Не вдалося створити', subtitle: humanizeDbError(e) })
    } finally {
      setCreating(false)
    }
  }

  async function handleRevoke(id: string) {
    if (offlineGuard()) return
    setRevoking(id)
    try {
      const { error } = await supabase
        .from('db_members')
        .update({ status: 'revoked' })
        .eq('id', id)
      if (error) throw error
      setMembers(prev => prev.map(m => m.id === id ? { ...m, status: 'revoked' as const } : m))
      hapticNotify('success')
    } catch (e) {
      showToast({ type: 'error', title: 'Помилка', subtitle: humanizeDbError(e) })
    } finally {
      setRevoking(null)
    }
  }

  async function handleCopyLink(link: string) {
    const ok = await copyLink(link)
    if (ok) showToast({ type: 'success', title: 'Посилання скопійовано' })
    else showToast({ type: 'error', title: 'Не вдалося скопіювати' })
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
            onClick={() => { setLabelText(''); setShowCreateModal(true) }}
            style={{ background: 'none', border: 'var(--bd)' }}
          >
            <IconPlus size={15} />
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
                        {m.status === 'pending' && (
                          <button
                            style={{ flex: 1, padding: '6px 0', borderRadius: 'var(--r-sm)', background: 'var(--info-bg)', border: 'none', fontSize: 'var(--fs-cap1)', fontWeight: 'var(--fw-semi)', color: 'var(--info)', cursor: 'pointer', display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 4 }}
                            onClick={() => openTelegramShare(buildDeepLink(`team_${m.invite_token}`), 'Запрошення до команди бази нерухомості')}
                          >
                            <IconLink size={12} />Поділитись
                          </button>
                        )}
                        <button
                          style={{ flex: 1, padding: '6px 0', borderRadius: 'var(--r-sm)', background: 'var(--err-bg)', border: 'none', fontSize: 'var(--fs-cap1)', fontWeight: 'var(--fw-semi)', color: 'var(--err-fg)', cursor: 'pointer', display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 4, opacity: revoking === m.id ? .6 : 1 }}
                          disabled={revoking === m.id}
                          onClick={() => setRevokeTarget(m)}
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

      {showCreateModal && (
        <Modal
          title="Запросити в команду"
          subtitle="Людина отримає право редагувати об'єкти цієї бази"
          onClose={() => !creating && setShowCreateModal(false)}
          actions={[
            { label: creating ? 'Створення...' : 'Створити запрошення', variant: 'primary', disabled: creating, onClick: handleCreate },
            { label: 'Скасувати', variant: 'secondary', disabled: creating, onClick: () => setShowCreateModal(false) },
          ]}
        >
          <div style={{ paddingTop: 4 }}>
            <div className="fg" style={{ marginBottom: 0 }}>
              <div className="fr" style={{ borderBottom: 'none' }}>
                <div className="fr-l">Підпис (необов&apos;язково)</div>
                <input
                  ref={labelInputRef}
                  className="fr-i"
                  type="text"
                  placeholder="напр. Менеджер Оля"
                  value={labelText}
                  onChange={e => setLabelText(e.target.value)}
                  maxLength={100}
                />
              </div>
            </div>
          </div>
        </Modal>
      )}

      {revokeTarget && (
        <Modal
          title="Відкликати доступ?"
          subtitle={`«${revokeTarget.member_name || revokeTarget.label || 'Учасник'}» втратить право редагувати базу.`}
          onClose={() => setRevokeTarget(null)}
          actions={[
            {
              label: 'Відкликати',
              variant: 'danger',
              onClick: () => {
                hapticNotify('warning')
                const id = revokeTarget.id
                setRevokeTarget(null)
                handleRevoke(id)
              },
            },
            { label: 'Скасувати', variant: 'secondary', onClick: () => setRevokeTarget(null) },
          ]}
        />
      )}

      {newLink && (
        <Modal
          title="Запрошення створено!"
          subtitle="Надішліть майбутньому члену команди"
          onClose={() => setNewLink(null)}
          actions={[
            { label: 'Поділитись в Telegram', variant: 'primary', onClick: () => { openTelegramShare(newLink, 'Запрошення до команди бази нерухомості'); setNewLink(null) } },
            { label: 'Скопіювати', variant: 'secondary', onClick: () => { handleCopyLink(newLink); setNewLink(null) } },
          ]}
        >
          <div style={{ wordBreak: 'break-all', fontSize: 'var(--fs-cap1)', color: 'var(--t3)', fontFamily: 'monospace', background: 'var(--glass-1)', borderRadius: 'var(--r-sm)', padding: '8px 10px', marginTop: 6 }}>
            {newLink}
          </div>
        </Modal>
      )}
    </div>
  )
}

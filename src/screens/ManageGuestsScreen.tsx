'use client'

import { useEffect, useState, useRef } from 'react'
import { useAppStore } from '@/store/appStore'
import { supabase } from '@/lib/supabase'
import Header from '@/components/ui/Header'
import Modal from '@/components/ui/Modal'
import { IconPlus, IconLink, IconBan, IconUser } from '@/components/Icons'
import { buildDeepLink } from '@/lib/telegram'
import type { GuestLink } from '@/types'

const STATUS_LABEL: Record<string, string> = {
  pending: 'Очікує',
  active: 'Активний',
  revoked: 'Відкликано',
}
const STATUS_COLOR: Record<string, string> = {
  pending: '#fbbf24',
  active: '#4ade80',
  revoked: 'var(--t4)',
}

export default function ManageGuestsScreen() {
  const { user, screenParams, showToast } = useAppStore()
  const [links, setLinks] = useState<GuestLink[]>([])
  const [loading, setLoading] = useState(true)
  const [showCreateModal, setShowCreateModal] = useState(false)
  const [creating, setCreating] = useState(false)
  const [labelText, setLabelText] = useState('')
  const [newLink, setNewLink] = useState<string | null>(null)
  const [revoking, setRevoking] = useState<string | null>(null)
  const labelInputRef = useRef<HTMLInputElement>(null)

  const isProperty = !!screenParams.propertyId
  const targetId = screenParams.propertyId ?? screenParams.dbId
  const targetTitle = isProperty ? 'Гості об\'єкта' : 'Гості бази'

  async function load() {
    if (!targetId) return
    setLoading(true)
    try {
      const { data, error } = await supabase
        .from('guest_links')
        .select('*')
        .eq(isProperty ? 'property_id' : 'db_id', targetId)
        .order('created_at', { ascending: false })
      if (error) throw error
      setLinks((data ?? []) as GuestLink[])
    } catch (e) {
      showToast({ type: 'error', title: 'Помилка завантаження', subtitle: (e as Error).message })
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    load()
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [targetId])

  useEffect(() => {
    if (!showCreateModal) return
    const t = setTimeout(() => labelInputRef.current?.focus(), 400)
    return () => clearTimeout(t)
  }, [showCreateModal])

  async function handleCreate() {
    if (!user || !targetId) return
    setCreating(true)
    try {
      const { data, error } = await supabase
        .from('guest_links')
        .insert({
          owner_id: user.id,
          property_id: isProperty ? targetId : null,
          db_id: isProperty ? null : targetId,
          label: labelText.trim() || null,
        })
        .select('invite_token')
        .single()
      if (error) throw error
      const token = (data as { invite_token: string }).invite_token
      const deepLink = buildDeepLink(`guest_${token}`)
      setLabelText('')
      setShowCreateModal(false)
      setNewLink(deepLink)
      await load()
    } catch (e) {
      showToast({ type: 'error', title: 'Не вдалося створити', subtitle: (e as Error).message })
    } finally {
      setCreating(false)
    }
  }

  async function handleRevoke(id: string) {
    setRevoking(id)
    try {
      const { error } = await supabase
        .from('guest_links')
        .update({ status: 'revoked' })
        .eq('id', id)
      if (error) throw error
      setLinks(prev => prev.map(l => l.id === id ? { ...l, status: 'revoked' as const } : l))
      window.Telegram?.WebApp?.HapticFeedback?.notificationOccurred('success')
    } catch (e) {
      showToast({ type: 'error', title: 'Помилка', subtitle: (e as Error).message })
    } finally {
      setRevoking(null)
    }
  }

  function handleShareLink(link: string) {
    const text = isProperty ? 'Запрошення до перегляду об\'єкта' : 'Запрошення до перегляду бази'
    const shareUrl = `https://t.me/share/url?url=${encodeURIComponent(link)}&text=${encodeURIComponent(text)}`
    window.Telegram?.WebApp?.openTelegramLink(shareUrl)
  }

  function handleCopyLink(link: string) {
    navigator.clipboard.writeText(link).then(() => {
      showToast({ type: 'success', title: 'Посилання скопійовано' })
    }).catch(() => {
      showToast({ type: 'error', title: 'Не вдалося скопіювати' })
    })
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
            onClick={() => { setLabelText(''); setShowCreateModal(true) }}
            style={{ background: 'none', border: 'var(--bd)' }}
          >
            <IconPlus size={15} />
          </button>
        }
      />

      <div className="body" style={{ animation: 'cascadeIn .2s ease both' }}>
        {loading ? (
          <div className="loader-wrap"><div className="loader" /></div>
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
                  <div style={{ width: 36, height: 36, borderRadius: '50%', background: 'rgba(122,179,255,.12)', display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0, marginTop: 2 }}>
                    <IconUser size={16} color="#7AB3FF" />
                  </div>
                  <div style={{ flex: 1, minWidth: 0 }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 3 }}>
                      <span style={{ fontSize: 14, fontWeight: 600, color: 'var(--t1)', flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                        {link.label ?? 'Гість'}
                      </span>
                      <span style={{ fontSize: 11, fontWeight: 600, padding: '2px 8px', borderRadius: 'var(--r-pill)', background: `${STATUS_COLOR[link.status]}22`, color: STATUS_COLOR[link.status], flexShrink: 0 }}>
                        {STATUS_LABEL[link.status] ?? link.status}
                      </span>
                    </div>
                    <div style={{ fontSize: 11, color: 'var(--t4)' }}>
                      {link.claimed_at
                        ? `Прийнято ${new Date(link.claimed_at).toLocaleDateString('uk-UA')}`
                        : `Створено ${new Date(link.created_at).toLocaleDateString('uk-UA')}`}
                    </div>
                    {link.status !== 'revoked' && (
                      <div style={{ display: 'flex', gap: 6, marginTop: 8 }}>
                        <button
                          style={{ flex: 1, padding: '6px 0', borderRadius: 'var(--r-sm)', background: 'rgba(122,179,255,.14)', border: 'none', fontSize: 12, fontWeight: 600, color: '#7AB3FF', cursor: 'pointer', display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 4 }}
                          onClick={() => handleShareLink(buildDeepLink(`guest_${link.invite_token}`))}
                        >
                          <IconLink size={12} />Поділитись
                        </button>
                        <button
                          style={{ flex: 1, padding: '6px 0', borderRadius: 'var(--r-sm)', background: 'rgba(248,113,113,.10)', border: 'none', fontSize: 12, fontWeight: 600, color: '#f87171', cursor: 'pointer', display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 4, opacity: revoking === link.id ? .6 : 1 }}
                          disabled={revoking === link.id}
                          onClick={() => handleRevoke(link.id)}
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
          title="Запросити гостя"
          subtitle="Згенеруємо запрошення-посилання"
          onClose={() => !creating && setShowCreateModal(false)}
          actions={[
            { label: creating ? 'Створення...' : 'Створити посилання', variant: 'primary', disabled: creating, onClick: handleCreate },
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
                  placeholder="напр. Орендар, кв. 5"
                  value={labelText}
                  onChange={e => setLabelText(e.target.value)}
                  maxLength={100}
                />
              </div>
            </div>
          </div>
        </Modal>
      )}

      {newLink && (
        <Modal
          title="Посилання створено!"
          subtitle="Надішліть гостю для отримання доступу"
          onClose={() => setNewLink(null)}
          actions={[
            { label: 'Поділитись в Telegram', variant: 'primary', onClick: () => { handleShareLink(newLink); setNewLink(null) } },
            { label: 'Скопіювати', variant: 'secondary', onClick: () => { handleCopyLink(newLink); setNewLink(null) } },
          ]}
        >
          <div style={{ wordBreak: 'break-all', fontSize: 12, color: 'var(--t3)', fontFamily: 'monospace', background: 'var(--glass-1)', borderRadius: 'var(--r-sm)', padding: '8px 10px', marginTop: 6 }}>
            {newLink}
          </div>
        </Modal>
      )}
    </div>
  )
}

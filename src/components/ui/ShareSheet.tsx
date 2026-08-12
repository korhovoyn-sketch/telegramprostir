'use client'

import { useEffect, useState } from 'react'
import { z } from 'zod'
import QRCode from 'react-qr-code'
import { useAppStore } from '@/store/appStore'
import { offlineGuard } from '@/lib/offline'
import { confirmAction as confirmDestructive } from '@/lib/confirm'
import { supabase } from '@/lib/supabase'
import Modal, { modalBtnClass } from '@/components/ui/Modal'
import { buildPublicUrl, openTelegramShare , hapticNotify } from '@/lib/telegram'
import { copyLink } from '@/lib/share'
import { formatLeaseDate } from '@/lib/utils'
import { IconRefresh, IconBan, IconChevronRight, IconClock } from '@/components/Icons'

const ManageShareSchema = z.array(z.object({
  share_token: z.string().nullable(),
  share_expires_at: z.string().nullable(),
  error: z.string().nullable(),
}))

const KIND_TABLE = { db: 'databases', prop: 'properties', col: 'collections' } as const

interface ShareSheetProps {
  kind: 'db' | 'prop' | 'col'
  id: string
  name: string
  shareText: string
  onClose: () => void
}

/**
 * Unified share sheet for databases, properties and collections:
 * QR + link + copy + Telegram share, expiry presets (7/30 days/∞),
 * token rotation and revocation via the manage_share RPC.
 */
export default function ShareSheet({ kind, id, name, shareText, onClose }: ShareSheetProps) {
  const { showToast } = useAppStore()
  const [token, setToken] = useState<string | null>(null)
  const [expiresAt, setExpiresAt] = useState<string | null>(null)
  const [resolvedName, setResolvedName] = useState<string | null>(null)
  const [loading, setLoading] = useState(true)
  const [busy, setBusy] = useState(false)

  useEffect(() => {
    let cancelled = false
    async function load() {
      setLoading(true)
      try {
        const { data } = await supabase
          .from(KIND_TABLE[kind])
          .select('name,share_token,share_expires_at')
          .eq('id', id)
          .single()
        if (cancelled) return
        if (data?.name) setResolvedName(data.name)
        if (data?.share_token) {
          setToken(data.share_token)
          setExpiresAt(data.share_expires_at)
        } else {
          // Row predates token defaults — generate one now so the link works.
          // silent: тост «Старе посилання більше не діє» тут збив би з пантелику,
          // старого посилання ніколи не існувало.
          await runManage('rotate', undefined, { silent: true })
        }
      } finally {
        if (!cancelled) setLoading(false)
      }
    }
    load()
    return () => { cancelled = true }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [kind, id])

  async function runManage(action: 'rotate' | 'set_expiry' | 'clear_expiry' | 'revoke', days?: number, opts?: { silent?: boolean }) {
    // silent-режим (фонове першогенерування при відкритті шита) не має права
    // показувати ЖОДНИХ тостів — ні офлайн-гарда, ні помилки: користувач
    // нічого не робив. Ретрай доступний кнопкою «Створити посилання».
    if (opts?.silent) {
      if (!useAppStore.getState().isOnline) return
    } else if (offlineGuard('Зміни недоступні офлайн')) {
      return
    }
    setBusy(true)
    try {
      const { data, error } = await supabase.rpc('manage_share', {
        p_kind: kind, p_id: id, p_action: action, p_days: days ?? null,
      })
      if (error) throw new Error(error.message)
      const row = ManageShareSchema.parse(data)[0]
      if (!row || row.error) throw new Error(row?.error ?? 'empty response')
      setToken(row.share_token)
      setExpiresAt(row.share_expires_at)
      if (!opts?.silent) {
        hapticNotify('success')
        if (action === 'rotate') showToast({ type: 'success', title: 'Посилання оновлено', subtitle: 'Старе посилання більше не діє' })
        if (action === 'revoke') showToast({ type: 'success', title: 'Доступ відкликано' })
      }
    } catch {
      if (!opts?.silent) showToast({ type: 'error', title: 'Не вдалося змінити посилання' })
    } finally {
      setBusy(false)
    }
  }

  async function askManage(action: 'rotate' | 'revoke') {
    const ok = await confirmDestructive({
      title: action === 'rotate' ? 'Оновити посилання?' : 'Відкликати доступ?',
      message: action === 'rotate'
        ? 'Старе посилання та QR-код перестануть працювати. Усі, з ким ви ділились, втратять доступ.'
        : 'Посилання одразу стане неактивним. Ви зможете створити нове через «Оновити посилання».',
      confirmLabel: action === 'rotate' ? 'Оновити' : 'Відкликати',
      destructive: true,
    })
    if (ok) await runManage(action)
  }

  // Реактивація мертвого лінка пресетом терміну — тільки через підтвердження:
  // revoke лишає токен, тож set_expiry/clear_expiry повернули б доступ УСІМ,
  // хто зберіг старе посилання, непомітно для власника.
  async function askRevive(action: 'set_expiry' | 'clear_expiry', days?: number) {
    const ok = await confirmDestructive({
      title: 'Активувати старе посилання?',
      message: 'Воно знову запрацює для ВСІХ, хто його вже має — включно з тими, у кого ви відкликали доступ. Щоб роздати доступ заново, скористайтесь «Оновити посилання».',
      confirmLabel: 'Активувати старе',
      destructive: true,
    })
    if (ok) await runManage(action, days)
  }

  const url = token ? buildPublicUrl(kind, token) : ''
  const isExpired = !!expiresAt && new Date(expiresAt) <= new Date()
  // Selected expiry preset derived from remaining days (no extra state)
  const daysLeft = expiresAt ? Math.ceil((new Date(expiresAt).getTime() - Date.now()) / 86400000) : null

  async function handleCopy() {
    if (!url) return
    const ok = await copyLink(url)
    if (ok) showToast({ type: 'success', title: 'Посилання скопійовано' })
    else showToast({ type: 'error', title: 'Не вдалося скопіювати', subtitle: 'Виділіть і скопіюйте посилання вручну' })
  }

  return (
    <Modal title={resolvedName ?? name} subtitle="Поділитися" onClose={onClose}>
      {/* QR + link */}
      <div className="qr-hero glass-s" style={{ margin: '0 0 12px' }}>
        <div className="qr-wrap">
          {!loading && url ? (
            <>
              {/* level M: запас корекції для скану з екрана телефону (відблиски,
                  муар) — дефолтний L на 124px читається нестабільно */}
              <QRCode value={url} size={124} level="M" bgColor="#ffffff" fgColor="#000000" style={{ borderRadius: 6, display: 'block', opacity: isExpired ? .25 : 1 }} />
              {isExpired && (
                <div className="qr-dead-ov">
                  {/* літерал: бан лежить на БІЛІЙ QR-картці, --err-fg тюнений під темний фон */}
                  <IconBan size={40} color="#b91c1c" />
                </div>
              )}
            </>
          ) : loading ? (
            <div className="qr-empty"><div className="loader" /></div>
          ) : (
            /* Легасі-рядок без токена + фонове генерування не вдалося (офлайн,
               помилка RPC): без цієї кнопки тут висів би вічний спінер. */
            <button className="qr-empty qr-retry" onClick={() => runManage('rotate')} disabled={busy}>
              Створити посилання
            </button>
          )}
        </div>
        <div className="qr-meta">
          <div className="qr-name">{isExpired ? 'Посилання неактивне' : url ? 'Посилання для перегляду' : 'Посилання ще не створено'}</div>
          <div className="qr-link" style={{ wordBreak: 'break-all', textDecoration: isExpired ? 'line-through' : 'none', opacity: isExpired ? .6 : 1 }}>{url || '…'}</div>
          {isExpired && (
            <div className="qr-hint">Натисніть «Оновити посилання», щоб створити нове</div>
          )}
        </div>
      </div>

      {/* Copy + Telegram share — для мертвого посилання не даємо його ширити.
          Свідомо В ПОТОЦІ, а не в `actions`: пара належить своєму посиланню
          вгорі, а sticky-дно тут займали б кнопки шаринга над небезпечними
          рядками керування. Клас — з `modalBtnClass`, інакше «У Telegram»
          лишається без заливки (див. коментар до хелпера в Modal). */}
      <div style={{ display: 'flex', gap: 8, marginBottom: 12 }}>
        <button className={`${modalBtnClass('secondary')} sm`} disabled={loading || !url || isExpired} onClick={handleCopy}>
          Скопіювати
        </button>
        <button className={`${modalBtnClass('primary')} sm`} disabled={loading || !url || isExpired} onClick={() => openTelegramShare(url, shareText)}>
          У Telegram
        </button>
      </div>

      {/* Expiry */}
      <div className="sheet-group">
        <div className="sheet-row" style={{ cursor: 'default' }}>
          <span className="sheet-ic"><IconClock size={16} /></span>
          <span className="sheet-lbl">Термін дії</span>
          <span style={{ color: isExpired ? 'var(--err-fg)' : 'var(--t3)', fontSize: 'var(--fs-foot)', flexShrink: 0 }}>
            {isExpired ? 'закінчився' : expiresAt ? `до ${formatLeaseDate(expiresAt)}` : 'безстрокове'}
          </span>
        </div>
        <div style={{ padding: '10px 14px 12px' }}>
          <div className="fr-seg">
            {([
              { label: '7 днів',  action: 'set_expiry' as const,   days: 7,          on: daysLeft !== null && daysLeft > 0 && daysLeft <= 7 },
              { label: '30 днів', action: 'set_expiry' as const,   days: 30,         on: daysLeft !== null && daysLeft > 7 && daysLeft <= 30 },
              { label: 'Без обмежень', action: 'clear_expiry' as const, days: undefined, on: !expiresAt },
            ]).map(({ label, action, days, on }) => (
              <button
                type="button"
                key={label}
                className={`fr-seg-b ${on ? 'on' : ''}`}
                // Справжній `disabled`, а не зняття обробника: `onClick={undefined}`
                // лишало cursor:pointer і :active, тож сегмент підсвічувався під
                // пальцем і не робив НІЧОГО, поки летів запит.
                disabled={busy}
                onClick={() => {
                  // Мертвий лінк (revoke/протухання) пресет ОЖИВЛЯЄ з тим самим
                  // токеном — це має бути свідоме рішення, не випадковий тап
                  if (isExpired) askRevive(action, days)
                  else runManage(action, days)
                }}
              >{label}</button>
            ))}
          </div>
        </div>
      </div>

      {/* Management */}
      <div className="sheet-group" style={{ marginBottom: 16 }}>
        <button type="button" className="sheet-row" disabled={busy} onClick={() => askManage('rotate')}>
          <span className="sheet-ic"><IconRefresh size={16} /></span>
          <span className="sheet-lbl">Оновити посилання</span>
          <IconChevronRight size={16} className="sheet-chev" />
        </button>
        <button type="button" className="sheet-row danger" disabled={busy} onClick={() => askManage('revoke')}>
          <span className="sheet-ic"><IconBan size={16} /></span>
          <span className="sheet-lbl">Відкликати доступ</span>
        </button>
      </div>

    </Modal>
  )
}

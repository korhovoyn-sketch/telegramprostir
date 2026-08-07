'use client'

import { useEffect, useState } from 'react'
import { z } from 'zod'
import { useAppStore } from '@/store/appStore'
import { offlineGuard } from '@/lib/offline'
import { supabase, USER_COLUMNS } from '@/lib/supabase'
import Header from '@/components/ui/Header'
import { TG_BOT , hapticNotify } from '@/lib/telegram'
import { scrollFocusedIntoView } from '@/lib/utils'
import type { User } from '@/types'

const SubscribeSchema = z.array(z.object({
  db_id: z.string().uuid().nullable(),
  db_name: z.string().nullable(),
  error: z.string().nullable(),
}))

// Parse db token from scanned QR content.
// Handles deep-link: https://t.me/<bot>?startapp=db_<token>
// public viewer:     https://<domain>/v/?db=<token>   ← what our QR codes encode
// and raw formats:   db_<token>  or  just <token>
function extractDbToken(raw: string): string | null {
  try {
    const url = new URL(raw)
    const startapp = url.searchParams.get('startapp') ?? url.searchParams.get('start') ?? ''
    if (startapp.startsWith('db_')) return startapp.slice(3)
    const dbParam = url.searchParams.get('db')
    if (dbParam) return dbParam
  } catch {
    // Not a URL — try raw token formats
  }
  const match = raw.match(/db_([a-f0-9]+)/i)
  if (match) return match[1]
  // Accept plain hex token (24 chars = share_token length)
  if (/^[a-f0-9]{24}$/i.test(raw.trim())) return raw.trim()
  return null
}

export default function QRScannerScreen() {
  const { user, navigate, showToast } = useAppStore()
  const [scanning, setScanning] = useState(false)
  const [manualToken, setManualToken] = useState('')
  const [submitting, setSubmitting] = useState(false)

  async function subscribeByToken(token: string) {
    if (!user) return
    if (offlineGuard('Підключення до бази недоступне офлайн')) return
    // Token-validated SECURITY DEFINER RPC: checks the token + expiry and
    // creates the subscription server-side (clients can no longer INSERT
    // subscriptions directly — see migration 036).
    const { data, error } = await supabase.rpc('subscribe_to_shared_db', { p_token: token })
    if (error) {
      showToast({ type: 'error', title: 'Помилка підписки', subtitle: 'Спробуйте ще раз' })
      return
    }
    // safeParse: a malformed RPC response must surface the error toast, not
    // throw out of the scan callback and leave the screen stuck silently.
    const parsed = SubscribeSchema.safeParse(data ?? [])
    const row = parsed.success ? parsed.data[0] : undefined
    if (!row || row.error === 'not_found') {
      // 036 filters expired tokens server-side, so "not found" covers both cases
      showToast({ type: 'error', title: 'Базу не знайдено', subtitle: 'Посилання невірне або застаріло' })
      return
    }
    if (row.error === 'own_db' && row.db_id) {
      showToast({ type: 'info', title: 'Це ваша база', subtitle: 'QR-код для ріелторів — не для власника' })
      navigate('db-objects', { dbId: row.db_id })
      return
    }
    if (row.error || !row.db_id) {
      showToast({ type: 'error', title: 'Помилка підписки', subtitle: 'Спробуйте ще раз' })
      return
    }
    // subscribe_to_shared_db may have normalised a default-owner (no databases
    // of their own) to 'realtor' server-side (037) — re-fetch so the store role
    // matches, same as useDeepLink. Best effort: never block navigation.
    try {
      const { data: freshUser } = await supabase
        .from('users')
        .select(USER_COLUMNS)
        .eq('id', user.id)
        .single()
      if (freshUser) useAppStore.getState().setUser(freshUser as User)
    } catch { /* role refresh is best-effort */ }
    hapticNotify('success')
    showToast({ type: 'success', title: 'Базу підключено! 🎉' })
    navigate('realtor-database', { dbId: row.db_id })
  }

  useEffect(() => {
    if (typeof window !== 'undefined' && window.Telegram?.WebApp) {
      const tg = window.Telegram.WebApp as unknown as Record<string, unknown>
      if (typeof tg.showScanQrPopup === 'function') {
        setScanning(true)
        ;(tg.showScanQrPopup as (opts: { text: string }, cb: (r: string | null) => boolean | Promise<boolean>) => void)(
          { text: 'Відскануй QR-код бази prostir' },
          async (result) => {
            if (!result) return false
            const token = extractDbToken(result)
            if (!token) {
              showToast({ type: 'error', title: 'Невірний QR-код', subtitle: 'Відскануйте QR від prostir' })
              return true
            }
            await subscribeByToken(token)
            return true
          }
        )
      }
    }
  }, [user, navigate, showToast]) // eslint-disable-line react-hooks/exhaustive-deps

  async function handleManualSubmit() {
    if (!manualToken.trim() || !user) return
    setSubmitting(true)
    try {
      // Accept full URL, db_ prefix, or raw token
      const token = extractDbToken(manualToken.trim()) ?? manualToken.trim()
      await subscribeByToken(token)
    } finally {
      setSubmitting(false)
    }
  }

  return (
    <div className="scr" style={{ background: '#000' }}>
      <Header title="Сканер QR" backLabel="Назад" />

      <div onFocusCapture={scrollFocusedIntoView} style={{ flex: 1, display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', padding: '0 32px', gap: 24 }}>
        {/* Scanner frame */}
        <div style={{ position: 'relative', width: 240, height: 240 }}>
          <div style={{
            width: '100%', height: '100%',
            border: '2px solid rgba(255,255,255,.15)',
            borderRadius: 16,
            background: 'rgba(255,255,255,.05)',
            display: 'flex', alignItems: 'center', justifyContent: 'center',
          }}>
            <div style={{ fontSize: 48, opacity: 0.4 }}>📷</div>
          </div>
          {/* Corner brackets */}
          {(['tl', 'tr', 'bl', 'br'] as const).map((pos) => (
            <div
              key={pos}
              style={{
                position: 'absolute',
                width: 24, height: 24,
                borderColor: '#a78bfa',
                borderStyle: 'solid',
                borderWidth: 0,
                ...(pos === 'tl' ? { top: -2, left: -2, borderTopWidth: 3, borderLeftWidth: 3, borderTopLeftRadius: 6 } : {}),
                ...(pos === 'tr' ? { top: -2, right: -2, borderTopWidth: 3, borderRightWidth: 3, borderTopRightRadius: 6 } : {}),
                ...(pos === 'bl' ? { bottom: -2, left: -2, borderBottomWidth: 3, borderLeftWidth: 3, borderBottomLeftRadius: 6 } : {}),
                ...(pos === 'br' ? { bottom: -2, right: -2, borderBottomWidth: 3, borderRightWidth: 3, borderBottomRightRadius: 6 } : {}),
              }}
            />
          ))}
          {scanning && (
            <div style={{
              position: 'absolute',
              left: 4, right: 4,
              height: 2,
              background: 'linear-gradient(90deg, transparent, #a78bfa, transparent)',
              animation: 'scanLine 2s ease-in-out infinite',
              top: '50%',
            }} />
          )}
        </div>

        <div style={{ textAlign: 'center' }}>
          <div style={{ color: 'var(--t1)', fontWeight: 'var(--fw-semi)', fontSize: 'var(--fs-call)', marginBottom: 6 }}>
            Відскануйте QR-код
          </div>
          <div style={{ color: 'var(--t3)', fontSize: 'var(--fs-foot)' }}>
            Направте камеру на QR-код від власника бази
          </div>
        </div>

        {/* Manual input — accepts URL, db_ prefix, or raw token */}
        <div style={{ width: '100%', display: 'flex', flexDirection: 'column', gap: 10 }}>
          <div style={{ color: 'var(--t3)', fontSize: 'var(--fs-cap1)', textAlign: 'center' }}>або вставте посилання / токен</div>
          <div style={{ display: 'flex', gap: 8 }}>
            <input
              type="text"
              value={manualToken}
              onChange={(e) => setManualToken(e.target.value)}
              placeholder={`https://t.me/${TG_BOT}?startapp=...`}
              onKeyDown={(e) => { if (e.key === 'Enter') handleManualSubmit() }}
              style={{
                flex: 1,
                height: 44,
                borderRadius: 12,
                border: '1px solid rgba(255,255,255,.15)',
                background: 'var(--glass-2)',
                color: 'var(--t1)',
                fontSize: 'var(--fs-call)',
                padding: '0 14px',
                outline: 'none',
              }}
            />
            <button
              onClick={handleManualSubmit}
              disabled={submitting || !manualToken.trim()}
              style={{
                height: 44,
                paddingInline: 16,
                borderRadius: 12,
                background: submitting ? 'rgba(167,139,250,.3)' : 'rgba(167,139,250,.85)',
                border: 'none',
                color: 'var(--t1)',
                fontWeight: 'var(--fw-semi)',
                fontSize: 'var(--fs-note)',
                cursor: submitting ? 'default' : 'pointer',
                whiteSpace: 'nowrap',
              }}
            >
              {submitting ? '...' : 'Додати'}
            </button>
          </div>
        </div>

      </div>
    </div>
  )
}

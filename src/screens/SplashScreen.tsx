'use client'

import { useEffect, useRef, useState } from 'react'
import { useAppStore } from '@/store/appStore'
import { useAuth, RESTORE_BUDGET_MS } from '@/hooks/useAuth'
import { useTelegram } from '@/hooks/useTelegram'

// How long to wait for a stored session to restore before giving up and
// showing WelcomeScreen. Auto-login (Edge Function) is intentionally NOT done
// here — it hangs the splash at 90% on cold starts. WelcomeScreen handles it.
//
// RESTORE_BUDGET_MS is shared with useAuth's loginViaTelegram, which derives its
// own wait from however much of this budget the in-flight restore already used —
// keeping both screens deferring to one source of truth instead of guessing.

export default function SplashScreen() {
  const [progress, setProgress] = useState(0)
  const [statusText, setStatusText] = useState('Завантажуємо...')
  const navigateRoot = useAppStore((s) => s.navigateRoot)
  const { restoreSession } = useAuth()
  const { isReady } = useTelegram()
  const startedRef = useRef(false)

  // Prefetch screens the user will land on right after splash
  useEffect(() => {
    import('@/screens/WelcomeScreen')
    import('@/screens/DatabaseListScreen')
    import('@/screens/RealtorDashboardScreen')
    import('@/screens/GuestHomeScreen')
    import('@/screens/DatabaseObjectsScreen')
    import('@/screens/ProfileScreen')
    import('@/screens/NotificationsScreen')
  }, [])

  // Pre-warm the Edge Function immediately so it isn't cold when session restore
  // fails and WelcomeScreen falls back to loginViaTelegram. Cold start is 10-30s,
  // the single biggest latency source in the auth flow — start warming it as
  // early as possible rather than waiting, since the fire-and-forget GET is cheap
  // even on the (less common) path where a cached session makes it unnecessary.
  useEffect(() => {
    const url = process.env.NEXT_PUBLIC_SUPABASE_URL
    const key = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY
    if (!url || !key) return
    fetch(`${url}/functions/v1/telegram-auth`, {
      method: 'GET',
      headers: { 'Authorization': `Bearer ${key}`, 'apikey': key },
    }).catch(() => {})
  }, [])

  useEffect(() => {
    if (!isReady) return
    if (startedRef.current) return
    startedRef.current = true

    let cancelled = false
    let ticker: ReturnType<typeof setInterval> | null = null

    // Smoothly animate progress toward a ceiling, stopping short of it
    function animateTo(ceiling: number) {
      if (ticker) clearInterval(ticker)
      ticker = setInterval(() => {
        setProgress(p => {
          if (p >= ceiling) { clearInterval(ticker!); return p }
          return Math.min(p + 1.8, ceiling)
        })
      }, 55)
    }

    async function init() {
      // SDK is ready
      setProgress(14)
      setStatusText('Перевіряємо сесію...')
      animateTo(58)

      const hasSession = await Promise.race([
        restoreSession(),
        new Promise<false>(r => setTimeout(() => r(false), RESTORE_BUDGET_MS)),
      ])

      if (cancelled) return
      if (ticker) clearInterval(ticker)

      if (hasSession) {
        setProgress(100)
        const user = useAppStore.getState().user
        if (!user) { navigateRoot('welcome'); return }
        const startParam = window.Telegram?.WebApp?.initDataUnsafe?.start_param
        if (startParam?.startsWith('db_') || startParam?.startsWith('prop_') || startParam?.startsWith('col_') || startParam?.startsWith('guest_')) return
        if (!user.role) { navigateRoot('role-select'); return }
        if (user.role === 'guest') { navigateRoot('guest-home'); return }
        navigateRoot(user.role === 'owner' ? 'db-list' : 'realtor-dashboard')
        return
      }

      // No session — check for public share links that work without login
      const startParam = window.Telegram?.WebApp?.initDataUnsafe?.start_param ?? ''
      if (startParam.startsWith('db_')) {
        setProgress(100)
        navigateRoot('guest-database', { token: startParam.slice(3) })
        return
      }
      if (startParam.startsWith('guest_')) {
        // Guest invite — show preview then prompt to register
        setProgress(100)
        navigateRoot('guest-database', { token: startParam.slice(6), guestMode: true })
        return
      }

      // No session → go to WelcomeScreen which handles auto-login via Edge Function.
      // We intentionally don't call loginViaTelegram here — the Edge Function cold
      // start (10-30 s) would freeze the splash at 90% with no feedback to the user.
      if (cancelled) return
      if (ticker) clearInterval(ticker)
      setProgress(100)
      navigateRoot('welcome')
    }

    init()

    return () => {
      cancelled = true
      if (ticker) clearInterval(ticker)
    }
  }, [isReady, navigateRoot, restoreSession])

  return (
    <div className="bg-welcome" style={{
      display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center',
      height: 'var(--tg-vh, 100svh)',
      position: 'relative', overflow: 'hidden',
    }}>
      {/* Neon Orb */}
      <div className="splash-orb">
        <div className="splash-ring" />
        <div className="splash-orb-inner">
          <div className="splash-orb-text">{statusText}</div>
          <div className="splash-orb-pct">{Math.round(Math.min(progress, 100))}%</div>
        </div>
      </div>

      <div className="splash-name">prostir</div>
      <div className="splash-sub">платформа нерухомості</div>

      <div style={{ position: 'absolute', bottom: 'calc(32px + var(--safe-bottom))', fontSize: 11, color: 'var(--t4)' }}>
        prostir v1.0.0 · powered by Telegram
      </div>
    </div>
  )
}

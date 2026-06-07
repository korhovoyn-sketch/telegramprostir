'use client'

import { useEffect, useRef, useState } from 'react'
import { useAppStore } from '@/store/appStore'
import { useAuth } from '@/hooks/useAuth'
import { useTelegram } from '@/hooks/useTelegram'

// Give restoreSession enough time — it may re-hydrate the session from Telegram
// CloudStorage and refresh the JWT, which costs a round-trip or two on slow LTE.
// Falling through to the Edge Function login is far slower, so we'd rather wait
// here. A genuinely session-less user still returns false well before this.
const SESSION_TIMEOUT_MS = 8000

export default function SplashScreen() {
  const [progress, setProgress] = useState(0)
  const [statusText, setStatusText] = useState('Завантажуємо...')
  const navigateRoot = useAppStore((s) => s.navigateRoot)
  const { restoreSession, loginViaTelegram } = useAuth()
  const { isReady } = useTelegram()
  const startedRef = useRef(false)

  // Prefetch screens the user will land on right after splash
  useEffect(() => {
    import('@/screens/WelcomeScreen')
    import('@/screens/DatabaseListScreen')
    import('@/screens/RealtorDashboardScreen')
    import('@/screens/DatabaseObjectsScreen')
    import('@/screens/ProfileScreen')
    import('@/screens/NotificationsScreen')
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
        new Promise<false>(r => setTimeout(() => r(false), SESSION_TIMEOUT_MS)),
      ])

      if (cancelled) return
      if (ticker) clearInterval(ticker)

      if (hasSession) {
        setProgress(100)
        const user = useAppStore.getState().user
        if (!user) { navigateRoot('welcome'); return }
        const startParam = window.Telegram?.WebApp?.initDataUnsafe?.start_param
        if (startParam?.startsWith('db_') || startParam?.startsWith('prop_') || startParam?.startsWith('col_')) return
        navigateRoot(user.role === 'owner' ? 'db-list' : 'realtor-dashboard')
        return
      }

      setProgress(62)

      // No session — check for guest share link (db_ without login)
      const startParam = window.Telegram?.WebApp?.initDataUnsafe?.start_param ?? ''
      if (startParam.startsWith('db_')) {
        setProgress(100)
        navigateRoot('guest-database', { token: startParam.slice(3) })
        return
      }

      // Try silent auto-login via Telegram initData
      const initData = window.Telegram?.WebApp?.initData
      if (initData) {
        setProgress(68)
        setStatusText('Авторизація...')
        animateTo(90)
        try {
          await loginViaTelegram(initData)
          if (cancelled) return
          // loginViaTelegram navigates on success — check if we're still on splash
          if (useAppStore.getState().screen !== 'splash') return
        } catch { /* auto-login failed — fall through to WelcomeScreen */ }
      }

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
  }, [isReady, navigateRoot, restoreSession, loginViaTelegram])

  return (
    <div className="scr bg-purple" style={{ alignItems: 'center', justifyContent: 'center' }}>
      {/* Logo */}
      <div style={{
        width: 88,
        height: 88,
        borderRadius: 24,
        background: 'linear-gradient(135deg,#7AB3FF 0%,#A87CFF 50%,#FF7AB8 100%)',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        fontSize: 40,
        fontWeight: 700,
        color: 'var(--t1)',
        marginBottom: 24,
        boxShadow: '0 12px 40px rgba(168,124,255,.4),inset 0 1.5px 0 rgba(255,255,255,.36)',
        letterSpacing: '-.02em',
      }}>
        P
      </div>

      <div style={{ fontSize: 28, fontWeight: 700, color: 'var(--t1)', letterSpacing: '-.03em', marginBottom: 8 }}>
        PropSpace
      </div>
      <div style={{ fontSize: 13, color: 'var(--t3)', marginBottom: 48 }}>
        Управління нерухомістю
      </div>

      {/* Progress bar */}
      <div style={{
        width: 180,
        height: 3,
        background: 'var(--glass-2)',
        borderRadius: 2,
        overflow: 'hidden',
        marginBottom: 12,
      }}>
        <div style={{
          height: '100%',
          width: `${Math.min(progress, 100)}%`,
          background: 'linear-gradient(90deg,#7AB3FF,#A87CFF)',
          borderRadius: 2,
          transition: 'width .12s linear',
        }} />
      </div>
      <div style={{ fontSize: 12, color: 'var(--t3)' }}>
        {statusText} {Math.round(Math.min(progress, 100))}%
      </div>

      <div style={{ position: 'absolute', bottom: 32, fontSize: 11, color: 'var(--t4)' }}>
        v1.0.0 · powered by Telegram
      </div>
    </div>
  )
}

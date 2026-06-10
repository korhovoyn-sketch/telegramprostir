'use client'

import { useEffect, useRef, useState } from 'react'
import { useAppStore } from '@/store/appStore'
import { useAuth } from '@/hooks/useAuth'
import { useTelegram } from '@/hooks/useTelegram'

// How long to wait for a stored session to restore before giving up and
// showing WelcomeScreen. Auto-login (Edge Function) is intentionally NOT done
// here — it hangs the splash at 90% on cold starts. WelcomeScreen handles it.


// Give restoreSession enough time — it may re-hydrate the session from Telegram
// CloudStorage and refresh the JWT, which costs a round-trip or two on slow LTE.
// Falling through to the Edge Function login is far slower, so we'd rather wait
// here. A genuinely session-less user still returns false well before this.
const SESSION_TIMEOUT_MS = 8000

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

      // No session — check for guest share link (db_ without login)
      const startParam = window.Telegram?.WebApp?.initDataUnsafe?.start_param ?? ''
      if (startParam.startsWith('db_')) {
        setProgress(100)
        navigateRoot('guest-database', { token: startParam.slice(3) })
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
    <div className="scr bg-purple" style={{ alignItems: 'center', justifyContent: 'center' }}>
      {/* 3D Liquid Glass App Icon */}
      <div style={{
        width: 96, height: 96, borderRadius: 28, marginBottom: 28,
        position: 'relative', overflow: 'hidden',
        // 3-stop gradient: cool sky at top-left → deep violet at bottom-right (simulates 3D light)
        background: 'linear-gradient(140deg,#b8e0ff 0%,#7ab3ff 18%,#9b6cf8 48%,#c040ff 74%,#6d18c4 100%)',
        boxShadow: [
          '0 28px 72px rgba(110,72,240,.60)',
          '0 8px 24px rgba(110,72,240,.38)',
          'inset 0 2.5px 0 rgba(255,255,255,.48)',  // top rim specular
          'inset 0 -4px 10px rgba(0,0,0,.22)',       // bottom depth
          '0 0 0 1px rgba(255,255,255,.16)',          // outer glass rim
        ].join(','),
      }}>
        {/* Specular highlight — radial white spot mimics 3D light source at top-left */}
        <div style={{
          position: 'absolute', top: 6, left: 8,
          width: 56, height: 34,
          background: 'radial-gradient(ellipse at 38% 32%, rgba(255,255,255,.62) 0%, transparent 70%)',
          filter: 'blur(3px)', borderRadius: '50%', pointerEvents: 'none',
        }} />
        {/* Bottom-right depth shadow for 3D volume */}
        <div style={{
          position: 'absolute', bottom: 0, right: 0,
          width: 60, height: 52,
          background: 'radial-gradient(ellipse at 65% 68%, rgba(0,0,0,.30) 0%, transparent 68%)',
          pointerEvents: 'none',
        }} />
        {/* П — Cyrillic for Простір, with 3D text shadow stack */}
        <span style={{
          position: 'relative', zIndex: 1,
          fontSize: 46, fontWeight: 900, color: '#fff', lineHeight: 1,
          letterSpacing: -2,
          textShadow: [
            '0 1px 0 rgba(255,255,255,.55)',   // top edge highlight
            '0 3px 6px rgba(0,0,0,.32)',        // near shadow
            '0 8px 18px rgba(0,0,0,.22)',       // far shadow
            '0 0 32px rgba(255,255,255,.18)',   // inner glow
          ].join(','),
        }}>П</span>
      </div>

      <div className="splash-name">prostir</div>
      <div className="splash-sub">платформа нерухомості</div>

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
        prostir v1.0.0 · powered by Telegram
      </div>
    </div>
  )
}

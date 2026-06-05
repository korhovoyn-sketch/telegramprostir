'use client'

import { useEffect, useRef, useState } from 'react'
import { useAppStore } from '@/store/appStore'
import { useAuth } from '@/hooks/useAuth'
import { useTelegram } from '@/hooks/useTelegram'

// Hard ceiling: if restoreSession hangs longer than this, try auto-login
const SESSION_TIMEOUT_MS = 5000

export default function SplashScreen() {
  const [progress, setProgress] = useState(0)
  const navigate = useAppStore((s) => s.navigate)
  const { restoreSession, loginViaTelegram } = useAuth()
  const { isReady } = useTelegram()
  // Guard against double-execution if isReady / deps change mid-flight
  const startedRef = useRef(false)

  useEffect(() => {
    if (!isReady) return
    if (startedRef.current) return
    startedRef.current = true

    let cancelled = false

    const interval = setInterval(() => {
      setProgress((p) => {
        if (p >= 85) { clearInterval(interval); return p }
        return p + Math.random() * 12
      })
    }, 100)

    async function init() {
      // Step 1: try to restore existing session from localStorage
      const sessionPromise = restoreSession()
      const timeoutPromise = new Promise<false>((resolve) =>
        setTimeout(() => resolve(false), SESSION_TIMEOUT_MS)
      )

      const hasSession = await Promise.race([sessionPromise, timeoutPromise])

      if (cancelled) return

      if (hasSession) {
        // Existing session restored — go straight to the app
        clearInterval(interval)
        setProgress(100)
        setTimeout(() => {
          if (cancelled) return
          const user = useAppStore.getState().user
          if (!user) { navigate('welcome'); return }
          const startParam = window.Telegram?.WebApp?.initDataUnsafe?.start_param
          if (startParam?.startsWith('db_') || startParam?.startsWith('prop_')) return
          navigate(user.role === 'owner' ? 'db-list' : 'realtor-dashboard')
        }, 300)
        return
      }

      // Step 2: no stored session — if startParam is db_<token>, show guest view
      // (skip auto-login so anonymous users can browse without registering first).
      const startParam = window.Telegram?.WebApp?.initDataUnsafe?.start_param ?? ''
      if (startParam.startsWith('db_')) {
        clearInterval(interval)
        setProgress(100)
        const token = startParam.slice(3)
        navigate('guest-database', { token })
        return
      }

      // Step 3: no stored session — try silent auto-login via Telegram initData.
      // Telegram always provides initData when the app is opened inside Telegram,
      // so returning users never need to press the login button again.
      const initData = window.Telegram?.WebApp?.initData
      if (initData) {
        setProgress(70)
        try {
          // loginViaTelegram navigates on success, so we only need to handle failure
          await loginViaTelegram(initData)
          if (cancelled) return
          // If user is now set, loginViaTelegram already navigated — we're done
          const user = useAppStore.getState().user
          if (user) {
            clearInterval(interval)
            setProgress(100)
            return
          }
        } catch {
          // Auto-login failed — fall through to WelcomeScreen
        }
      }

      if (cancelled) return

      // Step 3: no initData or auto-login failed — show manual login screen
      clearInterval(interval)
      setProgress(100)
      setTimeout(() => {
        if (cancelled) return
        navigate('welcome')
      }, 300)
    }

    init()

    return () => {
      cancelled = true
      clearInterval(interval)
    }
  }, [isReady, navigate, restoreSession, loginViaTelegram])

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
        color: '#fff',
        marginBottom: 24,
        boxShadow: '0 12px 40px rgba(168,124,255,.4),inset 0 1.5px 0 rgba(255,255,255,.36)',
        letterSpacing: '-.02em',
      }}>
        P
      </div>

      <div style={{ fontSize: 28, fontWeight: 700, color: '#fff', letterSpacing: '-.03em', marginBottom: 8 }}>
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
          transition: 'width .1s linear',
        }} />
      </div>
      <div style={{ fontSize: 12, color: 'var(--t4)' }}>
        {progress < 70 ? 'Завантажуємо...' : progress < 90 ? 'Перевіряємо сесію...' : 'Готово'}
        {' '}{Math.round(Math.min(progress, 100))}%
      </div>

      <div style={{ position: 'absolute', bottom: 32, fontSize: 11, color: 'var(--t4)' }}>
        v1.0.0 · powered by Telegram
      </div>
    </div>
  )
}

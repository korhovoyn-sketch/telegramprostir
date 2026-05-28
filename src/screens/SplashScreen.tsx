'use client'

import { useEffect, useState } from 'react'
import { useAppStore } from '@/store/appStore'
import { useAuth } from '@/hooks/useAuth'
import { useTelegram } from '@/hooks/useTelegram'

export default function SplashScreen() {
  const [progress, setProgress] = useState(0)
  const navigate = useAppStore((s) => s.navigate)
  const { restoreSession } = useAuth()
  const { isReady } = useTelegram()

  useEffect(() => {
    if (!isReady) return

    const interval = setInterval(() => {
      setProgress((p) => {
        if (p >= 90) { clearInterval(interval); return p }
        return p + Math.random() * 15
      })
    }, 100)

    restoreSession().then((hasSession) => {
      clearInterval(interval)
      setProgress(100)
      setTimeout(() => {
        const user = useAppStore.getState().user
        if (!hasSession || !user) {
          navigate('welcome')
        } else {
          navigate(user.role === 'owner' ? 'db-list' : 'realtor-dashboard')
        }
      }, 400)
    }).catch(() => {
      clearInterval(interval)
      setProgress(100)
      setTimeout(() => navigate('welcome'), 400)
    })

    return () => clearInterval(interval)
  }, [isReady, navigate, restoreSession])

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
        Завантажуємо дані... {Math.round(Math.min(progress, 100))}%
      </div>

      <div style={{ position: 'absolute', bottom: 32, fontSize: 11, color: 'var(--t4)' }}>
        v1.0.0 · powered by Telegram
      </div>
    </div>
  )
}

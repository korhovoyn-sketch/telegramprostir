'use client'

import { useEffect } from 'react'
import { useAppStore } from '@/store/appStore'
import ProxMascot from '@/components/ProxMascot'
import Confetti from '@/components/Confetti'

export default function SuccessScreen() {
  const { navigate, screenParams } = useAppStore()
  const title = (screenParams.title as string) ?? 'Збережено!'
  const message = (screenParams.message as string) ?? 'Дані успішно збережено'
  const nextScreen = (screenParams.nextScreen as string) ?? 'db-list'
  useEffect(() => {
    const nextParams = (screenParams.nextParams as Record<string, unknown>) ?? {}
    const timer = setTimeout(() => {
      navigate(nextScreen as Parameters<typeof navigate>[0], nextParams)
    }, 3000)
    return () => clearTimeout(timer)
  }, [navigate, nextScreen, screenParams.nextParams])

  return (
    <div className="scr bg-success">
      <Confetti />

      {/* Scroll-safe centered hero */}
      <div className="body" style={{ display: 'flex', flexDirection: 'column' }}>
        <div style={{ margin: 'auto', display: 'flex', flexDirection: 'column', alignItems: 'center', padding: '24px 0' }}>
          <ProxMascot mood="happy" />

          <div style={{ marginTop: 24, textAlign: 'center', padding: '0 32px' }}>
            <div style={{ fontSize: 30, fontWeight: 700, color: 'var(--t1)', marginBottom: 8 }}>
              {title}
            </div>
            <div style={{ fontSize: 15, color: 'var(--t2)', lineHeight: 1.5 }}>
              {message}
            </div>
          </div>

          <div style={{ marginTop: 32, display: 'flex', gap: 6 }}>
            {[0, 1, 2].map((i) => (
              <div
                key={i}
                style={{
                  width: i === 0 ? 20 : 6,
                  height: 6,
                  borderRadius: 3,
                  background: i === 0 ? '#fff' : 'rgba(255,255,255,.4)',
                }}
              />
            ))}
          </div>
        </div>
      </div>
    </div>
  )
}

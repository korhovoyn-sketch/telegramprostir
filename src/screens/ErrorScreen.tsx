'use client'

import { useAppStore } from '@/store/appStore'
import ProxMascot from '@/components/ProxMascot'

export default function ErrorScreen() {
  const { back, screenParams } = useAppStore()
  const message = (screenParams.message as string) ?? 'Щось пішло не так'

  return (
    <div className="scr bg-error">
      {/* Scroll-safe centered hero: margin:auto centers when it fits, scrolls when it doesn't */}
      <div className="body" style={{ display: 'flex', flexDirection: 'column' }}>
        <div style={{ margin: 'auto', display: 'flex', flexDirection: 'column', alignItems: 'center', padding: '24px 0' }}>
          <ProxMascot mood="sad" />

          <div style={{ marginTop: 24, textAlign: 'center', padding: '0 32px' }}>
            <div style={{ fontSize: 26, fontWeight: 700, color: 'var(--t1)', marginBottom: 8 }}>
              Помилка
            </div>
            <div style={{ fontSize: 15, color: 'var(--t2)', lineHeight: 1.5 }}>
              {message}
            </div>
          </div>

          <button
            className="mbtn"
            onClick={back}
            style={{ position: 'relative', bottom: 'auto', left: 'auto', right: 'auto', width: 'auto', marginTop: 40, minWidth: 200 }}
          >
            Спробувати ще раз
          </button>
        </div>
      </div>
    </div>
  )
}

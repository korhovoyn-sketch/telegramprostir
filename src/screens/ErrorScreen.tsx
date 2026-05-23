'use client'

import { useAppStore } from '@/store/appStore'
import ProxMascot from '@/components/ProxMascot'

export default function ErrorScreen() {
  const { back, screenParams } = useAppStore()
  const message = (screenParams.message as string) ?? 'Щось пішло не так'

  return (
    <div className="scr bg-error" style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', gap: 0 }}>
      <ProxMascot mood="sad" />

      <div style={{ marginTop: 24, textAlign: 'center', padding: '0 32px' }}>
        <div style={{ fontSize: 26, fontWeight: 800, color: '#fff', marginBottom: 8 }}>
          Помилка
        </div>
        <div style={{ fontSize: 15, color: 'rgba(255,255,255,.7)', lineHeight: 1.5 }}>
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
  )
}

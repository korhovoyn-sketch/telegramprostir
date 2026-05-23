'use client'

import { useEffect, useState } from 'react'
import { useAppStore } from '@/store/appStore'
import { supabase } from '@/lib/supabase'
import Header from '@/components/ui/Header'
import { IconBolt } from '@/components/Icons'

export default function QRScannerScreen() {
  const { user, navigate, showToast } = useAppStore()
  const [scanning, setScanning] = useState(false)
  const [flashOn, setFlashOn] = useState(false)

  useEffect(() => {
    if (typeof window !== 'undefined' && window.Telegram?.WebApp) {
      const tg = window.Telegram.WebApp as unknown as Record<string, unknown>
      if (typeof tg.showScanQrPopup === 'function') {
        setScanning(true)
        ;(tg.showScanQrPopup as (opts: { text: string }, cb: (r: string | null) => boolean | Promise<boolean>) => void)({ text: 'Відскануй QR-код бази' }, async (result) => {
          if (!result) return false
          const match = result.match(/db_([a-f0-9]{8})/)
          if (!match) {
            showToast({ type: 'error', title: 'Невірний QR-код' })
            return true
          }
          const token = match[1]
          const { data: db } = await supabase
            .from('databases')
            .select('id')
            .ilike('share_token', `${token}%`)
            .single()
          if (!db || !user) {
            showToast({ type: 'error', title: 'Базу не знайдено' })
            return true
          }
          const { error } = await supabase
            .from('realtor_subscriptions')
            .upsert({ realtor_id: user.id, db_id: db.id }, { onConflict: 'realtor_id,db_id' })
          if (!error) {
            showToast({ type: 'success', title: 'Підписку додано!' })
            navigate('realtor-database', { dbId: db.id })
          }
          return true
        })
      }
    }
  }, [user, navigate, showToast])

  return (
    <div className="scr" style={{ background: '#000' }}>
      <Header title="Сканер QR" backLabel="Назад" />

      <div style={{ flex: 1, display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', padding: '0 32px', gap: 32 }}>
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
          {['tl', 'tr', 'bl', 'br'].map((pos) => (
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
          {/* Scan line */}
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
          <div style={{ color: '#fff', fontWeight: 600, fontSize: 16, marginBottom: 6 }}>
            Відскануйте QR-код
          </div>
          <div style={{ color: 'rgba(255,255,255,.5)', fontSize: 13 }}>
            Направте камеру на QR-код від власника бази
          </div>
        </div>

        <button
          style={{
            width: 52, height: 52,
            borderRadius: '50%',
            background: flashOn ? 'rgba(255,220,0,.2)' : 'rgba(255,255,255,.1)',
            border: `1px solid ${flashOn ? 'rgba(255,220,0,.5)' : 'rgba(255,255,255,.2)'}`,
            display: 'flex', alignItems: 'center', justifyContent: 'center',
            cursor: 'pointer',
            color: flashOn ? '#FFD700' : 'rgba(255,255,255,.6)',
          }}
          onClick={() => setFlashOn(!flashOn)}
        >
          <IconBolt size={20} />
        </button>
      </div>
    </div>
  )
}

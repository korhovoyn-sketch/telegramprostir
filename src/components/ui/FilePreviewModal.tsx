'use client'

import { useEffect } from 'react'
import { IconX, IconDownload } from '@/components/Icons'

interface FilePreviewModalProps {
  url: string
  mime: string
  name: string
  onClose: () => void
}

export default function FilePreviewModal({ url, name, onClose }: FilePreviewModalProps) {
  useEffect(() => {
    const tg = window.Telegram?.WebApp
    if (tg?.openLink) tg.openLink(url)
    else window.open(url, '_blank', 'noopener')
  }, [url])

  function handleOpen() {
    const tg = window.Telegram?.WebApp
    if (tg?.openLink) tg.openLink(url)
    else window.open(url, '_blank', 'noopener')
  }

  return (
    <div
      onClick={onClose}
      style={{
        position: 'fixed', inset: 0, zIndex: 200,
        background: 'rgba(0,0,0,.6)',
        display: 'flex', alignItems: 'flex-end',
      }}
    >
      <div
        onClick={e => e.stopPropagation()}
        style={{
          width: '100%',
          background: 'var(--glass-bg, #1a0a2e)',
          borderRadius: '20px 20px 0 0',
          padding: '20px 20px calc(24px + env(safe-area-inset-bottom))',
          border: '.5px solid rgba(255,255,255,.12)',
          borderBottom: 'none',
        }}
      >
        {/* Header */}
        <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 16 }}>
          <div style={{ flex: 1, minWidth: 0 }}>
            <div style={{ fontSize: 15, fontWeight: 700, color: 'var(--t1)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
              {name}
            </div>
            <div style={{ fontSize: 12, color: 'var(--t3)', marginTop: 3 }}>
              Відкривається у браузері
            </div>
          </div>
          <button
            onClick={onClose}
            style={{
              width: 36, height: 36, borderRadius: '50%',
              background: 'var(--glass-2)', border: 'var(--bd)',
              display: 'flex', alignItems: 'center', justifyContent: 'center',
              color: 'var(--t1)', cursor: 'pointer', flexShrink: 0,
            }}
          >
            <IconX size={16} />
          </button>
        </div>

        {/* Open button */}
        <button
          onClick={handleOpen}
          style={{
            display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 8,
            width: '100%', padding: '13px 20px', borderRadius: 14,
            background: 'linear-gradient(135deg,rgba(122,179,255,.2),rgba(167,139,250,.2))',
            border: '.5px solid rgba(122,179,255,.35)',
            color: '#7AB3FF', fontSize: 15, fontWeight: 600, cursor: 'pointer',
          }}
        >
          <IconDownload size={17} />
          Відкрити файл ще раз
        </button>
      </div>
    </div>
  )
}

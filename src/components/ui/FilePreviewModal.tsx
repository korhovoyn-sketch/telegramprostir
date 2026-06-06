'use client'

import { useState } from 'react'
import { IconX, IconDownload } from '@/components/Icons'

interface FilePreviewModalProps {
  url: string
  mime: string
  name: string
  onClose: () => void
}

export default function FilePreviewModal({ url, mime, name, onClose }: FilePreviewModalProps) {
  const [loaded, setLoaded] = useState(false)

  // DOC/DOCX need Google Docs Viewer; PDF renders natively in WebView
  const isDoc = mime.includes('word') || mime.includes('officedocument')
  const iframeSrc = isDoc
    ? `https://docs.google.com/viewer?url=${encodeURIComponent(url)}&embedded=true`
    : url

  // Fallback: open outside TMA (download button)
  function handleOpenExternal() {
    const tg = window.Telegram?.WebApp
    if (tg?.openLink) tg.openLink(url)
    else window.open(url, '_blank', 'noopener')
  }

  return (
    <div style={{
      position: 'fixed',
      inset: 0,
      zIndex: 200,
      background: '#08081a',
      display: 'flex',
      flexDirection: 'column',
    }}>
      {/* ── Header ── */}
      <div style={{
        display: 'flex',
        alignItems: 'center',
        gap: 10,
        padding: 'calc(12px + var(--safe-top)) 12px 12px',
        borderBottom: '.5px solid rgba(255,255,255,.1)',
        background: 'rgba(8,8,26,.96)',
        backdropFilter: 'blur(20px)',
        WebkitBackdropFilter: 'blur(20px)',
        flexShrink: 0,
      }}>
        {/* Close */}
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

        {/* Filename */}
        <span style={{
          flex: 1,
          fontSize: 14, fontWeight: 600, color: 'var(--t1)',
          overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
        }}>
          {name}
        </span>

        {/* Download / open external fallback */}
        <button
          onClick={handleOpenExternal}
          title="Завантажити"
          style={{
            width: 36, height: 36, borderRadius: '50%',
            background: 'var(--glass-2)', border: 'var(--bd)',
            display: 'flex', alignItems: 'center', justifyContent: 'center',
            color: 'var(--t2)', cursor: 'pointer', flexShrink: 0,
          }}
        >
          <IconDownload size={16} />
        </button>
      </div>

      {/* ── Loading spinner (hidden after iframe loads) ── */}
      {!loaded && (
        <div style={{
          position: 'absolute',
          top: '50%', left: '50%',
          transform: 'translate(-50%, -50%)',
          display: 'flex', flexDirection: 'column',
          alignItems: 'center', gap: 12, zIndex: 1,
          pointerEvents: 'none',
        }}>
          <div className="loader" />
          <div style={{ fontSize: 13, color: 'var(--t3)' }}>
            {isDoc ? 'Відкриваємо через Google Docs...' : 'Завантаження PDF...'}
          </div>
        </div>
      )}

      {/* ── iframe ── */}
      <iframe
        src={iframeSrc}
        title={name}
        style={{
          flex: 1,
          border: 'none',
          width: '100%',
          background: 'transparent',
          opacity: loaded ? 1 : 0,
          transition: 'opacity .25s ease',
        }}
        onLoad={() => setLoaded(true)}
      />
    </div>
  )
}

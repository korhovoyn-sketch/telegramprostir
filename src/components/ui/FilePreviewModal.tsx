'use client'

/* eslint-disable @next/next/no-img-element */
import { IconX, IconDownload } from '@/components/Icons'

interface FilePreviewModalProps {
  url: string
  mime: string
  name: string
  onClose: () => void
}

export default function FilePreviewModal({ url, mime, name, onClose }: FilePreviewModalProps) {
  const isPdf   = mime === 'application/pdf'
  const isImage = mime.startsWith('image/')

  function handleDownload() {
    const tg = window.Telegram?.WebApp
    // Bot API 7.10 types not yet in SDK typedefs — cast to access newer methods
    const tgExt = tg as unknown as { isVersionAtLeast?: (v: string) => boolean; downloadFile?: (p: { url: string; file_name: string }) => void }
    if (tgExt.isVersionAtLeast?.('7.10')) {
      tgExt.downloadFile?.({ url, file_name: name })
    } else if (tg?.openLink) {
      tg.openLink(url)
    } else {
      window.open(url, '_blank', 'noopener')
    }
  }

  return (
    <div style={{ position: 'fixed', inset: 0, zIndex: 200, background: '#000', display: 'flex', flexDirection: 'column' }}>
      {/* Top bar */}
      <div style={{
        position: 'absolute', top: 0, left: 0, right: 0, zIndex: 2,
        display: 'flex', alignItems: 'center', gap: 10,
        padding: 'calc(12px + var(--safe-top, 0px)) 16px 12px',
        background: 'linear-gradient(to bottom, rgba(0,0,0,.85), transparent)',
        pointerEvents: 'none',
      }}>
        <button
          onClick={onClose}
          style={{
            width: 36, height: 36, borderRadius: '50%',
            background: 'rgba(255,255,255,.15)',
            border: '1px solid rgba(255,255,255,.2)',
            display: 'flex', alignItems: 'center', justifyContent: 'center',
            color: '#fff', cursor: 'pointer', flexShrink: 0,
            pointerEvents: 'all',
          }}
        >
          <IconX size={18} />
        </button>
        <div style={{
          flex: 1, fontSize: 14, fontWeight: 600, color: '#fff',
          overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
          pointerEvents: 'none',
        }}>
          {name}
        </div>
        {!isPdf && !isImage && (
          <button
            onClick={handleDownload}
            style={{
              width: 36, height: 36, borderRadius: '50%',
              background: 'rgba(255,255,255,.15)',
              border: '1px solid rgba(255,255,255,.2)',
              display: 'flex', alignItems: 'center', justifyContent: 'center',
              color: '#fff', cursor: 'pointer', flexShrink: 0,
              pointerEvents: 'all',
            }}
          >
            <IconDownload size={18} />
          </button>
        )}
      </div>

      {isPdf ? (
        /* PDF: inline iframe — no external browser */
        <iframe
          src={url}
          title={name}
          style={{ flex: 1, width: '100%', border: 'none', background: '#fff' }}
        />
      ) : isImage ? (
        /* Image: fullscreen viewer, tap backdrop to close */
        <div
          onClick={onClose}
          style={{ flex: 1, display: 'flex', alignItems: 'center', justifyContent: 'center', overflow: 'hidden' }}
        >
          <img
            src={url}
            alt={name}
            style={{ maxWidth: '100%', maxHeight: '100%', objectFit: 'contain', animation: 'galleryFadeIn .22s ease both' }}
          />
        </div>
      ) : (
        /* Other (doc/docx): download card */
        <div style={{ flex: 1, display: 'flex', alignItems: 'center', justifyContent: 'center', padding: 24 }}>
          <div style={{
            width: '100%', maxWidth: 320,
            background: 'rgba(255,255,255,.08)', backdropFilter: 'blur(20px)',
            borderRadius: 20, padding: '28px 24px',
            border: '.5px solid rgba(255,255,255,.15)',
            display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 16,
          }}>
            <div style={{
              width: 64, height: 64, borderRadius: 16,
              background: 'rgba(122,179,255,.15)',
              border: '.5px solid rgba(122,179,255,.3)',
              display: 'flex', alignItems: 'center', justifyContent: 'center',
              fontSize: 28,
            }}>
              📄
            </div>
            <div style={{ textAlign: 'center' }}>
              <div style={{
                fontSize: 15, fontWeight: 700, color: '#fff', marginBottom: 6,
                wordBreak: 'break-all', lineHeight: 1.4,
              }}>
                {name}
              </div>
              <div style={{ fontSize: 12, color: 'rgba(255,255,255,.45)' }}>
                Цей формат не можна переглянути напряму
              </div>
            </div>
            <button
              onClick={handleDownload}
              style={{
                display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 8,
                width: '100%', padding: '13px 20px', borderRadius: 14,
                background: 'linear-gradient(135deg,rgba(122,179,255,.25),rgba(167,139,250,.25))',
                border: '.5px solid rgba(122,179,255,.4)',
                color: '#7AB3FF', fontSize: 15, fontWeight: 600, cursor: 'pointer',
              }}
            >
              <IconDownload size={17} />
              Завантажити файл
            </button>
          </div>
        </div>
      )}
    </div>
  )
}

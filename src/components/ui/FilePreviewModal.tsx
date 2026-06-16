'use client'

/* eslint-disable @next/next/no-img-element */
import { useEffect } from 'react'
import { createPortal } from 'react-dom'
import { IconX, IconDownload, IconExternalLink } from '@/components/Icons'

interface FilePreviewModalProps {
  url: string
  mime: string
  name: string
  onClose: () => void
}

export default function FilePreviewModal({ url, mime, name, onClose }: FilePreviewModalProps) {
  const isPdf   = mime === 'application/pdf'
  const isImage = mime.startsWith('image/')

  // Lock body scroll while modal is open; restore on close
  useEffect(() => {
    const prev = document.body.style.overflow
    document.body.style.overflow = 'hidden'
    return () => { document.body.style.overflow = prev }
  }, [])

  // Dismiss on Escape key
  useEffect(() => {
    function onKey(e: KeyboardEvent) { if (e.key === 'Escape') onClose() }
    document.addEventListener('keydown', onKey)
    return () => document.removeEventListener('keydown', onKey)
  }, [onClose])

  function handleOpen() {
    try {
      const tg = window.Telegram?.WebApp
      if (tg?.openLink) {
        tg.openLink(url)
      } else {
        window.open(url, '_blank', 'noopener')
      }
    } catch {
      window.open(url, '_blank', 'noopener')
    }
  }

  function handleDownload() {
    try {
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
    } catch {
      window.open(url, '_blank', 'noopener')
    }
  }

  const content = (
    <div style={{
      position: 'fixed', inset: 0, zIndex: 9999,
      background: '#000',
      display: 'flex', flexDirection: 'column',
    }}>
      {/* Top bar */}
      <div style={{
        display: 'flex', alignItems: 'center', gap: 10, flexShrink: 0,
        padding: 'calc(12px + var(--safe-top, 0px)) 16px 12px',
        background: 'linear-gradient(to bottom, rgba(0,0,0,.85), transparent)',
      }}>
        <button
          onClick={onClose}
          aria-label="Закрити"
          style={{
            width: 36, height: 36, borderRadius: '50%',
            background: 'rgba(255,255,255,.15)',
            border: '1px solid rgba(255,255,255,.2)',
            display: 'flex', alignItems: 'center', justifyContent: 'center',
            color: '#fff', cursor: 'pointer', flexShrink: 0,
          }}
        >
          <IconX size={18} />
        </button>
        <div style={{
          flex: 1, fontSize: 14, fontWeight: 600, color: '#fff',
          overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
        }}>
          {name}
        </div>
        <button
          onClick={handleDownload}
          aria-label="Завантажити файл"
          style={{
            width: 36, height: 36, borderRadius: '50%',
            background: 'rgba(255,255,255,.15)',
            border: '1px solid rgba(255,255,255,.2)',
            display: 'flex', alignItems: 'center', justifyContent: 'center',
            color: '#fff', cursor: 'pointer', flexShrink: 0,
          }}
        >
          <IconDownload size={18} />
        </button>
      </div>

      {isImage ? (
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
        /* PDF / doc / docx — show document card with open+download actions.
           Inline PDF iframes are unreliable in Telegram WebApp (WebView crash risk). */
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
              background: isPdf ? 'rgba(255,107,107,.15)' : 'rgba(122,179,255,.15)',
              border: `.5px solid ${isPdf ? 'rgba(255,107,107,.3)' : 'rgba(122,179,255,.3)'}`,
              display: 'flex', alignItems: 'center', justifyContent: 'center',
              fontSize: 28,
            }}>
              {isPdf ? '📄' : '📝'}
            </div>
            <div style={{ textAlign: 'center' }}>
              <div style={{
                fontSize: 15, fontWeight: 700, color: '#fff', marginBottom: 6,
                wordBreak: 'break-all', lineHeight: 1.4,
              }}>
                {name}
              </div>
              <div style={{ fontSize: 12, color: 'rgba(255,255,255,.45)' }}>
                {isPdf ? 'PDF документ' : 'Word документ'}
              </div>
            </div>
            <div style={{ width: '100%', display: 'flex', flexDirection: 'column', gap: 10 }}>
              <button
                onClick={handleOpen}
                style={{
                  display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 8,
                  width: '100%', padding: '13px 20px', borderRadius: 14,
                  background: 'linear-gradient(135deg,rgba(122,179,255,.25),rgba(167,139,250,.25))',
                  border: '.5px solid rgba(122,179,255,.4)',
                  color: '#7AB3FF', fontSize: 15, fontWeight: 600, cursor: 'pointer',
                }}
              >
                <IconExternalLink size={17} />
                Відкрити
              </button>
              <button
                onClick={handleDownload}
                style={{
                  display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 8,
                  width: '100%', padding: '11px 20px', borderRadius: 14,
                  background: 'rgba(255,255,255,.07)',
                  border: '.5px solid rgba(255,255,255,.18)',
                  color: 'rgba(255,255,255,.8)', fontSize: 14, fontWeight: 500, cursor: 'pointer',
                }}
              >
                <IconDownload size={16} />
                Завантажити
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )

  // Portal renders outside .nav-wrap so position:fixed works relative to viewport,
  // not the will-change:transform ancestor that breaks fixed positioning.
  if (typeof document === 'undefined') return null
  return createPortal(content, document.body)
}

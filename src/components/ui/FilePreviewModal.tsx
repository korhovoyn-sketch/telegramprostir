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

  // Lock scroll on the inner .body div (real scroll container) while open.
  useEffect(() => {
    const appRoot = document.getElementById('app-root')
    const bodyDiv = appRoot?.querySelector<HTMLElement>('.body')
    if (bodyDiv) {
      const prev = bodyDiv.style.overflow
      bodyDiv.style.overflow = 'hidden'
      return () => { bodyDiv.style.overflow = prev }
    }
  }, [])

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
      const tgExt = tg as unknown as {
        isVersionAtLeast?: (v: string) => boolean
        downloadFile?: (p: { url: string; file_name: string }) => void
      }
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

  // Button style reused for top-bar icon buttons — 44×44 minimum touch target (Apple HIG)
  const iconBtnStyle: React.CSSProperties = {
    width: 44, height: 44, borderRadius: '50%',
    background: 'rgba(255,255,255,.15)',
    border: '1px solid rgba(255,255,255,.2)',
    display: 'flex', alignItems: 'center', justifyContent: 'center',
    color: '#fff', cursor: 'pointer', flexShrink: 0,
    WebkitTapHighlightColor: 'transparent',
  }

  const content = (
    // Portal target is #app-root (position:fixed, covers exactly the TG viewport).
    // Using position:absolute + explicit top/right/bottom/left (not inset shorthand)
    // for iOS 14.4 and earlier compatibility.
    // touchAction:none prevents background scroll bleed on mobile WebKit.
    <div
      style={{
        position: 'absolute',
        top: 0, right: 0, bottom: 0, left: 0,
        zIndex: 200,
        background: '#000',
        display: 'flex',
        flexDirection: 'column',
        touchAction: 'none',
        animation: 'fpmSlideUp .22s cubic-bezier(.16,1,.3,1) both',
      }}
      onClick={e => e.stopPropagation()}
    >
      {/* Top bar */}
      <div style={{
        display: 'flex', alignItems: 'center', gap: 10, flexShrink: 0,
        padding: 'calc(12px + env(safe-area-inset-top, 0px)) 12px 12px',
        background: 'linear-gradient(to bottom, rgba(0,0,0,.9), transparent)',
      }}>
        <button onClick={onClose} aria-label="Закрити" style={iconBtnStyle}>
          <IconX size={20} />
        </button>
        <div style={{
          flex: 1, fontSize: 14, fontWeight: 600, color: '#fff',
          overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
          paddingLeft: 2,
        }}>
          {name}
        </div>
        <button onClick={handleDownload} aria-label="Завантажити файл" style={iconBtnStyle}>
          <IconDownload size={20} />
        </button>
      </div>

      {isImage ? (
        // Image: tap backdrop to close
        <div
          onClick={onClose}
          style={{
            flex: 1, display: 'flex', alignItems: 'center', justifyContent: 'center',
            overflow: 'hidden', cursor: 'zoom-out',
          }}
        >
          <img
            src={url}
            alt={name}
            style={{
              maxWidth: '100%', maxHeight: '100%',
              objectFit: 'contain',
              animation: 'galleryFadeIn .22s ease both',
            }}
            onClick={e => e.stopPropagation()}
          />
        </div>
      ) : (
        // PDF / DOC — card with open + download. Tap backdrop to close.
        <div
          onClick={onClose}
          style={{
            flex: 1, display: 'flex', alignItems: 'center', justifyContent: 'center',
            padding: '24px 24px calc(24px + env(safe-area-inset-bottom, 0px))',
            cursor: 'default',
          }}
        >
          <div
            onClick={e => e.stopPropagation()}
            style={{
              width: '100%', maxWidth: 320,
              background: 'rgba(255,255,255,.08)',
              backdropFilter: 'blur(20px)',
              WebkitBackdropFilter: 'blur(20px)',
              borderRadius: 20, padding: '28px 24px',
              border: '.5px solid rgba(255,255,255,.15)',
              display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 16,
            }}
          >
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
                  width: '100%', padding: '14px 20px', borderRadius: 14,
                  background: 'linear-gradient(135deg,rgba(122,179,255,.25),rgba(167,139,250,.25))',
                  border: '.5px solid rgba(122,179,255,.4)',
                  color: '#7AB3FF', fontSize: 15, fontWeight: 600, cursor: 'pointer',
                  WebkitTapHighlightColor: 'transparent',
                }}
              >
                <IconExternalLink size={17} />
                Відкрити
              </button>
              <button
                onClick={handleDownload}
                style={{
                  display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 8,
                  width: '100%', padding: '13px 20px', borderRadius: 14,
                  background: 'rgba(255,255,255,.07)',
                  border: '.5px solid rgba(255,255,255,.18)',
                  color: 'rgba(255,255,255,.8)', fontSize: 14, fontWeight: 500, cursor: 'pointer',
                  WebkitTapHighlightColor: 'transparent',
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

  if (typeof document === 'undefined') return null
  const appRoot = document.getElementById('app-root')
  if (!appRoot) return null
  return createPortal(content, appRoot)
}

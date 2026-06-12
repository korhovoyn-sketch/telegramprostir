'use client'

/* eslint-disable @next/next/no-img-element */
import { useState, useRef, useEffect } from 'react'
import { useAppStore } from '@/store/appStore'
import { IconX, IconShare, IconDownload, IconChevronLeft, IconChevronRight } from '@/components/Icons'
import type { PropertyPhoto } from '@/types'

export default function PhotoGalleryScreen() {
  const { back, screenParams } = useAppStore()
  const photos = (screenParams.photos as PropertyPhoto[]) ?? []
  const initialIndex = (screenParams.initialIndex as number) ?? 0
  const [current, setCurrent] = useState(initialIndex)

  const touchStartX = useRef(0)
  const touchStartY = useRef(0)
  const thumbStripRef = useRef<HTMLDivElement>(null)
  const thumbRefs = useRef<(HTMLDivElement | null)[]>([])

  // Auto-scroll thumbnail strip to keep active thumb visible
  useEffect(() => {
    const el = thumbRefs.current[current]
    if (el) el.scrollIntoView({ behavior: 'smooth', block: 'nearest', inline: 'center' })
  }, [current])

  function prev() { setCurrent((i) => (i > 0 ? i - 1 : photos.length - 1)) }
  function next() { setCurrent((i) => (i < photos.length - 1 ? i + 1 : 0)) }

  function handleTouchStart(e: React.TouchEvent) {
    touchStartX.current = e.touches[0].clientX
    touchStartY.current = e.touches[0].clientY
  }

  function handleTouchEnd(e: React.TouchEvent) {
    const dx = e.changedTouches[0].clientX - touchStartX.current
    const dy = Math.abs(e.changedTouches[0].clientY - touchStartY.current)
    if (dy > 60) return // vertical scroll, ignore
    if (dx < -50) {
      // swipe left → next
      window.Telegram?.WebApp?.HapticFeedback?.impactOccurred('light')
      setCurrent((i) => Math.min(i + 1, photos.length - 1))
    } else if (dx > 50) {
      // swipe right → prev
      window.Telegram?.WebApp?.HapticFeedback?.impactOccurred('light')
      setCurrent((i) => Math.max(i - 1, 0))
    }
  }

  useEffect(() => {
    function onKey(e: KeyboardEvent) {
      if (e.key === 'ArrowRight') setCurrent((i) => Math.min(i + 1, photos.length - 1))
      if (e.key === 'ArrowLeft') setCurrent((i) => Math.max(i - 1, 0))
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [photos.length])

  const photo = photos[current]
  const url = photo
    ? `${process.env.NEXT_PUBLIC_SUPABASE_URL}/storage/v1/object/public/photos/${photo.storage_path}`
    : null

  function handleShare() {
    if (!photo) return
    const imageUrl = `${process.env.NEXT_PUBLIC_SUPABASE_URL}/storage/v1/object/public/photos/${photo.storage_path}`
    const shareText = `Фото нерухомості ${current + 1}/${photos.length}`
    const shareUrl = `https://t.me/share/url?url=${encodeURIComponent(imageUrl)}&text=${encodeURIComponent(shareText)}`
    if (typeof window !== 'undefined' && window.Telegram?.WebApp) {
      window.Telegram.WebApp.openTelegramLink(shareUrl)
    }
  }

  function handleDownload() {
    if (!url || !photo) return
    const tg = window.Telegram?.WebApp
    const fileName = photo.storage_path.split('/').pop() ?? 'photo.jpg'
    // Bot API 7.10 types not yet in SDK typedefs — cast to access newer methods
    const tgExt = tg as unknown as { isVersionAtLeast?: (v: string) => boolean; downloadFile?: (p: { url: string; file_name: string }) => void }
    if (tgExt.isVersionAtLeast?.('7.10')) {
      tgExt.downloadFile?.({ url, file_name: fileName })
    } else if (tg?.openLink) {
      tg.openLink(url)
    } else {
      window.open(url, '_blank')
    }
  }

  return (
    <div style={{
      position: 'fixed', inset: 0,
      background: '#000',
      display: 'flex', flexDirection: 'column',
      zIndex: 100,
    }}>
      {/* Top bar */}
      <div style={{
        display: 'flex', alignItems: 'center', justifyContent: 'space-between',
        padding: '12px 16px',
        paddingTop: 'calc(12px + var(--safe-top))',
        background: 'linear-gradient(to bottom, rgba(0,0,0,.8), transparent)',
        position: 'absolute', top: 0, left: 0, right: 0, zIndex: 2,
      }}>
        <button
          aria-label="Закрити"
          onClick={back}
          style={{
            width: 36, height: 36, borderRadius: '50%',
            background: 'rgba(255,255,255,.15)',
            border: '1px solid rgba(255,255,255,.2)',
            display: 'flex', alignItems: 'center', justifyContent: 'center',
            color: 'var(--t1)',
          }}
        >
          <IconX size={18} />
        </button>
        <div style={{ color: 'var(--t2)', fontSize: 14 }}>
          {current + 1} / {photos.length}
        </div>
        <div style={{ display: 'flex', gap: 8 }}>
          <button
            aria-label="Завантажити фото"
            onClick={handleDownload}
            style={{
              width: 36, height: 36, borderRadius: '50%',
              background: 'rgba(255,255,255,.15)',
              border: '1px solid rgba(255,255,255,.2)',
              display: 'flex', alignItems: 'center', justifyContent: 'center',
              color: 'var(--t1)',
            }}
          >
            <IconDownload size={18} />
          </button>
          <button
            aria-label="Поділитись фото"
            onClick={handleShare}
            style={{
              width: 36, height: 36, borderRadius: '50%',
              background: 'rgba(255,255,255,.15)',
              border: '1px solid rgba(255,255,255,.2)',
              display: 'flex', alignItems: 'center', justifyContent: 'center',
              color: 'var(--t1)',
            }}
          >
            <IconShare size={18} />
          </button>
        </div>
      </div>

      {/* Main image */}
      <div
        style={{ flex: 1, display: 'flex', alignItems: 'center', justifyContent: 'center', position: 'relative' }}
        onTouchStart={handleTouchStart}
        onTouchEnd={handleTouchEnd}
      >
        {/* Counter badge */}
        <div style={{
          position: 'absolute', top: 16, right: 16, zIndex: 10,
          background: 'rgba(0,0,0,.55)', backdropFilter: 'blur(8px)',
          padding: '4px 10px', borderRadius: 'var(--r-pill)',
          fontSize: 13, fontWeight: 600, color: 'var(--t1)',
        }}>
          {current + 1} / {photos.length}
        </div>
        {url ? (
          <img
            key={url}
            src={url}
            alt={`Photo ${current + 1}`}
            style={{ maxWidth: '100%', maxHeight: '100%', objectFit: 'contain', animation: 'galleryFadeIn .22s ease both' }}
          />
        ) : (
          <div style={{ fontSize: 64, opacity: 0.3 }}>🖼️</div>
        )}

        {photos.length > 1 && (
          <>
            <button
              aria-label="Попереднє фото"
              onClick={prev}
              style={{
                position: 'absolute', left: 16,
                width: 40, height: 40, borderRadius: '50%',
                background: 'rgba(255,255,255,.15)',
                border: '1px solid rgba(255,255,255,.2)',
                display: 'flex', alignItems: 'center', justifyContent: 'center',
                color: 'var(--t1)',
              }}
            >
              <IconChevronLeft size={20} />
            </button>
            <button
              aria-label="Наступне фото"
              onClick={next}
              style={{
                position: 'absolute', right: 16,
                width: 40, height: 40, borderRadius: '50%',
                background: 'rgba(255,255,255,.15)',
                border: '1px solid rgba(255,255,255,.2)',
                display: 'flex', alignItems: 'center', justifyContent: 'center',
                color: 'var(--t1)',
              }}
            >
              <IconChevronRight size={20} />
            </button>
          </>
        )}
      </div>

      {/* Thumbnail strip */}
      {photos.length > 1 && (
        <div
          ref={thumbStripRef}
          style={{
            display: 'flex', gap: 6,
            padding: '12px 16px',
            paddingBottom: 'calc(12px + var(--safe-bottom))',
            overflowX: 'auto',
            scrollbarWidth: 'none',
            background: 'linear-gradient(to top, rgba(0,0,0,.8), transparent)',
          }}
        >
          {photos.map((p, i) => {
            const thumbUrl = `${process.env.NEXT_PUBLIC_SUPABASE_URL}/storage/v1/object/public/photos/${p.storage_path}`
            return (
              <div
                key={p.id}
                ref={(el) => { thumbRefs.current[i] = el }}
                onClick={() => setCurrent(i)}
                style={{
                  width: 56, height: 56, flexShrink: 0,
                  borderRadius: 8,
                  overflow: 'hidden',
                  border: i === current ? '2px solid #a78bfa' : '2px solid transparent',
                  cursor: 'pointer',
                  background: 'rgba(255,255,255,.1)',
                  display: 'flex', alignItems: 'center', justifyContent: 'center',
                  transition: 'border-color .2s ease',
                }}
              >
                <img src={thumbUrl} alt="" loading="lazy" style={{ width: '100%', height: '100%', objectFit: 'cover' }} />
              </div>
            )
          })}
        </div>
      )}
    </div>
  )
}

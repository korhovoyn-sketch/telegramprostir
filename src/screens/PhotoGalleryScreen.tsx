'use client'

/* eslint-disable @next/next/no-img-element */
import { useState } from 'react'
import { useAppStore } from '@/store/appStore'
import { IconX, IconShare, IconChevronLeft, IconChevronRight } from '@/components/Icons'
import type { PropertyPhoto } from '@/types'

export default function PhotoGalleryScreen() {
  const { back, screenParams } = useAppStore()
  const photos = (screenParams.photos as PropertyPhoto[]) ?? []
  const initialIndex = (screenParams.initialIndex as number) ?? 0
  const [current, setCurrent] = useState(initialIndex)

  function prev() { setCurrent((i) => (i > 0 ? i - 1 : photos.length - 1)) }
  function next() { setCurrent((i) => (i < photos.length - 1 ? i + 1 : 0)) }

  const photo = photos[current]
  const url = photo
    ? `${process.env.NEXT_PUBLIC_SUPABASE_URL}/storage/v1/object/public/photos/${photo.storage_path}`
    : null

  function handleShare() {
    if (!url) return
    if (typeof window !== 'undefined' && window.Telegram?.WebApp) {
      window.Telegram.WebApp.openTelegramLink(
        `https://t.me/share/url?url=${encodeURIComponent(url)}`
      )
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
          onClick={back}
          style={{
            width: 36, height: 36, borderRadius: '50%',
            background: 'rgba(255,255,255,.15)',
            border: '1px solid rgba(255,255,255,.2)',
            display: 'flex', alignItems: 'center', justifyContent: 'center',
            color: '#fff',
          }}
        >
          <IconX size={18} />
        </button>
        <div style={{ color: 'rgba(255,255,255,.7)', fontSize: 14 }}>
          {current + 1} / {photos.length}
        </div>
        <button
          onClick={handleShare}
          style={{
            width: 36, height: 36, borderRadius: '50%',
            background: 'rgba(255,255,255,.15)',
            border: '1px solid rgba(255,255,255,.2)',
            display: 'flex', alignItems: 'center', justifyContent: 'center',
            color: '#fff',
          }}
        >
          <IconShare size={18} />
        </button>
      </div>

      {/* Main image */}
      <div style={{ flex: 1, display: 'flex', alignItems: 'center', justifyContent: 'center', position: 'relative' }}>
        {url ? (
          <img
            src={url}
            alt={`Photo ${current + 1}`}
            style={{ maxWidth: '100%', maxHeight: '100%', objectFit: 'contain' }}
          />
        ) : (
          <div style={{ fontSize: 64, opacity: 0.3 }}>🖼️</div>
        )}

        {photos.length > 1 && (
          <>
            <button
              onClick={prev}
              style={{
                position: 'absolute', left: 16,
                width: 40, height: 40, borderRadius: '50%',
                background: 'rgba(255,255,255,.15)',
                border: '1px solid rgba(255,255,255,.2)',
                display: 'flex', alignItems: 'center', justifyContent: 'center',
                color: '#fff',
              }}
            >
              <IconChevronLeft size={20} />
            </button>
            <button
              onClick={next}
              style={{
                position: 'absolute', right: 16,
                width: 40, height: 40, borderRadius: '50%',
                background: 'rgba(255,255,255,.15)',
                border: '1px solid rgba(255,255,255,.2)',
                display: 'flex', alignItems: 'center', justifyContent: 'center',
                color: '#fff',
              }}
            >
              <IconChevronRight size={20} />
            </button>
          </>
        )}
      </div>

      {/* Thumbnail strip */}
      {photos.length > 1 && (
        <div style={{
          display: 'flex', gap: 6,
          padding: '12px 16px',
          paddingBottom: 'calc(12px + var(--safe-bottom))',
          overflowX: 'auto',
          background: 'linear-gradient(to top, rgba(0,0,0,.8), transparent)',
        }}>
          {photos.map((p, i) => {
            const thumbUrl = `${process.env.NEXT_PUBLIC_SUPABASE_URL}/storage/v1/object/public/photos/${p.storage_path}`
            return (
              <div
                key={p.id}
                onClick={() => setCurrent(i)}
                style={{
                  width: 56, height: 56, flexShrink: 0,
                  borderRadius: 8,
                  overflow: 'hidden',
                  border: i === current ? '2px solid #a78bfa' : '2px solid transparent',
                  cursor: 'pointer',
                  background: 'rgba(255,255,255,.1)',
                  display: 'flex', alignItems: 'center', justifyContent: 'center',
                }}
              >
                <img src={thumbUrl} alt="" style={{ width: '100%', height: '100%', objectFit: 'cover' }} />
              </div>
            )
          })}
        </div>
      )}
    </div>
  )
}

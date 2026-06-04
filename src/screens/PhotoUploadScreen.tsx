'use client'

import { useEffect, useState, useRef } from 'react'
import { useAppStore } from '@/store/appStore'
import Header from '@/components/ui/Header'
import { supabase } from '@/lib/supabase'
import { IconCheck, IconX } from '@/components/Icons'

/* eslint-disable @next/next/no-img-element */

interface UploadItem {
  file: File
  status: 'pending' | 'uploading' | 'done' | 'error'
  progress: number
  path?: string
  errorMsg?: string
}

export default function PhotoUploadScreen() {
  const { screenParams, back, showToast } = useAppStore()
  const propertyId = screenParams.propertyId as string
  const MAX_MB = 10
  const ALLOWED = /\.(jpe?g|png|webp|heic|heif)$/i
  const rawFiles = (screenParams.files as File[]) ?? []
  const files = rawFiles.filter((f) =>
    (ALLOWED.test(f.name) || f.type.startsWith('image/')) &&
    f.size <= MAX_MB * 1024 * 1024
  )

  // Stable preview URLs — created once, revoked on unmount
  const [previews] = useState<string[]>(() => files.map((f) => URL.createObjectURL(f)))
  useEffect(() => () => previews.forEach((u) => URL.revokeObjectURL(u)), [previews])

  const [queue, setQueue] = useState<UploadItem[]>(
    files.map((f) => ({ file: f, status: 'pending', progress: 0 }))
  )

  // Derive done from queue — no separate boolean that can get stuck
  const total = queue.length
  const doneCount = queue.filter((x) => x.status === 'done').length
  const errorCount = queue.filter((x) => x.status === 'error').length
  const done = total > 0 && (doneCount + errorCount) === total
  const overallPct = total > 0 ? Math.round((doneCount / total) * 100) : 0

  // Auto-navigate back 1.5s after all uploads finish
  const backedRef = useRef(false)
  useEffect(() => {
    if (!done || backedRef.current) return
    if (doneCount > 0) {
      showToast({ type: 'success', title: `${doneCount} фото завантажено` })
    }
    const timer = setTimeout(() => {
      backedRef.current = true
      back()
    }, 1500)
    return () => clearTimeout(timer)
  }, [done, doneCount, showToast, back])

  useEffect(() => {
    if (files.length === 0) return
    let idx = 0

    async function uploadNext() {
      if (idx >= files.length) return

      const file = files[idx]
      const currentIdx = idx
      setQueue((q) => q.map((x, i) => i === currentIdx ? { ...x, status: 'uploading', progress: 10 } : x))

      const rawExt = file.name.split('.').pop() ?? ''
      const ext = /^[a-z0-9]{2,5}$/i.test(rawExt) ? rawExt.toLowerCase() : 'jpg'
      const path = `${propertyId}/${Date.now()}_${currentIdx}_${Math.random().toString(36).slice(2)}.${ext}`

      try {
        const { error: upErr } = await supabase.storage
          .from('photos')
          .upload(path, file)

        if (upErr) {
          setQueue((q) => q.map((x, i) => i === currentIdx
            ? { ...x, status: 'error', progress: 0, errorMsg: upErr.message } : x))
          showToast({ type: 'error', title: 'Помилка завантаження', subtitle: upErr.message })
        } else {
          const { error: dbErr } = await supabase
            .from('property_photos')
            .insert({ property_id: propertyId, storage_path: path, sort_order: currentIdx })
          if (dbErr) {
            // File uploaded but DB record failed — clean up storage
            await supabase.storage.from('photos').remove([path]).catch(() => {})
            setQueue((q) => q.map((x, i) => i === currentIdx
              ? { ...x, status: 'error', progress: 0, errorMsg: dbErr.message } : x))
            showToast({ type: 'error', title: 'Помилка збереження', subtitle: dbErr.message })
          } else {
            setQueue((q) => q.map((x, i) => i === currentIdx
              ? { ...x, status: 'done', progress: 100, path } : x))
          }
        }
      } catch (e) {
        const msg = (e as Error).message ?? 'Невідома помилка'
        setQueue((q) => q.map((x, i) => i === currentIdx
          ? { ...x, status: 'error', progress: 0, errorMsg: msg } : x))
        showToast({ type: 'error', title: 'Помилка завантаження', subtitle: msg })
      }

      idx++
      uploadNext()
    }

    uploadNext()
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  const radius = 44
  const circ = 2 * Math.PI * radius
  const offset = circ * (1 - overallPct / 100)

  return (
    <div className="scr bg-violet">
      <Header title="Завантаження фото" backLabel="Назад" />

      <div className="body" style={{ alignItems: 'center', justifyContent: 'center', display: 'flex', flexDirection: 'column', gap: 24 }}>
        {/* Circular progress */}
        <div style={{ position: 'relative', width: 112, height: 112 }}>
          <svg width="112" height="112" style={{ transform: 'rotate(-90deg)' }}>
            <circle cx="56" cy="56" r={radius} fill="none" stroke="rgba(255,255,255,.1)" strokeWidth="8" />
            <circle
              cx="56" cy="56" r={radius}
              fill="none"
              stroke={done && errorCount === 0 ? '#4ade80' : done && doneCount === 0 ? '#f87171' : '#a78bfa'}
              strokeWidth="8"
              strokeLinecap="round"
              strokeDasharray={circ}
              strokeDashoffset={done ? 0 : offset}
              style={{ transition: 'stroke-dashoffset 0.4s ease, stroke 0.3s ease' }}
            />
          </svg>
          <div style={{
            position: 'absolute', inset: 0,
            display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center',
          }}>
            {done ? (
              <span className="icon-check-pop">
                <IconCheck size={28} color="#4ade80" />
              </span>
            ) : (
              <>
                <div style={{ fontSize: 20, fontWeight: 700, color: '#fff' }}>{overallPct}%</div>
                <div style={{ fontSize: 10, color: 'var(--t3)' }}>{doneCount}/{total}</div>
              </>
            )}
          </div>
        </div>

        <div style={{ textAlign: 'center' }}>
          <div style={{ color: '#fff', fontWeight: 600, fontSize: 16 }}>
            {done ? (errorCount > 0 && doneCount === 0 ? 'Помилка завантаження' : 'Завантажено!') : 'Завантаження...'}
          </div>
          <div style={{ color: 'var(--t3)', fontSize: 13, marginTop: 4 }}>
            {done
              ? (errorCount > 0 ? `${doneCount} успішно, ${errorCount} з помилкою` : `${doneCount} фото збережено`)
              : `${doneCount} з ${total} фото`
            }
          </div>
        </div>

        {/* Queue list */}
        <div className="glass-s" style={{ width: '100%', borderRadius: 14, overflow: 'hidden' }}>
          {queue.map((item, i) => (
            <div
              key={i}
              style={{
                display: 'flex', alignItems: 'center', gap: 12,
                padding: '10px 14px',
                borderBottom: i < queue.length - 1 ? '1px solid rgba(255,255,255,.06)' : 'none',
              }}
            >
              {/* Thumbnail preview */}
              <div style={{
                width: 44, height: 44, borderRadius: 8,
                background: 'rgba(255,255,255,.08)',
                display: 'flex', alignItems: 'center', justifyContent: 'center',
                flexShrink: 0, overflow: 'hidden',
                border: item.status === 'error'
                  ? '1.5px solid #f87171'
                  : item.status === 'done'
                  ? '1.5px solid #4ade80'
                  : '1.5px solid rgba(255,255,255,.1)',
                transition: 'border-color .3s ease',
              }}>
                {previews[i] ? (
                  <img
                    src={previews[i]}
                    alt=""
                    style={{ width: '100%', height: '100%', objectFit: 'cover',
                      opacity: item.status === 'pending' ? 0.5 : 1,
                      transition: 'opacity .3s ease' }}
                  />
                ) : null}
              </div>
              <div style={{ flex: 1, minWidth: 0 }}>
                <div style={{ fontSize: 13, color: 'var(--t2)', fontWeight: 500, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                  {item.file.name}
                </div>
                {item.status === 'uploading' && (
                  <div style={{ marginTop: 4, height: 3, background: 'rgba(255,255,255,.1)', borderRadius: 2, overflow: 'hidden' }}>
                    <div style={{ height: '100%', width: `${item.progress}%`, background: '#a78bfa', transition: 'width .3s ease' }} />
                  </div>
                )}
                {item.status === 'error' && item.errorMsg && (
                  <div style={{ marginTop: 2, fontSize: 11, color: '#f87171', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                    {item.errorMsg}
                  </div>
                )}
                {item.status === 'pending' && (
                  <div style={{ marginTop: 2, fontSize: 11, color: 'var(--t4)' }}>
                    {(item.file.size / 1024 / 1024).toFixed(1)} MB
                  </div>
                )}
                {item.status === 'done' && (
                  <div style={{ marginTop: 2, fontSize: 11, color: '#4ade80' }}>Збережено</div>
                )}
              </div>
              <div style={{ flexShrink: 0 }}>
                {item.status === 'done' && <IconCheck size={16} color="#4ade80" />}
                {item.status === 'error' && <IconX size={16} color="#f87171" />}
                {item.status === 'uploading' && (
                  <div className="loader" style={{ width: 14, height: 14 }} />
                )}
              </div>
            </div>
          ))}
        </div>

        {done && (
          <button
            className="mbtn"
            onClick={back}
            style={{ position: 'relative', bottom: 'auto', left: 'auto', right: 'auto', width: 'auto', minWidth: 200 }}
          >
            Готово
          </button>
        )}
      </div>
    </div>
  )
}

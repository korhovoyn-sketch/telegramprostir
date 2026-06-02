'use client'

import { useEffect, useState } from 'react'
import { useAppStore } from '@/store/appStore'
import Header from '@/components/ui/Header'
import { supabase } from '@/lib/supabase'
import { IconCheck, IconX, IconCloudUpload } from '@/components/Icons'

interface UploadItem {
  file: File
  status: 'pending' | 'uploading' | 'done' | 'error'
  progress: number
  path?: string
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
  const [queue, setQueue] = useState<UploadItem[]>(
    files.map((f) => ({ file: f, status: 'pending', progress: 0 }))
  )
  const [done, setDone] = useState(false)

  useEffect(() => {
    if (files.length === 0) return
    let idx = 0

    async function uploadNext() {
      if (idx >= queue.length) {
        setDone(true)
        showToast({ type: 'success', title: `${queue.length} фото завантажено` })
        return
      }
      const item = queue[idx]
      setQueue((q) => q.map((x, i) => i === idx ? { ...x, status: 'uploading', progress: 10 } : x))

      const ext = (item.file.name.split('.').pop() ?? 'jpg').replace(/[^a-z0-9]/gi, '')
      const path = `${propertyId}/${Date.now()}_${idx}.${ext}`
      const { error } = await supabase.storage
        .from('photos')
        .upload(path, item.file, { upsert: true })

      if (error) {
        setQueue((q) => q.map((x, i) => i === idx ? { ...x, status: 'error', progress: 0 } : x))
      } else {
        await supabase.from('property_photos').insert({ property_id: propertyId, storage_path: path, sort_order: idx })
        setQueue((q) => q.map((x, i) => i === idx ? { ...x, status: 'done', progress: 100, path } : x))
      }
      idx++
      uploadNext()
    }

    uploadNext()
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  const total = queue.length
  const doneCount = queue.filter((x) => x.status === 'done').length
  const overallPct = total > 0 ? Math.round((doneCount / total) * 100) : 0
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
              fill="none" stroke="#a78bfa" strokeWidth="8"
              strokeLinecap="round"
              strokeDasharray={circ}
              strokeDashoffset={offset}
              style={{ transition: 'stroke-dashoffset 0.4s ease' }}
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
            {done ? 'Завантажено!' : 'Завантаження...'}
          </div>
          <div style={{ color: 'var(--t3)', fontSize: 13, marginTop: 4 }}>
            {doneCount} з {total} фото
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
              <div style={{
                width: 36, height: 36, borderRadius: 8,
                background: 'rgba(255,255,255,.08)',
                display: 'flex', alignItems: 'center', justifyContent: 'center',
                flexShrink: 0,
              }}>
                <IconCloudUpload size={16} color="var(--t3)" />
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
          <button className="mbtn" onClick={back} style={{ position: 'relative', bottom: 'auto', left: 'auto', right: 'auto', width: 'auto', minWidth: 200 }}>
            Готово
          </button>
        )}
      </div>
    </div>
  )
}

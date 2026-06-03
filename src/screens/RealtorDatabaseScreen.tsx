'use client'

import { useEffect, useState } from 'react'
import { useAppStore } from '@/store/appStore'
import { supabase } from '@/lib/supabase'
import Header from '@/components/ui/Header'
import SearchBar from '@/components/ui/SearchBar'
import { StatusBadge } from '@/components/ui/Badge'
import SkeletonLoader from '@/components/ui/SkeletonLoader'
import { IconShare, IconBookmark, IconPhoto } from '@/components/Icons'
import { formatPrice, calcRent, calcUtilities, DB_TYPE_LABELS } from '@/lib/utils'
import type { Database, Property, PropertyStatus } from '@/types'

export default function RealtorDatabaseScreen() {
  const { screenParams, navigate, showToast } = useAppStore()
  const [db, setDb] = useState<Database | null>(null)
  const [properties, setProperties] = useState<Property[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(false)
  const [search, setSearch] = useState('')
  const [tab, setTab] = useState<'all' | PropertyStatus>('all')

  useEffect(() => {
    async function load() {
      if (!screenParams.dbId) return
      setLoading(true)
      setError(false)
      try {
        const [dbRes, propsRes] = await Promise.all([
          supabase.from('databases').select('*').eq('id', screenParams.dbId).single(),
          supabase.from('properties').select('*, photos:property_photos(*)').eq('db_id', screenParams.dbId).order('created_at', { ascending: false }),
        ])
        if (dbRes.error) throw dbRes.error
        if (propsRes.error) throw propsRes.error
        setDb(dbRes.data as Database)
        setProperties((propsRes.data ?? []) as Property[])
      } catch (e) {
        setError(true)
        showToast({ type: 'error', title: 'Помилка завантаження', subtitle: (e as Error).message })
      } finally {
        setLoading(false)
      }
    }
    load()
  }, [screenParams.dbId, showToast])

  const filtered = properties.filter((p) => {
    const matchSearch = p.name.toLowerCase().includes(search.toLowerCase())
    const matchTab = tab === 'all' || p.status === tab
    return matchSearch && matchTab
  })

  const counts = {
    all: properties.length,
    free: properties.filter(p => p.status === 'free').length,
  }

  if (!db) return (
    <div className="scr bg-cyan">
      <Header title="База" backLabel="Бази" />
      {error ? (
        <div className="empty-state" style={{ paddingTop: 40 }}>
          <div className="empty-ic">⚠️</div>
          <div className="empty-h">Помилка завантаження</div>
          <div className="empty-s">Перевір підключення і спробуй ще раз</div>
        </div>
      ) : (
        <div className="loader-wrap"><div className="loader" /></div>
      )}
    </div>
  )

  return (
    <div className="scr bg-cyan">
      <Header
        title={db.name}
        subtitle={DB_TYPE_LABELS[db.type]}
        backLabel="Бази"
        right={
          <button className="hdr-a" style={{ background: 'none', border: 'var(--bd)' }}>
            <IconBookmark size={16} />
          </button>
        }
      />

      <div className="body">
        {/* Owner card */}
        <div className="owner-c glass-s" style={{ margin: '0 12px 12px' }}>
          <div className="owner-av av-grad-2">О</div>
          <div className="owner-mn">
            <div className="owner-n">Власник</div>
            <div className="owner-s">
              <span>🟢</span>
              <span>Онлайн</span>
            </div>
          </div>
          <button className="owner-act">
            <span>💬</span>
          </button>
        </div>

        {/* Tabs */}
        <div className="seg">
          {([
            { id: 'all', label: `Всі (${counts.all})` },
            { id: 'free', label: `Вільно (${counts.free})` },
          ] as const).map((t) => (
            <div key={t.id} className={`seg-b ${tab === t.id ? 'on' : ''}`} onClick={() => { window.Telegram?.WebApp?.HapticFeedback.selectionChanged(); setTab(t.id) }}>
              {t.label}
            </div>
          ))}
        </div>

        <SearchBar value={search} onChange={setSearch} placeholder="Пошук об&apos;єкту..." />

        {loading ? (
          <SkeletonLoader />
        ) : filtered.length === 0 ? (
          <div className="empty-state" style={{ paddingTop: 24 }}>
            <div className="empty-ic">🔍</div>
            <div className="empty-h">Нічого не знайдено</div>
            <button
              style={{ marginTop: 16, padding: '8px 20px', borderRadius: 'var(--r-pill)', background: 'var(--glass-2)', border: 'var(--bd)', color: 'var(--t2)', fontSize: 13, cursor: 'pointer' }}
              onClick={() => setSearch('')}
            >
              Очистити пошук
            </button>
          </div>
        ) : (
          <div className="list" style={{ marginBottom: 80 }}>
            {filtered.map((p) => {
              const rent = p.rent_rate && p.area_useful ? calcRent(p.area_useful, p.rent_rate, p.rent_type) : 0
              const utils = p.utilities_rate && p.area_total ? calcUtilities(p.area_total, p.utilities_rate) : 0
              const total = rent + utils

              return (
                <div
                  key={p.id}
                  className="obj-card glass-s"
                  onClick={() => navigate('property-detail', { propertyId: p.id, dbId: db.id })}
                >
                  <div className="obj-hd">
                    <div>
                      <div className="obj-t">{p.name}</div>
                      {p.floor && <div className="obj-s">🏢 {p.floor} поверх</div>}
                    </div>
                    <StatusBadge status={p.status} />
                  </div>
                  <div className="obj-met">
                    {p.area_useful && <div className="obj-mt">📐 {p.area_useful}/{p.area_total ?? p.area_useful} м²</div>}
                    {p.has_parking && <div className="obj-mt">🅿️ {p.parking_spaces}</div>}
                    {(p.photos?.length ?? 0) > 0 && <div className="obj-mt"><IconPhoto size={11} /> {p.photos!.length}</div>}
                  </div>
                  {total > 0 && (
                    <div className="obj-tot">
                      <div className="obj-tot-l">На місяць</div>
                      <div className="obj-tot-v">{formatPrice(total)}</div>
                    </div>
                  )}
                </div>
              )
            })}
          </div>
        )}
      </div>

      <button className="mbtn" onClick={() => {
        // Use full share_token (never slice — Telegram start= supports 64 chars)
        const token = db.share_token ?? db.id
        const link = `https://t.me/propspacebot?start=db_${token}`
        if (typeof window !== 'undefined' && window.Telegram?.WebApp) {
          window.Telegram.WebApp.openTelegramLink(`https://t.me/share/url?url=${encodeURIComponent(link)}`)
        }
      }}>
        <IconShare size={18} /> Поділитись базою
      </button>
    </div>
  )
}

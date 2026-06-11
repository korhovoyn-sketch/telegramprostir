'use client'

import { useEffect, useState } from 'react'
import { supabase } from '@/lib/supabase'
import { useAppStore } from '@/store/appStore'
import { StatusBadge } from '@/components/ui/Badge'
import Header from '@/components/ui/Header'
import { IconBuilding } from '@/components/Icons'
import { formatPrice, calcRent } from '@/lib/utils'
import type { PropertyStatus, RentType } from '@/types'

interface SharedProperty {
  id: string
  name: string
  status: PropertyStatus
  area_useful: number | null
  area_total: number | null
  rent_rate: number | null
  rent_type: RentType
  floor: string | null
  first_photo: string | null
}

interface SharedCollectionData {
  id: string
  name: string
  properties: SharedProperty[]
}

function getPhotoUrl(storagePath: string): string {
  return `${process.env.NEXT_PUBLIC_SUPABASE_URL}/storage/v1/object/public/photos/${storagePath}`
}

export default function SharedCollectionScreen() {
  const { screenParams, user } = useAppStore()
  const collectionId = screenParams.collectionId as string | undefined

  const [data, setData] = useState<SharedCollectionData | null>(null)
  const [loading, setLoading] = useState(true)
  const [notFound, setNotFound] = useState(false)

  const currency = (user as unknown as { currency?: string })?.currency ?? 'USD'

  useEffect(() => {
    if (!collectionId) { setNotFound(true); setLoading(false); return }
    let cancelled = false

    async function load() {
      try {
        const { data: result } = await supabase.rpc('get_shared_collection', { p_collection_id: collectionId })
        if (cancelled) return
        if (!result) setNotFound(true)
        else setData(result as SharedCollectionData)
      } catch {
        if (!cancelled) setNotFound(true)
      } finally {
        if (!cancelled) setLoading(false)
      }
    }

    load()
    return () => { cancelled = true }
  }, [collectionId])

  if (loading) {
    return (
      <div className="scr bg-violet" style={{ alignItems: 'center', justifyContent: 'center' }}>
        <div className="loader" />
      </div>
    )
  }

  if (notFound || !data) {
    return (
      <div className="scr bg-violet">
        <Header title="Підбірка" backLabel="Назад" />
        <div className="empty-state" style={{ paddingTop: 48 }}>
          <div className="empty-ic">🔗</div>
          <div className="empty-h">Підбірку не знайдено</div>
          <div className="empty-s">Посилання недійсне або підбірку ще не опубліковано</div>
        </div>
      </div>
    )
  }

  return (
    <div className="scr bg-violet">
      <Header title={data.name} subtitle={`${data.properties.length} об'єктів`} backLabel="Назад" />

      <div className="body">
        {data.properties.length === 0 ? (
          <div className="empty-state" style={{ paddingTop: 32 }}>
            <div className="empty-ic">🏢</div>
            <div className="empty-h">Підбірка порожня</div>
            <div className="empty-s">Ріелтор ще не додав об&apos;єктів</div>
          </div>
        ) : (
          <div className="list">
            {data.properties.map((p) => {
              const thumbUrl = p.first_photo ? getPhotoUrl(p.first_photo) : null
              const rent = p.rent_rate && p.area_useful
                ? calcRent(p.area_useful, p.rent_rate, p.rent_type)
                : 0

              return (
                <div key={p.id} className="row glass-s" style={{ alignItems: 'flex-start', gap: 10 }}>
                  <div
                    className="row-ic"
                    style={{
                      backgroundImage: thumbUrl ? `url(${thumbUrl})` : undefined,
                      backgroundSize: 'cover',
                      backgroundPosition: 'center',
                      background: thumbUrl ? undefined : 'rgba(123,48,235,.18)',
                      flexShrink: 0,
                    }}
                  >
                    {!thumbUrl && <IconBuilding size={18} color="#A87CFF" />}
                  </div>

                  <div className="row-mn" style={{ flex: 1, minWidth: 0 }}>
                    <div className="row-t">{p.name}</div>
                    <div className="row-s" style={{ gap: 6, flexWrap: 'wrap', marginTop: 3 }}>
                      <StatusBadge status={p.status} />
                      {p.area_useful && (
                        <span>{p.area_useful}{p.area_total ? `/${p.area_total}` : ''} м²</span>
                      )}
                      {p.floor && <span>🏢 {p.floor} пов.</span>}
                      {rent > 0 && (
                        <span style={{ color: 'var(--t2)', fontWeight: 600 }}>
                          {formatPrice(rent, currency)}/міс
                        </span>
                      )}
                    </div>
                  </div>
                </div>
              )
            })}
          </div>
        )}
      </div>
    </div>
  )
}

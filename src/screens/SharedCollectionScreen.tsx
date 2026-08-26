'use client'

import { useEffect, useState } from 'react'
import { supabase } from '@/lib/supabase'
import { useAppStore } from '@/store/appStore'
import { StatusBadge } from '@/components/ui/Badge'
import Header from '@/components/ui/Header'
import { IconBuilding } from '@/components/Icons'
import { formatPrice, calcRent, basisArea, computedRentUnit, photoUrl } from '@/lib/utils'
import type { PropertyStatus, RentType } from '@/types'

interface SharedProperty {
  id: string
  name: string
  status: PropertyStatus
  area_useful: number | null
  area_total: number | null
  /** Приходить із `get_public_collection_preview` (050). До міграції — undefined,
   *  і `basisArea` фолбечиться на розрахункову: саме той дефолт, що й був. */
  area_basis?: string | null
  rent_rate: number | null
  rent_type: RentType
  floor: string | null
  first_photo: string | null
}

interface SharedCollectionData {
  name: string
  /** Валюта ВЛАСНИКА обʼєктів, а не глядача — див. коментар у `load`. */
  currency: string
  properties: SharedProperty[]
}

/** Рядок, який віддає `get_public_collection_preview` — по одному на обʼєкт. */
interface PreviewRow {
  collection_name: string
  owner_currency: string | null
  property_id: string | null
  property_name: string | null
  property_status: string | null
  property_floor: string | null
  property_area_useful: number | null
  property_area_total: number | null
  property_area_basis: string | null
  property_rent_type: string | null
  property_rent_rate: number | null
  first_photo: string | null
}

export default function SharedCollectionScreen() {
  const { screenParams } = useAppStore()
  const collectionId = screenParams.collectionId as string | undefined
  const colToken = screenParams.colToken as string | undefined

  const [data, setData] = useState<SharedCollectionData | null>(null)
  const [loading, setLoading] = useState(true)
  const [notFound, setNotFound] = useState(false)

  useEffect(() => {
    // Авторизує ТОКЕН, а не `collectionId`. Попередній шлях
    // (`get_shared_collection(p_collection_id)`) був IDOR: SECURITY DEFINER,
    // виданий anon, приймав пряме посилання на обʼєкт і не перевіряв токен
    // узагалі — тобто ротація посилання нікого не відрізала, хоч підтвердження
    // дослівно обіцяє протилежне. Без токена екран нічого не показує.
    if (!colToken) { setNotFound(true); setLoading(false); return }
    let cancelled = false

    async function load() {
      try {
        const { data: rows, error } = await supabase
          .rpc('get_public_collection_preview', { p_token: colToken })
        if (cancelled) return
        const list = (rows ?? []) as PreviewRow[]
        if (error || list.length === 0) { setNotFound(true); return }
        setData({
          name: list[0].collection_name,
          // Валюта ВЛАСНИКА, не глядача: раніше екран брав `user.currency`, тож
          // ціни, ведені в ₴, показувались глядачу-доларовику як «$18/м²» —
          // той самий клас, який для публічної /v закрила міграція 040.
          currency: list[0].owner_currency ?? 'USD',
          properties: list
            .filter((r): r is PreviewRow & { property_id: string } => !!r.property_id)
            .map((r) => ({
              id: r.property_id,
              name: r.property_name ?? '',
              status: (r.property_status ?? 'free') as PropertyStatus,
              area_useful: r.property_area_useful,
              area_total: r.property_area_total,
              area_basis: r.property_area_basis,
              rent_rate: r.property_rent_rate,
              rent_type: (r.property_rent_type ?? 'per_m2') as RentType,
              floor: r.property_floor,
              first_photo: r.first_photo,
            })),
        })
      } catch {
        if (!cancelled) setNotFound(true)
      } finally {
        if (!cancelled) setLoading(false)
      }
    }

    load()
    return () => { cancelled = true }
  }, [colToken, collectionId])

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
      <Header title={data.name} subtitle={`${data.properties.length} обʼєктів`} backLabel="Назад" />

      <div className="body">
        {data.properties.length === 0 ? (
          <div className="empty-state" style={{ paddingTop: 32 }}>
            <div className="empty-ic">🏢</div>
            <div className="empty-h">Підбірка порожня</div>
            <div className="empty-s">Ріелтор ще не додав обʼєктів</div>
          </div>
        ) : (
          <div className="list">
            {data.properties.map((p) => {
              const thumbUrl = p.first_photo ? photoUrl(p.first_photo) : null
              const rent = p.rent_rate
                ? calcRent(basisArea(p.area_useful, p.area_total, p.area_basis), p.rent_rate, p.rent_type)
                : 0

              return (
                <div key={p.id} className="row glass-s" style={{ alignItems: 'flex-start', gap: 10 }}>
                  <div
                    className="row-ic"
                    style={{
                      backgroundImage: thumbUrl ? `url(${thumbUrl})` : undefined,
                      backgroundSize: 'cover',
                      backgroundPosition: 'center',
                      background: thumbUrl ? undefined : 'var(--purple-bg)',
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
                      {p.floor && <span style={{ display: 'inline-flex', alignItems: 'center', gap: 3 }}><IconBuilding size={12} color="var(--t3)" />{p.floor} пов.</span>}
                      {rent > 0 && (
                        <span style={{ color: 'var(--t2)', fontWeight: 'var(--fw-semi)' }}>
                          {formatPrice(rent, data.currency)}{computedRentUnit(p.rent_type)}
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

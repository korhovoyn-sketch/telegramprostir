'use client'

import { useEffect, useState } from 'react'
import { supabase } from '@/lib/supabase'
import { useAppStore } from '@/store/appStore'
import { StatusBadge } from '@/components/ui/Badge'
import Header from '@/components/ui/Header'
import RetryState from '@/components/ui/RetryState'
import { IconBuilding, IconTelegram } from '@/components/Icons'
import { formatPrice, calcRent, basisArea, computedRentUnit, photoUrl, thumbBackground } from '@/lib/utils'
import { openTgUrl } from '@/lib/telegram'
import type { PropertyStatus, RentType } from '@/types'
import { tr } from '@/lib/i18n'

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
  sale_price?: number | null
}

interface SharedCollectionData {
  name: string
  /** Підпис під назвою: кількість для підбірки, назва бази для оголошення. */
  subtitle: string
  /** Валюта ВЛАСНИКА обʼєктів, а не глядача — див. коментар у `load`. */
  currency: string
  properties: SharedProperty[]
  /** Лише в режимі оголошення (`propToken`). */
  description?: string | null
  owner?: { name: string; tg: string | null; phone: string | null }
}

/** Рядок `get_public_property_preview` — те саме, що бачить публічна /v. */
interface PropPreviewRow {
  property_id: string
  property_name: string
  property_status: string
  property_floor: string | null
  property_area_useful: number | null
  property_area_total: number | null
  property_area_basis: string | null
  property_rent_type: string | null
  property_rent_rate: number | null
  property_sale_price: number | null
  property_description: string | null
  db_name: string
  owner_first_name: string | null
  owner_last_name: string | null
  owner_tg_username: string | null
  owner_phone: string | null
  owner_currency: string | null
  photos: string[] | null
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
  // Оголошення: `prop_`-лінк відкрив той, хто до обʼєкта доступу НЕ має
  // (сторонній із публічної /v). Картка обʼєкта для нього — це «Обʼєкт не
  // знайдено», бо RLS чужого не віддає; тут він бачить те саме, що на /v.
  const propToken = screenParams.propToken as string | undefined
  const isProp = !!propToken

  const [data, setData] = useState<SharedCollectionData | null>(null)
  const [loading, setLoading] = useState(true)
  const [notFound, setNotFound] = useState(false)
  /**
   * Збій ЗВʼЯЗКУ — окремий стан, а не той самий «не знайдено».
   *
   * Зливати їх не можна: обрив мережі казав людині, якій рієлтор щойно надіслав
   * лінк, впевнене «посилання недійсне», і повторити не було чим. Рієлтор
   * дізнавався про це як «твоє посилання не працює». Публічна /v цей розподіл
   * робить від початку (`networkErrorState`), тут його просто не було.
   */
  const [netErr, setNetErr] = useState(false)
  const [reloadKey, setReloadKey] = useState(0)

  useEffect(() => {
    // Авторизує ТОКЕН, а не `collectionId`. Попередній шлях
    // (`get_shared_collection(p_collection_id)`) був IDOR: SECURITY DEFINER,
    // виданий anon, приймав пряме посилання на обʼєкт і не перевіряв токен
    // узагалі — тобто ротація посилання нікого не відрізала, хоч підтвердження
    // дослівно обіцяє протилежне. Без токена екран нічого не показує.
    if (!colToken && !propToken) { setNotFound(true); setLoading(false); return }
    let cancelled = false
    setNetErr(false)
    setNotFound(false)
    setLoading(true)

    async function loadProp() {
      try {
        const { data: rows, error } = await supabase
          .rpc('get_public_property_preview', { p_token: propToken })
        if (cancelled) return
        if (error) { setNetErr(true); return }
        const r = ((rows ?? []) as PropPreviewRow[])[0]
        if (!r) { setNotFound(true); return }
        const name = [r.owner_first_name, r.owner_last_name].filter(Boolean).join(' ')
        setData({
          name: r.property_name,
          subtitle: r.db_name,
          currency: r.owner_currency ?? 'USD',
          properties: [{
            id: r.property_id,
            name: r.property_name,
            status: (r.property_status ?? 'free') as PropertyStatus,
            area_useful: r.property_area_useful,
            area_total: r.property_area_total,
            area_basis: r.property_area_basis,
            rent_rate: r.property_rent_rate,
            rent_type: (r.property_rent_type ?? 'per_m2') as RentType,
            floor: r.property_floor,
            first_photo: r.photos?.[0] ?? null,
            sale_price: r.property_sale_price,
          }],
          description: r.property_description,
          owner: name || r.owner_tg_username || r.owner_phone
            ? { name, tg: r.owner_tg_username, phone: r.owner_phone }
            : undefined,
        })
      } catch {
        if (!cancelled) setNetErr(true)
      } finally {
        if (!cancelled) setLoading(false)
      }
    }

    async function load() {
      try {
        const { data: rows, error } = await supabase
          .rpc('get_public_collection_preview', { p_token: colToken })
        if (cancelled) return
        const list = (rows ?? []) as PreviewRow[]
        // Помилка транспорту ≠ порожня відповідь: перша означає «не доїхало»,
        // друга — «такого нема». Однакова реакція на них і була дефектом.
        if (error) { setNetErr(true); return }
        if (list.length === 0) { setNotFound(true); return }
        setData({
          name: list[0].collection_name,
          subtitle: tr('{0} обʼєктів', list.filter((r) => !!r.property_id).length),
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
        if (!cancelled) setNetErr(true)
      } finally {
        if (!cancelled) setLoading(false)
      }
    }

    if (propToken) void loadProp()
    else void load()
    return () => { cancelled = true }
  }, [colToken, propToken, collectionId, reloadKey])

  const kindTitle = isProp ? tr('Оголошення') : tr('Підбірка')

  if (loading) {
    return (
      <div className="scr bg-violet" style={{ alignItems: 'center', justifyContent: 'center' }}>
        <div className="loader" />
      </div>
    )
  }

  if (netErr) {
    return (
      <div className="scr bg-violet">
        <Header title={kindTitle} backLabel={tr('Назад')} />
        <RetryState
          icon="📡"
          title={tr('Не вдалося завантажити')}
          subtitle={typeof navigator !== 'undefined' && !navigator.onLine
            ? tr('Немає зʼєднання з інтернетом. Перевірте мережу і спробуйте ще раз.')
            : tr('Перевірте зʼєднання та спробуйте ще раз.')}
          onRetry={() => setReloadKey((k) => k + 1)}
        />
      </div>
    )
  }

  if (notFound || !data) {
    return (
      <div className="scr bg-violet">
        <Header title={kindTitle} backLabel={tr('Назад')} />
        <div className="empty-state" style={{ paddingTop: 48 }}>
          <div className="empty-ic">🔗</div>
          <div className="empty-h">{isProp ? tr('Оголошення не знайдено') : tr('Підбірку не знайдено')}</div>
          <div className="empty-s">{isProp
            ? tr('Посилання недійсне або власник його відкликав')
            : tr('Посилання недійсне або підбірку ще не опубліковано')}</div>
        </div>
      </div>
    )
  }

  return (
    <div className="scr bg-violet">
      <Header title={data.name} subtitle={data.subtitle} backLabel={tr('Назад')} />

      <div className="body">
        {data.properties.length === 0 ? (
          <div className="empty-state" style={{ paddingTop: 32 }}>
            <div className="empty-ic">🏢</div>
            <div className="empty-h">{tr('Підбірка порожня')}</div>
            <div className="empty-s">{tr('Ріелтор ще не додав обʼєктів')}</div>
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
                    // ОДИН shorthand, а не `backgroundImage` + `background: undefined`:
                    // React виставляє `background = ''`, і це стирає щойно задані
                    // longhand-и — фото не малювалось ніколи (див. thumbBackground).
                    style={{ background: thumbBackground(thumbUrl), flexShrink: 0 }}
                  >
                    {!thumbUrl && <IconBuilding size={18} color="#A87CFF" />}
                  </div>

                  <div className="row-mn" style={{ flex: 1, minWidth: 0 }}>
                    <div className="row-t">{p.name}</div>
                    <div className="row-s" style={{ gap: 6, flexWrap: 'wrap', marginTop: 3 }}>
                      <StatusBadge status={p.status} />
                      {p.area_useful && (
                        <span>{p.area_useful}{p.area_total ? `/${p.area_total}` : ''} {tr('м²')}</span>
                      )}
                      {p.floor && <span style={{ display: 'inline-flex', alignItems: 'center', gap: 3 }}><IconBuilding size={12} color="var(--t3)" />{tr('{0} пов.', p.floor)}</span>}
                      {rent > 0 && p.status !== 'for_sale' && (
                        <span style={{ color: 'var(--t2)', fontWeight: 'var(--fw-semi)' }}>
                          {formatPrice(rent, data.currency)}{computedRentUnit(p.rent_type)}
                        </span>
                      )}
                      {p.status === 'for_sale' && (p.sale_price ?? 0) > 0 && (
                        <span style={{ color: 'var(--t2)', fontWeight: 'var(--fw-semi)' }}>
                          {formatPrice(p.sale_price!, data.currency)}
                        </span>
                      )}
                    </div>
                  </div>
                </div>
              )
            })}
          </div>
        )}

        {isProp && data.description && (
          <div className="glass-s shared-desc">{data.description}</div>
        )}

        {isProp && data.owner && (
          <div className="glass-s shared-owner">
            <div className="row-mn">
              <div className="row-s" style={{ marginTop: 0 }}><span>{tr('Власник')}</span></div>
              <div className="row-t">{data.owner.name || (data.owner.tg ? `@${data.owner.tg}` : tr('Власник'))}</div>
            </div>
            {data.owner.tg && (
              <button type="button" className="shared-owner-act" onClick={() => openTgUrl(`https://t.me/${data.owner!.tg}`)}>
                <IconTelegram size={16} />{tr('Написати')}
              </button>
            )}
            {!data.owner.tg && data.owner.phone && (
              <a className="shared-owner-act" href={`tel:${data.owner.phone}`}>{tr('Подзвонити')}</a>
            )}
          </div>
        )}
      </div>
    </div>
  )
}

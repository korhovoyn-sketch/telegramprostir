'use client'

import { useEffect, useState, useCallback, useRef } from 'react'
import { useAppStore } from '@/store/appStore'
import { supabase } from '@/lib/supabase'
import TabBar from '@/components/ui/TabBar'
import { StatusBadge } from '@/components/ui/Badge'
import Modal from '@/components/ui/Modal'
import { IconPlus, IconShare, IconX, IconChevronLeft, IconTrash, IconBuilding } from '@/components/Icons'
import { formatPrice, calcRent, formatDate, photoUrl } from '@/lib/utils'
import { sharePublicUrl } from '@/lib/telegram'
import type { Property, Collection } from '@/types'
import CoachMark from '@/components/ui/CoachMark'
import { useOnboarding } from '@/hooks/useOnboarding'

// ─── Extended types ────────────────────────────────────────────────────────────

interface CollectionWithCount extends Collection {
  property_count: number
  thumb_urls: string[]
}

interface CollectionProperty {
  property_id: string
  property: Property & { photos: { storage_path: string }[] }
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

function getRentLabel(p: Property, currency = 'USD'): string {
  if (!p.rent_rate) return '—'
  const rent = calcRent(p.area_useful ?? 0, p.rent_rate, p.rent_type)
  return formatPrice(rent, currency)
}

// ─── Collection List View ─────────────────────────────────────────────────────

function CollectionCard({
  col,
  onClick,
  onShare,
}: {
  col: CollectionWithCount
  onClick: () => void
  onShare: (e: React.MouseEvent) => void
}) {
  return (
    <div className="collection-c glass-s" onClick={onClick} style={{ cursor: 'pointer' }}>
      <div className="collection-h">
        <div style={{ flex: 1, minWidth: 0 }}>
          <div className="collection-n">{col.name}</div>
          <div className="collection-meta">
            {col.is_draft && <span className="bdg bdg-info">Чернетка</span>}
            <span>·</span>
            <span>{formatDate(col.updated_at)}</span>
            <span>·</span>
            <span>{col.property_count} об&apos;єктів</span>
          </div>
        </div>
        <button
          className="owner-act"
          aria-label="Поділитись підбіркою"
          onClick={onShare}
        >
          <IconShare size={14} />
        </button>
      </div>

      <div className="collection-thumbs">
        {col.thumb_urls.length > 0 ? (
          col.thumb_urls.map((url, i) => (
            <div
              key={i}
              className="collection-thumb"
              style={{
                backgroundImage: `url(${url})`,
                backgroundSize: 'cover',
                backgroundPosition: 'center',
              }}
            />
          ))
        ) : (
          <>
            <div className="collection-thumb" style={{ display: 'flex', alignItems: 'center', justifyContent: 'center' }}><IconBuilding size={18} color="#A87CFF" /></div>
            <div className="collection-thumb" style={{ display: 'flex', alignItems: 'center', justifyContent: 'center' }}><IconBuilding size={18} color="#A87CFF" /></div>
          </>
        )}
        {col.property_count > col.thumb_urls.length && col.thumb_urls.length > 0 && (
          <div className="collection-thumb more">+{col.property_count - col.thumb_urls.length}</div>
        )}
      </div>
    </div>
  )
}

// ─── Collection Detail View ───────────────────────────────────────────────────

function CollectionDetail({
  collection,
  onBack,
  onUpdate,
  onDelete,
}: {
  collection: CollectionWithCount
  onBack: () => void
  onUpdate: (updated: CollectionWithCount) => void
  onDelete: (id: string) => void
}) {
  const { user, showToast } = useAppStore()

  const [collectionProps, setCollectionProps] = useState<CollectionProperty[]>([])
  const [loadingProps, setLoadingProps] = useState(true)

  // Available properties to add
  const [availableProps, setAvailableProps] = useState<Property[]>([])
  const [loadingAvail, setLoadingAvail] = useState(false)
  const [showAddModal, setShowAddModal] = useState(false)
  const [showDeleteModal, setShowDeleteModal] = useState(false)

  const loadCollectionProperties = useCallback(async () => {
    setLoadingProps(true)
    try {
      const { data, error } = await supabase
        .from('collection_properties')
        .select('property_id, property:properties(*, photos:property_photos(*))')
        .eq('collection_id', collection.id)
      if (error) throw error
      setCollectionProps((data ?? []) as unknown as CollectionProperty[])
    } catch (e) {
      showToast({ type: 'error', title: 'Помилка завантаження', subtitle: (e as Error).message })
    } finally {
      setLoadingProps(false)
    }
  }, [collection.id, showToast])

  useEffect(() => {
    loadCollectionProperties()
  }, [loadCollectionProperties])

  async function loadAvailableProperties() {
    if (!user) return
    setLoadingAvail(true)
    try {
      // Get subscribed db ids
      const { data: subs, error: subsErr } = await supabase
        .from('realtor_subscriptions')
        .select('db_id')
        .eq('realtor_id', user.id)
      if (subsErr) throw subsErr

      const dbIds = (subs ?? []).map((s: { db_id: string }) => s.db_id)
      if (dbIds.length === 0) {
        setAvailableProps([])
        return
      }

      const { data: props, error: propsErr } = await supabase
        .from('properties')
        .select('*, photos:property_photos(*)')
        .in('db_id', dbIds)
        .order('created_at', { ascending: false })
      if (propsErr) throw propsErr

      // Filter out already-added properties
      const addedIds = new Set(collectionProps.map((cp) => cp.property_id))
      const available = ((props ?? []) as Property[]).filter((p) => !addedIds.has(p.id))
      setAvailableProps(available)
    } catch (e) {
      showToast({ type: 'error', title: 'Помилка завантаження', subtitle: (e as Error).message })
    } finally {
      setLoadingAvail(false)
    }
  }

  function openAddModal() {
    setShowAddModal(true)
    loadAvailableProperties()
  }

  async function addProperty(propertyId: string) {
    try {
      const { error } = await supabase
        .from('collection_properties')
        .insert({ collection_id: collection.id, property_id: propertyId })
      if (error) throw error

      // Reload
      await loadCollectionProperties()
      setAvailableProps((prev) => prev.filter((p) => p.id !== propertyId))

      // Update count in parent
      onUpdate({ ...collection, property_count: collection.property_count + 1 })
      showToast({ type: 'success', title: 'Об\'єкт додано' })
    } catch (e) {
      showToast({ type: 'error', title: 'Помилка', subtitle: (e as Error).message })
    }
  }

  async function removeProperty(propertyId: string) {
    try {
      const { error } = await supabase
        .from('collection_properties')
        .delete()
        .eq('collection_id', collection.id)
        .eq('property_id', propertyId)
      if (error) throw error

      setCollectionProps((prev) => prev.filter((cp) => cp.property_id !== propertyId))
      onUpdate({ ...collection, property_count: Math.max(0, collection.property_count - 1) })
      showToast({ type: 'success', title: 'Об\'єкт видалено' })
    } catch (e) {
      showToast({ type: 'error', title: 'Помилка', subtitle: (e as Error).message })
    }
  }

  async function shareCollection() {
    // Mark as active (not draft) when sharing
    if (collection.is_draft) {
      try {
        const { error } = await supabase
          .from('collections')
          .update({ is_draft: false, updated_at: new Date().toISOString() })
          .eq('id', collection.id)
        if (error) throw error
        onUpdate({ ...collection, is_draft: false })
      } catch (e) {
        showToast({ type: 'error', title: 'Помилка', subtitle: (e as Error).message })
        return
      }
    }

    sharePublicUrl('col', collection.share_token || collection.id, collection.name)
  }

  async function deleteCollection() {
    try {
      const { error } = await supabase
        .from('collections')
        .delete()
        .eq('id', collection.id)
      if (error) throw error
      window.Telegram?.WebApp?.HapticFeedback?.notificationOccurred('success')
      showToast({ type: 'success', title: 'Підбірку видалено' })
      onDelete(collection.id)
    } catch (e) {
      showToast({ type: 'error', title: 'Помилка', subtitle: (e as Error).message })
    } finally {
      setShowDeleteModal(false)
    }
  }

  const currency = user ? (user as unknown as { currency?: string }).currency ?? 'USD' : 'USD'

  return (
    <div className="scr bg-violet">
      {/* Header */}
      <div className="hdr">
        <button
          className="hdr-a"
          aria-label="Назад"
          onClick={onBack}
          style={{ background: 'none', border: 'var(--bd)' }}
        >
          <IconChevronLeft size={16} />
        </button>
        <div className="hdr-t" style={{ flex: 1, textAlign: 'center' }}>
          <div style={{ fontSize: 15, fontWeight: 700, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
            {collection.name}
          </div>
          {collection.is_draft && (
            <div style={{ fontSize: 12, color: 'var(--t3)' }}>Чернетка</div>
          )}
        </div>
        <div style={{ display: 'flex', gap: 8 }}>
          <button
            className="hdr-a"
            aria-label="Видалити підбірку"
            onClick={() => setShowDeleteModal(true)}
            style={{ background: 'none', border: 'var(--bd)', color: 'var(--err)' }}
          >
            <IconTrash size={16} />
          </button>
          <button
            className="hdr-a"
            aria-label="Поділитись підбіркою"
            onClick={shareCollection}
            style={{ background: 'none', border: 'var(--bd)' }}
          >
            <IconShare size={16} />
          </button>
        </div>
      </div>

      {/* Body */}
      <div className="body has-fab">
        {loadingProps ? (
          <div className="loader-wrap"><div className="loader" /></div>
        ) : collectionProps.length === 0 ? (
          <div className="empty-state" style={{ paddingTop: 32 }}>
            <div className="empty-ic">🏢</div>
            <div className="empty-h">Немає об&apos;єктів</div>
            <div className="empty-s">Додай перший об&apos;єкт до підбірки</div>
          </div>
        ) : (
          <div className="list">
            {collectionProps.map((cp) => {
              const p = cp.property
              if (!p) return null
              const firstPhoto = p.photos?.[0]
              const thumbUrl = firstPhoto ? photoUrl(firstPhoto.storage_path) : null

              return (
                <div key={cp.property_id} className="row glass-s" style={{ alignItems: 'flex-start', gap: 10 }}>
                  {/* Thumbnail */}
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

                  {/* Info */}
                  <div className="row-mn" style={{ flex: 1, minWidth: 0 }}>
                    <div className="row-t">{p.name}</div>
                    <div className="row-s" style={{ gap: 6, flexWrap: 'wrap' }}>
                      <StatusBadge status={p.status} />
                      {p.area_useful && (
                        <span>{p.area_useful} м²</span>
                      )}
                      {p.rent_rate && (
                        <span>{getRentLabel(p, currency)}</span>
                      )}
                    </div>
                  </div>

                  {/* Remove button */}
                  <button
                    className="owner-act"
                    aria-label="Видалити з підбірки"
                    onClick={() => removeProperty(cp.property_id)}
                    style={{ flexShrink: 0, marginTop: 2 }}
                  >
                    <IconX size={14} />
                  </button>
                </div>
              )
            })}
          </div>
        )}
      </div>

      {/* Add button */}
      <button className="fab" aria-label="Додати об'єкт" onClick={openAddModal}>
        <IconPlus size={20} />
      </button>

      {/* Add property modal */}
      {showAddModal && (
        <Modal
          title="Додати об'єкт"
          subtitle="Оберіть об'єкт із підписаних баз"
          onClose={() => setShowAddModal(false)}
          actions={[
            { label: 'Закрити', variant: 'secondary', onClick: () => setShowAddModal(false) },
          ]}
        >
          <div style={{ marginTop: 4 }}>
            {loadingAvail ? (
              <div className="loader-wrap" style={{ padding: '24px 0' }}>
                <div className="loader" />
              </div>
            ) : availableProps.length === 0 ? (
              <div style={{ textAlign: 'center', padding: '24px 0', color: 'var(--t3)', fontSize: 13 }}>
                Немає доступних об&apos;єктів
              </div>
            ) : (
              <div className="list" style={{ gap: 6 }}>
                {availableProps.map((p) => {
                  const firstPhoto = p.photos?.[0]
                  const thumbUrl = firstPhoto ? photoUrl(firstPhoto.storage_path) : null

                  return (
                    <div key={p.id} className="row glass-s" style={{ alignItems: 'center', gap: 8 }}>
                      <div
                        className="row-ic"
                        style={{
                          backgroundImage: thumbUrl ? `url(${thumbUrl})` : undefined,
                          backgroundSize: 'cover',
                          backgroundPosition: 'center',
                          background: thumbUrl ? undefined : 'rgba(123,48,235,.18)',
                          flexShrink: 0,
                          width: 36,
                          height: 36,
                        }}
                      >
                        {!thumbUrl && <IconBuilding size={16} color="#A87CFF" />}
                      </div>
                      <div className="row-mn" style={{ flex: 1, minWidth: 0 }}>
                        <div className="row-t" style={{ fontSize: 13 }}>{p.name}</div>
                        <div className="row-s" style={{ gap: 4 }}>
                          <StatusBadge status={p.status} />
                          {p.area_useful && <span>{p.area_useful} м²</span>}
                        </div>
                      </div>
                      <button
                        className="owner-act"
                        aria-label="Додати до підбірки"
                        onClick={() => addProperty(p.id)}
                        style={{ flexShrink: 0, background: 'rgba(123,48,235,.28)' }}
                      >
                        <IconPlus size={14} />
                      </button>
                    </div>
                  )
                })}
              </div>
            )}
          </div>
        </Modal>
      )}

      {showDeleteModal && (
        <Modal
          title="Видалити підбірку?"
          subtitle={`Підбірку "${collection.name}" буде видалено. Це незворотно.`}
          onClose={() => setShowDeleteModal(false)}
          actions={[
            { label: 'Видалити', variant: 'danger', onClick: deleteCollection },
            { label: 'Скасувати', variant: 'secondary', onClick: () => setShowDeleteModal(false) },
          ]}
        />
      )}
    </div>
  )
}

// ─── Main Screen ──────────────────────────────────────────────────────────────

export default function CollectionsScreen() {
  const { user, showToast, screenParams } = useAppStore()
  const [collections, setCollections] = useState<CollectionWithCount[]>([])
  const [loading, setLoading] = useState(true)
  const [selectedCollection, setSelectedCollection] = useState<CollectionWithCount | null>(null)
  const fabRef = useRef<HTMLButtonElement>(null)
  const { isDone: fabSeen, markDone: markFabSeen } = useOnboarding('col-fab')

  const loadCollections = useCallback(async () => {
    if (!user) return
    setLoading(true)
    try {
      // Single query for counts + one batch query for thumbnails — no N+1
      const { data: colsData, error } = await supabase
        .from('collections')
        .select('*, collection_properties(count)')
        .eq('realtor_id', user.id)
        .order('created_at', { ascending: false })
      if (error) throw error

      const cols = colsData ?? []
      if (cols.length === 0) { setCollections([]); return }

      // Batch-fetch up to 3 thumbnail paths per collection in one round-trip
      const colIds = cols.map(c => c.id)
      const { data: cpRows } = await supabase
        .from('collection_properties')
        .select('collection_id, property:properties(id, photos:property_photos(storage_path))')
        .in('collection_id', colIds)

      // Build map: collectionId → first 3 photo URLs
      const thumbMap: Record<string, string[]> = {}
      for (const row of (cpRows ?? []) as unknown as Array<{
        collection_id: string
        property: { id: string; photos: { storage_path: string }[] } | null
      }>) {
        const urls = (thumbMap[row.collection_id] ??= [])
        if (urls.length < 3 && row.property?.photos?.[0]?.storage_path) {
          urls.push(photoUrl(row.property.photos[0].storage_path))
        }
      }

      const enriched: CollectionWithCount[] = cols.map(col => {
        const countArr = (col as unknown as { collection_properties: { count: number }[] }).collection_properties
        const property_count = Array.isArray(countArr) && countArr.length > 0 ? countArr[0].count : 0
        return { ...col, property_count, thumb_urls: thumbMap[col.id] ?? [] } as CollectionWithCount
      })

      setCollections(enriched)
    } catch (e) {
      showToast({ type: 'error', title: 'Помилка завантаження', subtitle: (e as Error).message })
    } finally {
      setLoading(false)
    }
  }, [user, showToast])

  useEffect(() => {
    loadCollections()
  }, [loadCollections])

  // Auto-open a collection when navigated here via deep link
  useEffect(() => {
    const id = screenParams.collectionId as string | undefined
    if (!id || selectedCollection) return
    const match = collections.find(c => c.id === id)
    if (match) setSelectedCollection(match)
  }, [screenParams.collectionId, collections, selectedCollection])

  async function createCollection() {
    if (!user) return
    const name = `Підбірка ${collections.length + 1}`
    try {
      const { data, error } = await supabase
        .from('collections')
        .insert({ realtor_id: user.id, name, is_draft: true })
        .select()
        .single()
      if (error) throw error
      const newCol: CollectionWithCount = {
        ...(data as Collection),
        property_count: 0,
        thumb_urls: [],
      }
      setCollections([newCol, ...collections])
      showToast({ type: 'success', title: 'Підбірку створено' })
    } catch (e) {
      showToast({ type: 'error', title: 'Помилка', subtitle: (e as Error).message })
    }
  }

  function handleShare(e: React.MouseEvent, col: CollectionWithCount) {
    e.stopPropagation()
    if (col.property_count === 0) {
      useAppStore.getState().showToast({ type: 'error', title: 'Підбірка порожня', subtitle: 'Додайте об\'єкти перед тим як ділитися' })
      return
    }
    sharePublicUrl('col', col.share_token || col.id, col.name)
  }

  function handleCollectionUpdate(updated: CollectionWithCount) {
    setCollections((prev) =>
      prev.map((c) => (c.id === updated.id ? updated : c))
    )
    setSelectedCollection(updated)
  }

  function handleCollectionDelete(id: string) {
    setCollections((prev) => prev.filter((c) => c.id !== id))
    setSelectedCollection(null)
  }

  // ── Detail view ──
  if (selectedCollection) {
    return (
      <CollectionDetail
        collection={selectedCollection}
        onBack={() => setSelectedCollection(null)}
        onUpdate={handleCollectionUpdate}
        onDelete={handleCollectionDelete}
      />
    )
  }

  // ── List view ──
  return (
    <div className="scr bg-violet">
      <div className="hdr">
        <div className="hdr-sp" />
        <div className="hdr-t">Підбірки</div>
        <div className="hdr-sp" />
      </div>

      <div className="body has-fab">
        <div className="greet">Мої підбірки</div>
        <div className="display">Для клієнтів</div>

        {loading ? (
          <div className="loader-wrap"><div className="loader" /></div>
        ) : collections.length === 0 ? (
          <div className="empty-state" style={{ paddingTop: 32 }}>
            <div className="empty-ic">📋</div>
            <div className="empty-h">Немає підбірок</div>
            <div className="empty-s">Створи першу підбірку об&apos;єктів для клієнта</div>
          </div>
        ) : (
          <div className="list">
            {collections.map((col) => (
              <CollectionCard
                key={col.id}
                col={col}
                onClick={() => setSelectedCollection(col)}
                onShare={(e) => handleShare(e, col)}
              />
            ))}
          </div>
        )}
      </div>

      {/* FAB */}
      <button ref={fabRef} className="fab" aria-label="Створити підбірку" onClick={createCollection}>
        <IconPlus size={20} />
      </button>

      {!fabSeen && !loading && (
        <CoachMark
          title="Створіть підбірку"
          body="Натисніть +, щоб зібрати підбірку об'єктів для клієнта та поділитися посиланням."
          targetRef={fabRef}
          placement="above"
          onDone={markFabSeen}
        />
      )}

      <TabBar />
    </div>
  )
}

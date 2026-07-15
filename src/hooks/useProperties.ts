'use client'

import { useState, useCallback, useEffect, useRef } from 'react'
import { supabase } from '@/lib/supabase'
import { humanizeDbError, objectsWord } from '@/lib/utils'
import { readSnapshot, writeSnapshot } from '@/lib/snapshot'
import { compressImage } from '@/lib/image'
import { useAppStore } from '@/store/appStore'
import type { Property, PropertyStatus } from '@/types'

// Scalar column list + the photos relation, shared across every select so the
// four query sites can't drift apart (and none falls back to select('*')).
const PROPERTY_COLUMNS = `
  id, db_id, owner_id, name, floor, status,
  area_useful, area_total, rent_type, rent_rate, utilities_rate,
  has_parking, parking_spaces, description,
  address, utilities,
  sale_price, tenant_name, lease_start_date, lease_end_date,
  sort_order, created_at, updated_at
`
const PROPERTY_WITH_PHOTOS = `${PROPERTY_COLUMNS}, photos:property_photos(id, storage_path, sort_order)`

// loadProperties/loadSingleProperty additionally pull the view relation so the
// card can show a view count; create/update don't need it (a fresh row has none).
const PROPERTY_SELECT = `${PROPERTY_WITH_PHOTOS}, views:property_views(id)`

export function useProperties(dbId?: string) {
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [properties, setProperties] = useState<Property[]>([])
  const { user, showToast, navigate, backThenReplace } = useAppStore()

  // Mirror of `properties` for reading inside stable callbacks — screens
  // re-run their load effect off the callback identity, so loadProperties
  // must not depend on the list itself.
  const propertiesRef = useRef(properties)
  useEffect(() => { propertiesRef.current = properties }, [properties])

  const loadProperties = useCallback(async (id?: string) => {
    const targetDbId = id || dbId
    if (!targetDbId) return

    // Stale-while-revalidate: screens remount on every navigation, so without
    // this every visit opens on a skeleton. Paint the last known list
    // instantly and refresh silently in the background.
    let painted = propertiesRef.current.length > 0
    if (!painted && user) {
      const cached = readSnapshot<Property[]>(`props:${targetDbId}`, user.id)
      if (cached?.length) {
        setProperties(cached)
        painted = true
      }
    }
    if (!painted) setLoading(true)
    setError(null)
    try {
      const { data, error } = await supabase
        .from('properties')
        .select(PROPERTY_SELECT)
        .eq('db_id', targetDbId)
        .order('sort_order', { ascending: true })
        .order('created_at', { ascending: true })

      if (error) throw error
      const mapped = (data ?? []).map((p) => {
        const { views, ...rest } = p as Record<string, unknown>
        return { ...rest, _view_count: (views as unknown[])?.length ?? 0 }
      })
      setProperties(mapped as unknown as Property[])
      if (user) writeSnapshot(`props:${targetDbId}`, user.id, mapped)
    } catch (e) {
      const msg = humanizeDbError(e)
      setError(msg)
      showToast({ type: 'error', title: 'Помилка завантаження', subtitle: msg })
    } finally {
      setLoading(false)
    }
  }, [dbId, user, showToast])

  const loadSingleProperty = useCallback(async (propertyId: string) => {
    setLoading(true)
    setError(null)
    try {
      const { data, error } = await supabase
        .from('properties')
        .select(PROPERTY_SELECT)
        .eq('id', propertyId)
        .single()

      if (error) throw error
      const { views, ...rest } = data as Record<string, unknown>
      const mapped = { ...rest, _view_count: (views as unknown[])?.length ?? 0 } as unknown as Property
      setProperties([mapped])
    } catch (e) {
      const msg = humanizeDbError(e)
      setError(msg)
      showToast({ type: 'error', title: 'Помилка завантаження', subtitle: msg })
    } finally {
      setLoading(false)
    }
  }, [showToast])

  const createProperty = useCallback(async (
    payload: Omit<Property, 'id' | 'owner_id' | 'created_at' | 'updated_at' | 'photos'>
  ) => {
    if (!user) return
    setLoading(true)
    try {
      // Дані належать власнику БАЗИ: коли створює член команди, owner_id має
      // бути власників, інакше RLS-власницькі перевірки далі по системі
      // почнуть «губити» об'єкт (і WITH CHECK редакторської політики це
      // однаково вимагає).
      const dbOwner = useAppStore.getState().databases.find(d => d.id === payload.db_id)?.owner_id
      const { data, error } = await supabase
        .from('properties')
        .insert({ ...payload, owner_id: dbOwner ?? user.id })
        .select(PROPERTY_WITH_PHOTOS)
        .single()

      if (error) throw error
      setProperties((prev) => [data as Property, ...prev])
      showToast({ type: 'success', title: 'Об\'єкт додано' })
      backThenReplace('db-objects', { dbId: payload.db_id })
      return true
    } catch (e) {
      showToast({ type: 'error', title: 'Помилка', subtitle: humanizeDbError(e) })
      return false
    } finally {
      setLoading(false)
    }
  }, [user, showToast, backThenReplace])

  // Bulk create — one INSERT for the whole batch (e.g. 10 parking spots at
  // once), so it's a single round-trip and either all rows land or none.
  const createProperties = useCallback(async (
    payloads: Omit<Property, 'id' | 'owner_id' | 'created_at' | 'updated_at' | 'photos'>[]
  ): Promise<boolean> => {
    if (!user || payloads.length === 0) return false
    setLoading(true)
    try {
      const dbOwner = useAppStore.getState().databases.find(d => d.id === payloads[0].db_id)?.owner_id
      const { data, error } = await supabase
        .from('properties')
        .insert(payloads.map(p => ({ ...p, owner_id: dbOwner ?? user.id })))
        .select(PROPERTY_WITH_PHOTOS)

      if (error) throw error
      setProperties((prev) => [...((data ?? []) as Property[]), ...prev])
      showToast({ type: 'success', title: `Додано ${payloads.length} ${objectsWord(payloads.length)}` })
      backThenReplace('db-objects', { dbId: payloads[0].db_id })
      return true
    } catch (e) {
      showToast({ type: 'error', title: 'Помилка', subtitle: humanizeDbError(e) })
      return false
    } finally {
      setLoading(false)
    }
  }, [user, showToast, backThenReplace])

  const updateProperty = useCallback(async (
    id: string,
    payload: Partial<Property>,
    opts?: { optimistic?: boolean; silent?: boolean },
  ): Promise<boolean> => {
    // Optimistic path: apply locally right away, sync in the background,
    // roll back on failure. Used for one-tap status changes (free/rent) so
    // the UI never blocks on the network.
    if (opts?.optimistic) {
      const prevList = propertiesRef.current
      setProperties((prev) => prev.map((p) => (p.id === id ? ({ ...p, ...payload } as Property) : p)))
      try {
        const { data, error } = await supabase
          .from('properties')
          .update({ ...payload, updated_at: new Date().toISOString() })
          .eq('id', id)
          .select(PROPERTY_WITH_PHOTOS)
          .single()
        if (error) throw error
        setProperties((prev) => prev.map((p) => (
          p.id === id ? ({ ...(data as Property), _view_count: (p as Property & { _view_count?: number })._view_count } as Property) : p
        )))
        if (!opts.silent) showToast({ type: 'success', title: 'Збережено' })
        return true
      } catch (e) {
        setProperties(prevList)
        showToast({ type: 'error', title: 'Не збереглося — повернуто як було', subtitle: humanizeDbError(e) })
        return false
      }
    }

    setLoading(true)
    try {
      const { data, error } = await supabase
        .from('properties')
        .update({ ...payload, updated_at: new Date().toISOString() })
        .eq('id', id)
        .select(PROPERTY_WITH_PHOTOS)
        .single()

      if (error) throw error
      setProperties((prev) => prev.map((p) => (p.id === id ? (data as Property) : p)))
      if (!opts?.silent) showToast({ type: 'success', title: 'Збережено' })
      return true
    } catch (e) {
      showToast({ type: 'error', title: 'Помилка', subtitle: humanizeDbError(e) })
      return false
    } finally {
      setLoading(false)
    }
  }, [showToast])

  const cycleStatus = useCallback(async (id: string, current: PropertyStatus) => {
    const next: Record<PropertyStatus, PropertyStatus> = {
      free: 'occupied',
      occupied: 'for_sale',
      for_sale: 'free',
    }
    await updateProperty(id, { status: next[current] })
  }, [updateProperty])

  const deleteProperty = useCallback(async (id: string, dbId: string) => {
    setLoading(true)
    try {
      // Clean up storage files before deleting the record (cascade handles DB rows)
      const [{ data: photos }, { data: docs }] = await Promise.all([
        supabase.from('property_photos').select('storage_path').eq('property_id', id),
        supabase.from('property_files').select('storage_path').eq('property_id', id),
      ])

      if (photos && photos.length > 0) {
        await supabase.storage.from('photos').remove(photos.map((p) => p.storage_path))
      }
      if (docs && docs.length > 0) {
        await supabase.storage.from('property-files').remove(docs.map((d) => d.storage_path))
      }

      const { error } = await supabase.from('properties').delete().eq('id', id)
      if (error) throw error

      setProperties((prev) => prev.filter((p) => p.id !== id))
      showToast({ type: 'success', title: 'Об\'єкт видалено' })
      navigate('db-objects', { dbId })
    } catch (e) {
      showToast({ type: 'error', title: 'Помилка', subtitle: humanizeDbError(e) })
    } finally {
      setLoading(false)
    }
  }, [showToast, navigate])

  const batchDeleteProperties = useCallback(async (ids: string[]) => {
    if (ids.length === 0) return
    setLoading(true)
    try {
      // Collect all photo + document paths before deleting rows
      const [{ data: photos }, { data: docs }] = await Promise.all([
        supabase.from('property_photos').select('storage_path').in('property_id', ids),
        supabase.from('property_files').select('storage_path').in('property_id', ids),
      ])
      if (photos && photos.length > 0) {
        await supabase.storage.from('photos').remove(photos.map(p => p.storage_path))
      }
      if (docs && docs.length > 0) {
        await supabase.storage.from('property-files').remove(docs.map(d => d.storage_path))
      }
      const { error } = await supabase.from('properties').delete().in('id', ids)
      if (error) throw error
      setProperties(prev => prev.filter(p => !ids.includes(p.id)))
      showToast({ type: 'success', title: `Видалено ${ids.length} ${objectsWord(ids.length)}` })
    } catch (e) {
      showToast({ type: 'error', title: 'Помилка видалення', subtitle: humanizeDbError(e) })
    } finally {
      setLoading(false)
    }
  }, [showToast])

  const batchUpdateStatus = useCallback(async (ids: string[], status: PropertyStatus) => {
    if (ids.length === 0) return
    try {
      const { error } = await supabase
        .from('properties')
        .update({ status, updated_at: new Date().toISOString() })
        .in('id', ids)
      if (error) throw error
      setProperties(prev => prev.map(p => ids.includes(p.id) ? { ...p, status } : p))
      const label: Record<PropertyStatus, string> = { free: 'Вільно', occupied: 'Зайнято', for_sale: 'Продаж' }
      showToast({ type: 'success', title: `${ids.length} ${objectsWord(ids.length)} — ${label[status]}` })
    } catch (e) {
      showToast({ type: 'error', title: 'Помилка', subtitle: humanizeDbError(e) })
    }
  }, [showToast])

  const reorderProperty = useCallback(async (id: string, direction: 'up' | 'down') => {
    const idx = properties.findIndex(p => p.id === id)
    if (idx === -1) return
    const neighborIdx = direction === 'up' ? idx - 1 : idx + 1
    if (neighborIdx < 0 || neighborIdx >= properties.length) return

    try {
      // If any item lacks a real sort_order, initialise all before swapping
      let base = properties
      if (properties.some(p => !p.sort_order)) {
        base = properties.map((p, i) => ({ ...p, sort_order: (i + 1) * 100 }))
        await Promise.all(
          base.map(p => supabase.from('properties').update({ sort_order: p.sort_order }).eq('id', p.id))
        )
      }

      const a = base[idx]
      const b = base[neighborIdx]

      // Optimistic swap
      const next = base
        .map(p =>
          p.id === a.id ? { ...p, sort_order: b.sort_order } :
          p.id === b.id ? { ...p, sort_order: a.sort_order } : p
        )
        .sort((x, y) => (x.sort_order ?? 0) - (y.sort_order ?? 0) || x.created_at.localeCompare(y.created_at))
      setProperties(next)

      await Promise.all([
        supabase.from('properties').update({ sort_order: b.sort_order }).eq('id', a.id),
        supabase.from('properties').update({ sort_order: a.sort_order }).eq('id', b.id),
      ])
    } catch {
      setProperties(properties) // rollback
      showToast({ type: 'error', title: 'Не вдалося зберегти порядок' })
    }
  }, [properties, showToast])

  const deletePhoto = useCallback(async (photoId: string, storagePath: string) => {
    try {
      // Remove from storage first, then the DB record
      await supabase.storage.from('photos').remove([storagePath])
      const { error } = await supabase.from('property_photos').delete().eq('id', photoId)
      if (error) throw error

      // Update local state — remove photo from the relevant property
      setProperties((prev) => prev.map((p) => ({
        ...p,
        photos: p.photos?.filter((ph) => ph.id !== photoId),
      })))
    } catch (e) {
      showToast({ type: 'error', title: 'Помилка видалення фото', subtitle: humanizeDbError(e) })
      throw e
    }
  }, [showToast])

  const uploadPhoto = useCallback(async (propertyId: string, rawFile: File) => {
    const MAX_MB = 10
    const ALLOWED = /\.(jpe?g|png|webp|heic|heif)$/i
    if (!ALLOWED.test(rawFile.name) || !rawFile.type.startsWith('image/')) {
      throw new Error('Дозволені лише зображення (JPG, PNG, WEBP, HEIC)')
    }
    // Resize/re-encode BEFORE the size check: a 12 MB camera shot becomes a
    // few hundred KB and passes; on any failure the original comes back.
    const file = await compressImage(rawFile)
    if (file.size > MAX_MB * 1024 * 1024) {
      throw new Error(`Файл занадто великий (макс. ${MAX_MB}МБ)`)
    }

    const rawExt = file.name.split('.').pop() ?? ''
    const ext = /^[a-z0-9]{2,5}$/i.test(rawExt) ? rawExt.toLowerCase() : 'jpg'
    const path = `${propertyId}/${Date.now()}_${Math.random().toString(36).slice(2)}.${ext}`
    const { error: upErr } = await supabase.storage.from('photos').upload(path, file)
    if (upErr) throw upErr

    const { error: dbErr } = await supabase.from('property_photos').insert({
      property_id: propertyId,
      storage_path: path,
    })
    if (dbErr) {
      // Clean up the orphaned storage file so it doesn't accumulate
      await supabase.storage.from('photos').remove([path]).catch(() => {})
      throw dbErr
    }

    return path
  }, [])

  return {
    loading,
    error,
    properties,
    loadProperties,
    loadSingleProperty,
    createProperty,
    createProperties,
    updateProperty,
    cycleStatus,
    reorderProperty,
    batchDeleteProperties,
    batchUpdateStatus,
    deleteProperty,
    deletePhoto,
    uploadPhoto,
  }
}

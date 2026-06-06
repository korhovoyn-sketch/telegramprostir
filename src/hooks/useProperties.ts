'use client'

import { useState, useCallback } from 'react'
import { supabase } from '@/lib/supabase'
import { useAppStore } from '@/store/appStore'
import type { Property, PropertyStatus } from '@/types'

export function useProperties(dbId?: string) {
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [properties, setProperties] = useState<Property[]>([])
  const { user, showToast, navigate } = useAppStore()

  const loadProperties = useCallback(async (id?: string) => {
    const targetDbId = id || dbId
    if (!targetDbId) return
    setLoading(true)
    setError(null)
    try {
      const { data, error } = await supabase
        .from('properties')
        .select(`
          id, db_id, owner_id, name, floor, status,
          area_useful, area_total, rent_type, rent_rate, utilities_rate,
          has_parking, parking_spaces, description,
          address, utilities,
          sale_price, tenant_name, lease_start_date, lease_end_date,
          sort_order, created_at, updated_at,
          photos:property_photos(id, storage_path, sort_order),
          views:property_views(id)
        `)
        .eq('db_id', targetDbId)
        .order('sort_order', { ascending: true })
        .order('created_at', { ascending: true })

      if (error) throw error
      const mapped = (data ?? []).map((p) => {
        const { views, ...rest } = p as Record<string, unknown>
        return { ...rest, _view_count: (views as unknown[])?.length ?? 0 }
      })
      setProperties(mapped as unknown as Property[])
    } catch (e) {
      const msg = (e as Error).message
      setError(msg)
      showToast({ type: 'error', title: 'Помилка завантаження', subtitle: msg })
    } finally {
      setLoading(false)
    }
  }, [dbId, showToast])

  const loadSingleProperty = useCallback(async (propertyId: string) => {
    setLoading(true)
    setError(null)
    try {
      const { data, error } = await supabase
        .from('properties')
        .select(`
          id, db_id, owner_id, name, floor, status,
          area_useful, area_total, rent_type, rent_rate, utilities_rate,
          has_parking, parking_spaces, description,
          address, utilities,
          sale_price, tenant_name, lease_start_date, lease_end_date,
          sort_order, created_at, updated_at,
          photos:property_photos(id, storage_path, sort_order),
          views:property_views(id)
        `)
        .eq('id', propertyId)
        .single()

      if (error) throw error
      const { views, ...rest } = data as Record<string, unknown>
      const mapped = { ...rest, _view_count: (views as unknown[])?.length ?? 0 } as unknown as Property
      setProperties([mapped])
    } catch (e) {
      const msg = (e as Error).message
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
      const { data, error } = await supabase
        .from('properties')
        .insert({ ...payload, owner_id: user.id })
        .select(`*, photos:property_photos(*)`)
        .single()

      if (error) throw error
      setProperties((prev) => [data as Property, ...prev])
      showToast({ type: 'success', title: 'Об\'єкт додано' })
      navigate('db-objects', { dbId: payload.db_id })
    } catch (e) {
      showToast({ type: 'error', title: 'Помилка', subtitle: (e as Error).message })
    } finally {
      setLoading(false)
    }
  }, [user, showToast, navigate])

  const updateProperty = useCallback(async (id: string, payload: Partial<Property>) => {
    setLoading(true)
    try {
      const { data, error } = await supabase
        .from('properties')
        .update({ ...payload, updated_at: new Date().toISOString() })
        .eq('id', id)
        .select(`*, photos:property_photos(*)`)
        .single()

      if (error) throw error
      setProperties((prev) => prev.map((p) => (p.id === id ? (data as Property) : p)))
      showToast({ type: 'success', title: 'Збережено' })
    } catch (e) {
      showToast({ type: 'error', title: 'Помилка', subtitle: (e as Error).message })
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
      const { data: photos } = await supabase
        .from('property_photos')
        .select('storage_path')
        .eq('property_id', id)

      if (photos && photos.length > 0) {
        await supabase.storage.from('photos').remove(photos.map((p) => p.storage_path))
      }

      const { error } = await supabase.from('properties').delete().eq('id', id)
      if (error) throw error

      setProperties((prev) => prev.filter((p) => p.id !== id))
      showToast({ type: 'success', title: 'Об\'єкт видалено' })
      navigate('db-objects', { dbId })
    } catch (e) {
      showToast({ type: 'error', title: 'Помилка', subtitle: (e as Error).message })
    } finally {
      setLoading(false)
    }
  }, [showToast, navigate])

  const batchDeleteProperties = useCallback(async (ids: string[]) => {
    if (ids.length === 0) return
    setLoading(true)
    try {
      // Collect all photo paths before deleting rows
      const { data: photos } = await supabase
        .from('property_photos')
        .select('storage_path')
        .in('property_id', ids)
      if (photos && photos.length > 0) {
        await supabase.storage.from('photos').remove(photos.map(p => p.storage_path))
      }
      const { error } = await supabase.from('properties').delete().in('id', ids)
      if (error) throw error
      setProperties(prev => prev.filter(p => !ids.includes(p.id)))
      showToast({ type: 'success', title: `Видалено ${ids.length} об'єктів` })
    } catch (e) {
      showToast({ type: 'error', title: 'Помилка видалення', subtitle: (e as Error).message })
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
      showToast({ type: 'success', title: `${ids.length} об'єктів — ${label[status]}` })
    } catch (e) {
      showToast({ type: 'error', title: 'Помилка', subtitle: (e as Error).message })
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
      showToast({ type: 'error', title: 'Помилка видалення фото', subtitle: (e as Error).message })
      throw e
    }
  }, [showToast])

  const uploadPhoto = useCallback(async (propertyId: string, file: File) => {
    const MAX_MB = 10
    const ALLOWED = /\.(jpe?g|png|webp|heic|heif)$/i
    if (!ALLOWED.test(file.name) || !file.type.startsWith('image/')) {
      throw new Error('Дозволені лише зображення (JPG, PNG, WEBP, HEIC)')
    }
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

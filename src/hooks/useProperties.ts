'use client'

import { useState, useCallback } from 'react'
import { supabase } from '@/lib/supabase'
import { useAppStore } from '@/store/appStore'
import type { Property, PropertyStatus } from '@/types'

export function useProperties(dbId?: string) {
  const [loading, setLoading] = useState(false)
  const [properties, setProperties] = useState<Property[]>([])
  const { user, showToast, navigate } = useAppStore()

  const loadProperties = useCallback(async (id?: string) => {
    const targetDbId = id || dbId
    if (!targetDbId) return
    setLoading(true)
    try {
      const { data, error } = await supabase
        .from('properties')
        .select(`*, photos:property_photos(*), views:property_views(id)`)
        .eq('db_id', targetDbId)
        .order('created_at', { ascending: false })

      if (error) throw error
      const mapped = (data ?? []).map((p) => {
        const row = p as Record<string, unknown>
        return { ...row, views: undefined, _view_count: (row.views as unknown[])?.length ?? 0 }
      })
      setProperties(mapped as unknown as Property[])
    } catch (e) {
      showToast({ type: 'error', title: 'Помилка завантаження', subtitle: (e as Error).message })
    } finally {
      setLoading(false)
    }
  }, [dbId, showToast])

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

  const uploadPhoto = useCallback(async (propertyId: string, file: File) => {
    const path = `${propertyId}/${Date.now()}_${file.name}`
    const { error: upErr } = await supabase.storage.from('photos').upload(path, file)
    if (upErr) throw upErr

    const { error: dbErr } = await supabase.from('property_photos').insert({
      property_id: propertyId,
      storage_path: path,
    })
    if (dbErr) throw dbErr
  }, [])

  return {
    loading,
    properties,
    loadProperties,
    createProperty,
    updateProperty,
    cycleStatus,
    deleteProperty,
    uploadPhoto,
  }
}

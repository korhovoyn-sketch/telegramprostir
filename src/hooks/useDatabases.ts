'use client'

import { useState, useCallback } from 'react'
import { supabase } from '@/lib/supabase'
import { useAppStore } from '@/store/appStore'
import { calcRent } from '@/lib/utils'
import type { Database } from '@/types'

export function useDatabases() {
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const { user, setDatabases, databases, showToast, navigate, backThenReplace } = useAppStore()

  const loadDatabases = useCallback(async () => {
    if (!user) return
    setLoading(true)
    setError(null)
    try {
      const { data, error } = await supabase
        .from('databases')
        .select('*, properties(status, rent_rate, area_useful, rent_type)')
        .eq('owner_id', user.id)
        .order('created_at', { ascending: false })

      if (error) throw error

      const dbs = (data || []).map((d) => {
        const row = d as Record<string, unknown>
        type PropRow = { status: string; rent_rate?: number; area_useful?: number; rent_type?: string }
        const props = (row.properties as PropRow[]) ?? []
        const monthlyIncome = props
          .filter(p => p.status === 'occupied' && p.rent_rate)
          .reduce((sum, p) => {
            if (!p.rent_rate) return sum
            return sum + calcRent(p.area_useful ?? 0, p.rent_rate, p.rent_type ?? 'per_m2')
          }, 0)
        return {
          ...row,
          properties: undefined,
          _property_count:  props.length,
          _free_count:      props.filter(p => p.status === 'free').length,
          _occupied_count:  props.filter(p => p.status === 'occupied').length,
          _monthly_income:  monthlyIncome,
        }
      })

      setDatabases(dbs as unknown as Database[])
    } catch (e) {
      const msg = (e as Error).message
      setError(msg)
      showToast({ type: 'error', title: 'Помилка завантаження', subtitle: msg })
    } finally {
      setLoading(false)
    }
  }, [user, setDatabases, showToast])

  const createDatabase = useCallback(async (payload: Omit<Database, 'id' | 'owner_id' | 'share_token' | 'created_at' | 'updated_at'>) => {
    if (!user) return
    setLoading(true)
    try {
      const { data, error } = await supabase
        .from('databases')
        .insert({ ...payload, owner_id: user.id })
        .select()
        .single()

      if (error) throw error

      setDatabases([data as Database, ...databases])
      showToast({ type: 'success', title: 'Базу створено' })
      backThenReplace('db-objects', { dbId: data.id })
    } catch (e) {
      showToast({ type: 'error', title: 'Помилка', subtitle: (e as Error).message })
    } finally {
      setLoading(false)
    }
  }, [user, databases, setDatabases, showToast, backThenReplace])

  const updateDatabase = useCallback(async (id: string, payload: Partial<Database>) => {
    setLoading(true)
    try {
      const { data, error } = await supabase
        .from('databases')
        .update({ ...payload, updated_at: new Date().toISOString() })
        .eq('id', id)
        .select()
        .single()

      if (error) throw error

      setDatabases(databases.map((d) => (d.id === id ? { ...d, ...data } : d)))
      showToast({ type: 'success', title: 'Базу оновлено' })
    } catch (e) {
      showToast({ type: 'error', title: 'Помилка', subtitle: (e as Error).message })
    } finally {
      setLoading(false)
    }
  }, [databases, setDatabases, showToast])

  const deleteDatabase = useCallback(async (id: string) => {
    setLoading(true)
    try {
      // Clean up all storage files for this database before deleting records
      const { data: props } = await supabase
        .from('properties')
        .select('id')
        .eq('db_id', id)

      if (props && props.length > 0) {
        const propIds = props.map((p) => p.id)
        const { data: photos } = await supabase
          .from('property_photos')
          .select('storage_path')
          .in('property_id', propIds)

        if (photos && photos.length > 0) {
          await supabase.storage.from('photos').remove(photos.map((p) => p.storage_path))
        }
      }

      const { error } = await supabase.from('databases').delete().eq('id', id)
      if (error) throw error

      setDatabases(databases.filter((d) => d.id !== id))
      showToast({ type: 'success', title: 'Базу видалено' })
      navigate('db-list')
    } catch (e) {
      showToast({ type: 'error', title: 'Помилка', subtitle: (e as Error).message })
    } finally {
      setLoading(false)
    }
  }, [databases, setDatabases, showToast, navigate])

  return { loading, error, databases, loadDatabases, createDatabase, updateDatabase, deleteDatabase }
}

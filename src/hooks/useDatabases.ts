'use client'

import { useState, useCallback } from 'react'
import { supabase } from '@/lib/supabase'
import { useAppStore } from '@/store/appStore'
import type { Database } from '@/types'

export function useDatabases() {
  const [loading, setLoading] = useState(false)
  const { user, setDatabases, databases, showToast, navigate } = useAppStore()

  const loadDatabases = useCallback(async () => {
    if (!user) return
    setLoading(true)
    try {
      const { data, error } = await supabase
        .from('databases')
        .select('*, properties(id, status)')
        .eq('owner_id', user.id)
        .order('created_at', { ascending: false })

      if (error) throw error

      const dbs = (data || []).map((d) => {
        const row = d as Record<string, unknown>
        const props = (row.properties as Array<{ id: string; status: string }>) ?? []
        return {
          ...row,
          properties: undefined,
          _property_count: props.length,
          _free_count: props.filter((p) => p.status === 'free').length,
        }
      })

      setDatabases(dbs as unknown as Database[])
    } catch (e) {
      showToast({ type: 'error', title: 'Помилка завантаження', subtitle: (e as Error).message })
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
      navigate('db-objects', { dbId: data.id })
    } catch (e) {
      showToast({ type: 'error', title: 'Помилка', subtitle: (e as Error).message })
    } finally {
      setLoading(false)
    }
  }, [user, databases, setDatabases, showToast, navigate])

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

  return { loading, databases, loadDatabases, createDatabase, updateDatabase, deleteDatabase }
}

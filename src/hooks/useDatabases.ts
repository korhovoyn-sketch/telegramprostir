'use client'

import { useState, useCallback } from 'react'
import { supabase } from '@/lib/supabase'
import { useAppStore } from '@/store/appStore'
import { monthlyRent, humanizeDbError } from '@/lib/utils'
import { readSnapshot, writeSnapshot } from '@/lib/snapshot'
import type { Database } from '@/types'

// Single source of truth for the databases column list — keeps loadDatabases,
// createDatabase and updateDatabase from drifting apart.
const DB_COLUMNS = 'id,owner_id,name,address,type,color,share_token,share_expires_at,created_at,updated_at'

export function useDatabases() {
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const { user, setDatabases, databases, showToast, navigate, backThenReplace } = useAppStore()
  const setMemberDbIds = useAppStore(st => st.setMemberDbIds)

  const loadDatabases = useCallback(async () => {
    if (!user) return

    // Stale-while-revalidate: on a cold start paint the last known list
    // immediately and refresh silently — the skeleton shows only when there
    // is truly nothing to draw. State is read via getState() so the callback
    // identity stays stable (screens re-run their effect off it).
    let painted = useAppStore.getState().databases.length > 0
    if (!painted) {
      const cached = readSnapshot<Database[]>('databases', user.id)
      if (cached?.length) {
        setDatabases(cached)
        painted = true
      }
    }
    if (!painted) setLoading(true)
    setError(null)
    try {
      // Власні бази + бази, де користувач — член команди (editor).
      // Двома запитами: PostgREST не вміє OR із підзапитом, а окремий запит
      // по membership-ах дає ще й ids для canEdit-шлюзів у сторі.
      const [{ data, error }, memberRes] = await Promise.all([
        supabase
          .from('databases')
          .select(`${DB_COLUMNS}, properties(status, rent_rate, area_useful, rent_type)`)
          .eq('owner_id', user.id)
          .order('created_at', { ascending: false }),
        supabase
          .from('db_members')
          .select('db_id')
          .eq('user_id', user.id)
          .eq('status', 'active'),
      ])

      if (error) throw error

      // На бекенді без міграції 041 запит по db_members падає — команда тоді
      // просто вимкнена, власні бази працюють як раніше.
      const memberIds = (memberRes.error ? [] : (memberRes.data ?? []))
        .map((r: { db_id: string }) => r.db_id)
        .filter((id: string) => !(data ?? []).some((d) => (d as { id: string }).id === id))
      setMemberDbIds(memberIds)

      let memberRows: typeof data = []
      if (memberIds.length > 0) {
        const { data: mData } = await supabase
          .from('databases')
          .select(`${DB_COLUMNS}, properties(status, rent_rate, area_useful, rent_type)`)
          .in('id', memberIds)
          .order('created_at', { ascending: false })
        memberRows = mData ?? []
      }

      const dbs = [
        ...(data || []),
        ...(memberRows || []).map((d) => ({ ...(d as Record<string, unknown>), _member: true })),
      ].map((d) => {
        const row = d as Record<string, unknown>
        type PropRow = { status: string; rent_rate?: number; area_useful?: number; rent_type?: string }
        const props = (row.properties as PropRow[]) ?? []
        const monthlyIncome = props
          .filter(p => p.status === 'occupied' && p.rent_rate)
          .reduce((sum, p) => {
            if (!p.rent_rate) return sum
            return sum + monthlyRent(p.area_useful ?? 0, p.rent_rate, p.rent_type ?? 'per_m2')
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
      writeSnapshot('databases', user.id, dbs)
    } catch (e) {
      const msg = humanizeDbError(e)
      setError(msg)
      showToast({ type: 'error', title: 'Помилка завантаження', subtitle: msg })
    } finally {
      setLoading(false)
    }
  }, [user, setDatabases, setMemberDbIds, showToast])

  const createDatabase = useCallback(async (payload: Omit<Database, 'id' | 'owner_id' | 'share_token' | 'created_at' | 'updated_at'>) => {
    if (!user) return
    setLoading(true)
    try {
      const { data, error } = await supabase
        .from('databases')
        .insert({ ...payload, owner_id: user.id })
        .select(DB_COLUMNS)
        .single()

      if (error) throw error

      setDatabases([data as Database, ...databases])
      showToast({ type: 'success', title: 'Базу створено' })
      backThenReplace('db-objects', { dbId: data.id })
    } catch (e) {
      showToast({ type: 'error', title: 'Помилка', subtitle: humanizeDbError(e) })
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
        .select(DB_COLUMNS)
        .single()

      if (error) throw error

      setDatabases(databases.map((d) => (d.id === id ? { ...d, ...data } : d)))
      showToast({ type: 'success', title: 'Базу оновлено' })
    } catch (e) {
      showToast({ type: 'error', title: 'Помилка', subtitle: humanizeDbError(e) })
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
        const [{ data: photos }, { data: docs }] = await Promise.all([
          supabase.from('property_photos').select('storage_path').in('property_id', propIds),
          supabase.from('property_files').select('storage_path').in('property_id', propIds),
        ])

        if (photos && photos.length > 0) {
          await supabase.storage.from('photos').remove(photos.map((p) => p.storage_path))
        }
        if (docs && docs.length > 0) {
          await supabase.storage.from('property-files').remove(docs.map((d) => d.storage_path))
        }
      }

      const { error } = await supabase.from('databases').delete().eq('id', id)
      if (error) throw error

      setDatabases(databases.filter((d) => d.id !== id))
      showToast({ type: 'success', title: 'Базу видалено' })
      navigate('db-list')
    } catch (e) {
      showToast({ type: 'error', title: 'Помилка', subtitle: humanizeDbError(e) })
    } finally {
      setLoading(false)
    }
  }, [databases, setDatabases, showToast, navigate])

  return { loading, error, databases, loadDatabases, createDatabase, updateDatabase, deleteDatabase }
}

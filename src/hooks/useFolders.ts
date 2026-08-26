'use client'

import { useState, useCallback, useRef, useEffect } from 'react'
import { supabase } from '@/lib/supabase'
import { humanizeDbError } from '@/lib/utils'
import { assertAffected } from '@/lib/dbWrite'
import { useAppStore } from '@/store/appStore'
import type { PropertyFolder } from '@/types'

const FOLDER_COLUMNS = 'id, db_id, owner_id, name, sort_order, created_at, updated_at'

// Missing table (043 not applied) — the whole feature degrades silently: the
// list renders flat, folder actions are hidden. Detect both the PostgREST
// "relation does not exist" code and a message referencing the table.
const isMissingFolderTable = (e: unknown): boolean => {
  const err = e as { code?: string; message?: string } | null
  return err?.code === '42P01' || /property_folders/i.test(err?.message ?? '')
}

export function useFolders(dbId?: string) {
  const [folders, setFolders] = useState<PropertyFolder[]>([])
  const [loading, setLoading] = useState(false)
  // true once we know the backing table is absent → screens hide folder UI.
  const [unavailable, setUnavailable] = useState(false)
  const { user, showToast } = useAppStore()

  const foldersRef = useRef(folders)
  useEffect(() => { foldersRef.current = folders }, [folders])

  const loadFolders = useCallback(async (id?: string) => {
    const targetDbId = id || dbId
    if (!targetDbId) return
    setLoading(true)
    try {
      const { data, error } = await supabase
        .from('property_folders')
        .select(FOLDER_COLUMNS)
        .eq('db_id', targetDbId)
        .order('sort_order', { ascending: true })
        .order('created_at', { ascending: true })

      if (error) {
        if (isMissingFolderTable(error)) { setUnavailable(true); setFolders([]); return }
        throw error
      }
      setFolders((data ?? []) as PropertyFolder[])
    } catch (e) {
      showToast({ type: 'error', title: 'Помилка завантаження папок', subtitle: humanizeDbError(e) })
    } finally {
      setLoading(false)
    }
  }, [dbId, showToast])

  const createFolder = useCallback(async (name: string): Promise<PropertyFolder | null> => {
    const targetDbId = dbId
    if (!targetDbId || !user) return null
    const trimmed = name.trim()
    if (!trimmed) return null
    // Дублікати імен збивають з пантелику (дві однакові папки в списку) — не даємо.
    if (foldersRef.current.some(f => f.name.trim().toLowerCase() === trimmed.toLowerCase())) {
      showToast({ type: 'error', title: 'Така папка вже є', subtitle: `«${trimmed}» вже існує в цій базі` })
      return null
    }
    try {
      // Дані належать власнику БАЗИ (як і обʼєкти): editor-політика це форсить
      // через WITH CHECK, тож owner_id має бути власників, не творця.
      const dbOwner = useAppStore.getState().databases.find(d => d.id === targetDbId)?.owner_id
      const maxOrder = foldersRef.current.reduce((m, f) => Math.max(m, f.sort_order), 0)
      const { data, error } = await supabase
        .from('property_folders')
        .insert({ db_id: targetDbId, owner_id: dbOwner ?? user.id, name: trimmed, sort_order: maxOrder + 100 })
        .select(FOLDER_COLUMNS)
        .single()

      if (error) throw error
      setFolders(prev => [...prev, data as PropertyFolder])
      showToast({ type: 'success', title: 'Папку створено' })
      return data as PropertyFolder
    } catch (e) {
      showToast({ type: 'error', title: 'Помилка', subtitle: humanizeDbError(e) })
      return null
    }
  }, [dbId, user, showToast])

  const renameFolder = useCallback(async (id: string, name: string) => {
    const trimmed = name.trim()
    if (!trimmed) return
    const prev = foldersRef.current
    const current = prev.find(f => f.id === id)
    if (current && current.name === trimmed) return // без змін — не смикаємо мережу
    if (prev.some(f => f.id !== id && f.name.trim().toLowerCase() === trimmed.toLowerCase())) {
      showToast({ type: 'error', title: 'Така папка вже є', subtitle: `«${trimmed}» вже існує в цій базі` })
      return
    }
    setFolders(list => list.map(f => f.id === id ? { ...f, name: trimmed } : f))
    try {
      const { data, error } = await supabase
        .from('property_folders')
        .update({ name: trimmed, updated_at: new Date().toISOString() })
        .eq('id', id)
        .select('id')
      if (error) throw error
      assertAffected(data, 1, 'перейменування папки')
    } catch (e) {
      setFolders(prev)
      showToast({ type: 'error', title: 'Помилка', subtitle: humanizeDbError(e) })
    }
  }, [showToast])

  // Deleting a folder ungroups its objects (properties.folder_id → NULL via
  // ON DELETE SET NULL); the caller reloads properties to reflect that.
  const deleteFolder = useCallback(async (id: string): Promise<boolean> => {
    const prev = foldersRef.current
    setFolders(list => list.filter(f => f.id !== id))
    try {
      const { data, error } = await supabase
        .from('property_folders')
        .delete()
        .eq('id', id)
        .select('id')
      if (error) throw error
      assertAffected(data, 1, 'видалення папки')
      showToast({ type: 'success', title: 'Папку видалено' })
      return true
    } catch (e) {
      setFolders(prev)
      showToast({ type: 'error', title: 'Помилка', subtitle: humanizeDbError(e) })
      return false
    }
  }, [showToast])

  const reorderFolder = useCallback(async (id: string, direction: 'up' | 'down') => {
    const list = foldersRef.current
    const idx = list.findIndex(f => f.id === id)
    if (idx === -1) return
    const neighborIdx = direction === 'up' ? idx - 1 : idx + 1
    if (neighborIdx < 0 || neighborIdx >= list.length) return

    const a = list[idx]
    const b = list[neighborIdx]
    const next = list
      .map(f =>
        f.id === a.id ? { ...f, sort_order: b.sort_order } :
        f.id === b.id ? { ...f, sort_order: a.sort_order } : f
      )
      .sort((x, y) => x.sort_order - y.sort_order || x.created_at.localeCompare(y.created_at))
    setFolders(next)
    try {
      await Promise.all([
        supabase.from('property_folders').update({ sort_order: b.sort_order }).eq('id', a.id),
        supabase.from('property_folders').update({ sort_order: a.sort_order }).eq('id', b.id),
      ])
    } catch {
      setFolders(list)
      showToast({ type: 'error', title: 'Не вдалося зберегти порядок' })
    }
  }, [showToast])

  return { folders, loading, unavailable, loadFolders, createFolder, renameFolder, deleteFolder, reorderFolder }
}

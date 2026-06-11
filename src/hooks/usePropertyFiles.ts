'use client'

import { useState, useCallback } from 'react'
import { supabase } from '@/lib/supabase'
import type { PropertyFile } from '@/types'

const MAX_FILES = 10
const MAX_SIZE  = 20 * 1024 * 1024
const BUCKET    = 'property-files'
const ALLOWED_MIME = new Set([
  'application/pdf',
  'application/msword',
  'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
])

export function usePropertyFiles(propertyId: string | undefined) {
  const [files, setFiles]       = useState<PropertyFile[]>([])
  const [loading, setLoading]   = useState(false)
  const [uploading, setUploading] = useState(false)
  const [uploadProgress, setUploadProgress] = useState<{ done: number; total: number } | null>(null)
  const [currentUploadFile, setCurrentUploadFile] = useState<string | null>(null)

  const fetchFiles = useCallback(async () => {
    if (!propertyId) return
    setLoading(true)
    try {
      const { data, error } = await supabase
        .from('property_files')
        .select('*')
        .eq('property_id', propertyId)
        .order('sort_order', { ascending: true })
        .order('created_at',  { ascending: true })
      if (!error && data) setFiles(data as PropertyFile[])
    } finally {
      setLoading(false)
    }
  }, [propertyId])

  const uploadFiles = useCallback(async (
    picked: File[],
    onError: (msg: string) => void
  ) => {
    if (!propertyId) return

    // Guard: re-read fresh count to avoid race when uploading multiple
    let currentCount = files.length

    // Filter out invalid files before showing progress so total is accurate
    const valid = picked.filter(file => {
      if (currentCount >= MAX_FILES) return false
      if (!ALLOWED_MIME.has(file.type)) { onError(`«${file.name}» — формат не підтримується (тільки PDF, DOC, DOCX)`); return false }
      if (file.size > MAX_SIZE)         { onError(`«${file.name}» перевищує 20 МБ`); return false }
      return true
    })

    if (!valid.length) return

    setUploading(true)
    setUploadProgress({ done: 0, total: valid.length })
    try {
      // Get owner_id from the property once
      const { data: propRow } = await supabase
        .from('properties')
        .select('owner_id')
        .eq('id', propertyId)
        .single()

      for (let i = 0; i < valid.length; i++) {
        const file = valid[i]
        if (currentCount >= MAX_FILES) {
          onError(`Максимум ${MAX_FILES} файлів на об'єкт`)
          break
        }
        setCurrentUploadFile(file.name)
        setUploadProgress({ done: i, total: valid.length })

        const ext  = file.name.split('.').pop()?.toLowerCase() ?? 'bin'
        const rand = Math.random().toString(36).slice(2, 8)
        const path = `${propertyId}/${Date.now()}_${rand}.${ext}`

        const { error: storErr } = await supabase.storage.from(BUCKET).upload(path, file)
        if (storErr) { onError(storErr.message); continue }

        const { data: row, error: dbErr } = await supabase
          .from('property_files')
          .insert({
            property_id:  propertyId,
            owner_id:     propRow?.owner_id ?? '',
            storage_path: path,
            file_name:    file.name,
            file_size:    file.size,
            mime_type:    file.type,
            sort_order:   currentCount,
          })
          .select()
          .single()

        if (dbErr) {
          await supabase.storage.from(BUCKET).remove([path]).catch(() => {})
          onError(dbErr.message)
          continue
        }

        setFiles(prev => [...prev, row as PropertyFile])
        setUploadProgress({ done: i + 1, total: valid.length })
        currentCount++
      }
    } finally {
      setUploading(false)
      setCurrentUploadFile(null)
      setUploadProgress(null)
    }
  }, [propertyId, files.length])

  const deleteFile = useCallback(async (
    fileId: string,
    storagePath: string,
    onError: (msg: string) => void
  ) => {
    const { error } = await supabase.from('property_files').delete().eq('id', fileId)
    if (error) { onError(error.message); return }
    await supabase.storage.from(BUCKET).remove([storagePath]).catch(() => {})
    setFiles(prev => prev.filter(f => f.id !== fileId))
  }, [])

  const getSignedUrl = useCallback(async (storagePath: string): Promise<string | null> => {
    const { data, error } = await supabase.storage
      .from(BUCKET)
      .createSignedUrl(storagePath, 3600)
    return error ? null : data.signedUrl
  }, [])

  return {
    files,
    loading,
    uploading,
    uploadProgress,
    currentUploadFile,
    fetchFiles,
    uploadFiles,
    deleteFile,
    getSignedUrl,
    maxFiles: MAX_FILES,
  }
}

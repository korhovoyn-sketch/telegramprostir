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
        .select('id,property_id,owner_id,storage_path,file_name,file_size,mime_type,sort_order,created_at')
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

    // Guard: query DB for the real current count — avoids stale closure
    // when the user triggers a second upload batch before React re-renders.
    const { count: dbCount } = await supabase
      .from('property_files')
      .select('id', { count: 'exact', head: true })
      .eq('property_id', propertyId)
    let currentCount = dbCount ?? files.length

    // Filter out invalid files before showing progress so total is accurate
    const valid = picked.filter(file => {
      if (currentCount >= MAX_FILES) return false
      if (!ALLOWED_MIME.has(file.type)) { onError(`«${file.name}» — формат не підтримується (тільки PDF, DOC, DOCX)`); return false }
      if (file.size > MAX_SIZE)         { onError(`«${file.name}» перевищує 20 МБ`); return false }
      return true
    })

    if (!valid.length) return

    // Verify ownership before touching storage — prevents orphaned files when RLS
    // blocks the DB insert but the storage upload already succeeded.
    const { data: propRow, error: propErr } = await supabase
      .from('properties')
      .select('owner_id')
      .eq('id', propertyId)
      .single()

    if (propErr || !propRow?.owner_id) {
      onError('Не вдалося підтвердити право власності на об\'єкт')
      return
    }

    setUploading(true)
    setUploadProgress({ done: 0, total: valid.length })
    try {
      const supabaseUrl = process.env.NEXT_PUBLIC_SUPABASE_URL
      const supabaseKey = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY
      if (!supabaseUrl || !supabaseKey) throw new Error('Supabase config missing')

      // Pass user's JWT so the Edge Function can verify ownership via RLS.
      const { data: { session } } = await supabase.auth.getSession()
      const userToken = session?.access_token ?? supabaseKey

      for (let i = 0; i < valid.length; i++) {
        const file = valid[i]
        if (currentCount >= MAX_FILES) {
          onError(`Максимум ${MAX_FILES} файлів на об'єкт`)
          break
        }

        setCurrentUploadFile(file.name)
        setUploadProgress({ done: i, total: valid.length })

        // Call Edge Function to validate and get signed upload URL.
        // Authorization header carries user JWT so the function can verify property ownership.
        // Use AbortController to timeout on slow networks (10s max per file).
        const controller = new AbortController()
        const timeout = setTimeout(() => controller.abort(), 10000)

        let validateRes
        try {
          validateRes = await fetch(`${supabaseUrl}/functions/v1/validate-upload`, {
            method: 'POST',
            signal: controller.signal,
            headers: {
              'Content-Type': 'application/json',
              'Authorization': `Bearer ${userToken}`,
              'apikey': supabaseKey,
            },
            body: JSON.stringify({
              propertyId,
              fileName: file.name,
              mimeType: file.type,
              fileSize: file.size,
            }),
          })
        } catch (err) {
          if (err instanceof Error && err.name === 'AbortError') {
            onError('Timeout validating file (10s) — check your connection')
          } else {
            onError(`Upload validation failed: ${err instanceof Error ? err.message : String(err)}`)
          }
          continue
        } finally {
          clearTimeout(timeout)
        }

        if (!validateRes.ok) {
          const errData = await validateRes.json().catch(() => ({}))
          onError((errData as Record<string, unknown>).error as string || `Upload validation failed (${validateRes.status})`)
          continue
        }

        const { uploadUrl, storagePath } = await validateRes.json() as { uploadUrl: string; storagePath: string }
        if (!uploadUrl || !storagePath) {
          onError('Invalid upload response')
          continue
        }

        // Upload file using signed URL
        const uploadResult = await fetch(uploadUrl, {
          method: 'PUT',
          headers: {
            'Content-Type': file.type,
            'x-upsert': 'false',
          },
          body: file,
        })

        if (!uploadResult.ok) {
          onError(`Upload failed: ${uploadResult.status}`)
          continue
        }

        // Record in database
        const { data: row, error: dbErr } = await supabase
          .from('property_files')
          .insert({
            property_id:  propertyId,
            owner_id:     propRow.owner_id,
            storage_path: storagePath,
            file_name:    file.name,
            file_size:    file.size,
            mime_type:    file.type,
            sort_order:   currentCount,
          })
          .select()
          .single()

        if (dbErr) {
          console.warn(`[usePropertyFiles] DB insert failed for ${storagePath}:`, dbErr.message)
          onError(`Файл завантажено, але не збережено: ${dbErr.message}`)
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

'use client'

import { useEffect, useRef, useState } from 'react'
import { usePropertyFiles } from '@/hooks/usePropertyFiles'
import { useAppStore } from '@/store/appStore'
import Modal from '@/components/ui/Modal'
import FilePreviewModal from '@/components/ui/FilePreviewModal'
import { IconFile, IconPlus, IconTrash, IconEye, IconCloudUpload } from '@/components/Icons'
import type { PropertyFile } from '@/types'

interface FilesListProps {
  propertyId: string
  isOwner: boolean
}

function formatBytes(bytes: number): string {
  if (bytes < 1024)        return `${bytes} B`
  if (bytes < 1024 * 1024) return `${Math.round(bytes / 1024)} KB`
  return `${(bytes / 1024 / 1024).toFixed(1)} MB`
}

function FileBadge({ mime }: { mime: string }) {
  const isPdf = mime === 'application/pdf'
  return (
    <div style={{
      width: 38, height: 38, borderRadius: 10,
      display: 'flex', flexDirection: 'column',
      alignItems: 'center', justifyContent: 'center',
      background: isPdf ? 'rgba(255,107,107,.15)' : 'rgba(122,179,255,.15)',
      border: `.5px solid ${isPdf ? 'rgba(255,107,107,.3)' : 'rgba(122,179,255,.3)'}`,
      flexShrink: 0, gap: 1,
    }}>
      <IconFile size={14} color={isPdf ? '#ff6b6b' : '#7AB3FF'} />
      <span style={{
        fontSize: 8, fontWeight: 800, letterSpacing: '.04em',
        color: isPdf ? '#ff8585' : '#7AB3FF', lineHeight: 1,
      }}>
        {isPdf ? 'PDF' : 'DOC'}
      </span>
    </div>
  )
}

export default function FilesList({ propertyId, isOwner }: FilesListProps) {
  const { files, loading, uploading, uploadProgress, currentUploadFile, fetchFiles, uploadFiles, deleteFile, getSignedUrl, maxFiles } =
    usePropertyFiles(propertyId)
  const { showToast } = useAppStore()
  const fileInputRef = useRef<HTMLInputElement>(null)
  const [toDelete, setToDelete]     = useState<PropertyFile | null>(null)
  const [openingId, setOpeningId]   = useState<string | null>(null)
  const [previewFile, setPreviewFile] = useState<{ url: string; mime: string; name: string } | null>(null)

  useEffect(() => { fetchFiles() }, [fetchFiles])

  async function handleUpload(e: React.ChangeEvent<HTMLInputElement>) {
    const picked = Array.from(e.target.files ?? [])
    e.target.value = ''
    if (!picked.length) return
    await uploadFiles(picked, msg =>
      showToast({ type: 'error', title: 'Помилка завантаження', subtitle: msg })
    )
    showToast({ type: 'success', title: 'Файл(и) завантажено' })
  }

  async function handlePreview(file: PropertyFile) {
    setOpeningId(file.id)
    try {
      const url = await getSignedUrl(file.storage_path)
      if (!url) { showToast({ type: 'error', title: 'Не вдалося відкрити файл' }); return }
      setPreviewFile({ url, mime: file.mime_type, name: file.file_name })
    } finally {
      setOpeningId(null)
    }
  }

  async function handleDelete() {
    if (!toDelete) return
    await deleteFile(toDelete.id, toDelete.storage_path, msg =>
      showToast({ type: 'error', title: 'Помилка видалення', subtitle: msg })
    )
    setToDelete(null)
    showToast({ type: 'success', title: 'Файл видалено' })
  }

  const canUpload = isOwner && files.length < maxFiles && !uploading

  return (
    <>
      {/* ── Section header ── */}
      <div className="over">
        <span style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
          <IconFile size={14} color="#a78bfa" />
          Файли
          {files.length > 0 && (
            <span style={{
              fontSize: 11, fontWeight: 600, color: 'var(--t3)',
              background: 'var(--glass-2)', borderRadius: 8, padding: '1px 6px',
            }}>
              {files.length}/{maxFiles}
            </span>
          )}
        </span>
        {canUpload && (
          <button
            onClick={() => fileInputRef.current?.click()}
            style={{
              display: 'flex', alignItems: 'center', gap: 4,
              background: 'rgba(122,179,255,.14)',
              border: '.5px solid rgba(122,179,255,.3)',
              borderRadius: 10, padding: '4px 10px',
              color: '#7AB3FF', fontSize: 12, fontWeight: 600, cursor: 'pointer',
            }}
          >
            <IconPlus size={12} />Додати
          </button>
        )}
      </div>

      {/* ── Empty state ── */}
      {!loading && files.length === 0 && !uploading && (
        <div style={{
          margin: '0 12px 16px',
          border: '.5px dashed rgba(255,255,255,.18)',
          borderRadius: 'var(--r-md)', padding: '18px 16px',
          display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 8,
        }}>
          <IconCloudUpload size={28} color="var(--t4)" />
          <div style={{ fontSize: 13, color: 'var(--t3)', textAlign: 'center', lineHeight: 1.4 }}>
            {isOwner
              ? `Додайте PDF або Word файли (до ${maxFiles} шт., макс. 20 МБ)`
              : 'Файли ще не додані'}
          </div>
          {isOwner && (
            <button
              onClick={() => fileInputRef.current?.click()}
              style={{
                marginTop: 4, background: 'var(--glass-2)', border: 'var(--bd)',
                borderRadius: 'var(--r-pill)', color: 'var(--t1)',
                fontSize: 13, fontWeight: 600, padding: '8px 20px', cursor: 'pointer',
                display: 'flex', alignItems: 'center', gap: 6,
              }}
            >
              <IconPlus size={14} />Завантажити файл
            </button>
          )}
        </div>
      )}

      {/* ── Skeleton ── */}
      {loading && (
        <div style={{ margin: '0 12px 16px', display: 'flex', flexDirection: 'column', gap: 6 }}>
          {[1, 2].map(i => (
            <div key={i} className="skel" style={{ height: 58, borderRadius: 'var(--r-sm)' }} />
          ))}
        </div>
      )}

      {/* ── File rows ── */}
      {!loading && (files.length > 0 || uploading) && (
        <div style={{ margin: '0 12px 16px', display: 'flex', flexDirection: 'column', gap: 6 }}>
          {files.map(file => (
            <div key={file.id} style={{
              display: 'flex', alignItems: 'center', gap: 10,
              padding: '9px 12px', borderRadius: 'var(--r-sm)',
              background: 'var(--glass-1)', border: 'var(--bd)',
            }}>
              <FileBadge mime={file.mime_type} />

              <div style={{ flex: 1, minWidth: 0 }}>
                <div style={{
                  fontSize: 13, fontWeight: 600, color: 'var(--t1)',
                  overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
                }}>
                  {file.file_name}
                </div>
                <div style={{ fontSize: 11, color: 'var(--t3)', marginTop: 2 }}>
                  {formatBytes(file.file_size)}
                </div>
              </div>

              {/* Preview */}
              <button
                onClick={() => handlePreview(file)}
                disabled={openingId === file.id}
                style={{
                  width: 32, height: 32, borderRadius: '50%',
                  background: 'var(--glass-2)', border: 'var(--bd)',
                  display: 'flex', alignItems: 'center', justifyContent: 'center',
                  cursor: 'pointer', color: 'var(--t2)', flexShrink: 0,
                  opacity: openingId === file.id ? 0.5 : 1, transition: 'opacity .15s',
                }}
              >
                {openingId === file.id
                  ? <div className="loader" style={{ width: 14, height: 14, borderWidth: 2 }} />
                  : <IconEye size={14} />
                }
              </button>

              {/* Delete (owner only) */}
              {isOwner && (
                <button
                  onClick={() => setToDelete(file)}
                  style={{
                    width: 32, height: 32, borderRadius: '50%',
                    background: 'var(--glass-2)', border: 'var(--bd)',
                    display: 'flex', alignItems: 'center', justifyContent: 'center',
                    cursor: 'pointer', color: 'var(--err)', flexShrink: 0,
                  }}
                >
                  <IconTrash size={14} />
                </button>
              )}
            </div>
          ))}

          {/* Upload progress row */}
          {uploading && uploadProgress && (
            <div style={{
              display: 'flex', alignItems: 'center', gap: 10,
              padding: '10px 12px', borderRadius: 'var(--r-sm)',
              background: 'rgba(122,179,255,.08)',
              border: '.5px solid rgba(122,179,255,.25)',
            }}>
              <div className="loader" style={{ width: 16, height: 16, borderWidth: 2, flexShrink: 0 }} />
              <div style={{ flex: 1, minWidth: 0 }}>
                <div style={{ fontSize: 12, fontWeight: 600, color: '#7AB3FF', marginBottom: 4 }}>
                  Завантаження {uploadProgress.done + 1}/{uploadProgress.total}
                </div>
                {currentUploadFile && (
                  <div style={{ fontSize: 11, color: 'var(--t3)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                    {currentUploadFile}
                  </div>
                )}
                {/* Progress bar */}
                <div style={{ marginTop: 6, height: 3, borderRadius: 2, background: 'rgba(255,255,255,.1)' }}>
                  <div style={{
                    height: '100%', borderRadius: 2,
                    background: 'linear-gradient(90deg,#7AB3FF,#a78bfa)',
                    width: `${Math.round((uploadProgress.done / uploadProgress.total) * 100)}%`,
                    transition: 'width .25s ease',
                  }} />
                </div>
              </div>
            </div>
          )}

          {/* Add more row */}
          {isOwner && files.length < maxFiles && !uploading && (
            <button
              onClick={() => fileInputRef.current?.click()}
              style={{
                display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 6,
                padding: '9px 12px', borderRadius: 'var(--r-sm)',
                border: '.5px dashed rgba(255,255,255,.2)',
                background: 'transparent', color: 'var(--t3)',
                fontSize: 13, fontWeight: 500, cursor: 'pointer',
              }}
            >
              <IconPlus size={14} />Додати ще файл
            </button>
          )}

          {files.length >= maxFiles && (
            <div style={{ fontSize: 11, color: 'var(--t3)', textAlign: 'center', padding: '4px 0 2px' }}>
              Досягнуто ліміту {maxFiles} файлів
            </div>
          )}
        </div>
      )}

      {/* Hidden file input */}
      {isOwner && (
        <input
          ref={fileInputRef}
          type="file"
          accept=".pdf,.doc,.docx"
          multiple
          style={{ display: 'none' }}
          onChange={handleUpload}
        />
      )}

      {/* ── File preview (inline, no external browser) ── */}
      {previewFile && (
        <FilePreviewModal
          url={previewFile.url}
          mime={previewFile.mime}
          name={previewFile.name}
          onClose={() => setPreviewFile(null)}
        />
      )}

      {/* ── Delete confirmation ── */}
      {toDelete && (
        <Modal
          title="Видалити файл?"
          subtitle={`«${toDelete.file_name}» буде видалено назавжди.`}
          onClose={() => setToDelete(null)}
          actions={[
            { label: 'Видалити', variant: 'danger', onClick: handleDelete },
            { label: 'Скасувати', variant: 'secondary', onClick: () => setToDelete(null) },
          ]}
        />
      )}
    </>
  )
}

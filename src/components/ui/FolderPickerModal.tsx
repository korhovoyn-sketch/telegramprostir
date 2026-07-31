'use client'

import { useState } from 'react'
import Modal from '@/components/ui/Modal'
import { IconFolder, IconCheck, IconPlus, IconInbox } from '@/components/Icons'
import type { PropertyFolder } from '@/types'

interface Props {
  folders: PropertyFolder[]
  title: string
  subtitle?: string
  // Поточна папка (для одиночного переміщення) — показує галочку; для bulk = undefined.
  currentFolderId?: string | null
  onPick: (folderId: string | null) => void
  onCreate: (name: string) => Promise<PropertyFolder | null>
  onClose: () => void
}

export default function FolderPickerModal({ folders, title, subtitle, currentFolderId, onPick, onCreate, onClose }: Props) {
  const [newName, setNewName] = useState('')
  const [adding, setAdding] = useState(false)
  const [busy, setBusy] = useState(false)

  async function handleCreate() {
    const name = newName.trim()
    if (!name || busy) return
    setBusy(true)
    const created = await onCreate(name)
    setBusy(false)
    if (created) { onPick(created.id) }
  }

  return (
    <Modal title={title} subtitle={subtitle} onClose={onClose}>
      <div className="sheet-group">
        <div className="sheet-row" onClick={() => onPick(null)}>
          <span className="sheet-ic"><IconInbox size={17} /></span>
          <span className="sheet-lbl">Без папки</span>
          {currentFolderId === null && <IconCheck size={16} className="sheet-chev" />}
        </div>
        {folders.map((f) => (
          <div key={f.id} className="sheet-row" onClick={() => onPick(f.id)}>
            <span className="sheet-ic"><IconFolder size={17} /></span>
            <span className="sheet-lbl">{f.name}</span>
            {currentFolderId === f.id && <IconCheck size={16} className="sheet-chev" />}
          </div>
        ))}
      </div>

      {adding ? (
        <div className="fold-mng-new">
          <span className="fold-mng-ic"><IconPlus size={16} /></span>
          <input
            className="fold-mng-input"
            value={newName}
            placeholder="Назва папки…"
            autoFocus
            onChange={(e) => setNewName(e.target.value)}
            onKeyDown={(e) => { if (e.key === 'Enter') handleCreate() }}
            maxLength={40}
          />
          <button className="fold-mng-add" disabled={!newName.trim() || busy} onClick={handleCreate}>Створити</button>
        </div>
      ) : (
        <button className="sheet-cancel" style={{ marginBottom: 10 }} onClick={() => setAdding(true)}>
          + Нова папка
        </button>
      )}
      <button className="sheet-cancel" onClick={onClose}>Скасувати</button>
    </Modal>
  )
}

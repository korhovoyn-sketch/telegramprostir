'use client'

import Modal from '@/components/ui/Modal'
import SheetCreateRow from '@/components/ui/SheetCreateRow'
import { IconFolder, IconCheck, IconInbox } from '@/components/Icons'
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
  return (
    <Modal
      title={title}
      subtitle={subtitle}
      onClose={onClose}
      // Через actions, а не власна .sheet-cancel: sticky-позиція, safe-area і
      // клавіатурна корекція Modal (див. DbPickerModal).
      actions={[{ label: 'Скасувати', variant: 'secondary', onClick: onClose }]}
    >
      <SheetCreateRow
        collapsedLabel="Нова папка"
        fieldLabel="Назва нової папки"
        placeholder="Назва папки…"
        confirmLabel="Створити"
        maxLength={40}
        // Створення тут ЗАВЕРШУЄ вибір: нова папка одразу стає обраною.
        onCreate={async (name) => {
          const created = await onCreate(name)
          if (created) onPick(created.id)
          return !!created
        }}
      />

      <div className="sheet-group">
        <button type="button" className="sheet-row" onClick={() => onPick(null)}>
          <span className="sheet-ic"><IconInbox size={16} /></span>
          <span className="sheet-lbl">Без папки</span>
          {currentFolderId === null && <IconCheck size={16} className="sheet-chev" />}
        </button>
        {folders.map((f) => (
          <button key={f.id} type="button" className="sheet-row" onClick={() => onPick(f.id)}>
            <span className="sheet-ic"><IconFolder size={16} /></span>
            <span className="sheet-lbl">{f.name}</span>
            {currentFolderId === f.id && <IconCheck size={16} className="sheet-chev" />}
          </button>
        ))}
      </div>
    </Modal>
  )
}

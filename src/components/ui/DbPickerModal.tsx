'use client'

import { useState } from 'react'
import Modal from '@/components/ui/Modal'
import { GlassDbIcon, IconPlus } from '@/components/Icons'
import { objectsWord } from '@/lib/utils'
import type { Database } from '@/types'

interface Props {
  /** Бази-приймачі. Поточну база викликач НЕ передає. */
  databases: Database[]
  count: number
  onPick: (db: Database) => void
  /** Створити нову базу під перенос; повертає створену або null. */
  onCreate: (name: string) => Promise<Database | null>
  onClose: () => void
}

export default function DbPickerModal({ databases, count, onPick, onCreate, onClose }: Props) {
  const [newName, setNewName] = useState('')
  const [adding, setAdding] = useState(false)
  const [busy, setBusy] = useState(false)

  async function handleCreate() {
    const name = newName.trim()
    if (!name || busy) return
    setBusy(true)
    const created = await onCreate(name)
    setBusy(false)
    if (created) onPick(created)
  }

  return (
    <Modal
      title="Перенести в базу"
      subtitle={`${count} ${objectsWord(count)} буде переміщено`}
      onClose={onClose}
    >
      {/* Поле створення — ЗВЕРХУ: на iOS клавіатура накриває низ шита. */}
      {adding ? (
        <div className="fold-mng-new">
          <span className="fold-mng-ic"><IconPlus size={16} /></span>
          <input
            className="fold-mng-input"
            value={newName}
            aria-label="Назва нової бази"
            placeholder="Назва нової бази…"
            autoFocus
            onChange={(e) => setNewName(e.target.value)}
            onKeyDown={(e) => { if (e.key === 'Enter') handleCreate() }}
            maxLength={60}
          />
          <button className="fold-mng-add" disabled={!newName.trim() || busy} onClick={handleCreate}>
            Створити
          </button>
        </div>
      ) : (
        <button className="fold-pick-new" onClick={() => setAdding(true)}>
          <IconPlus size={16} /> Нова база з обраних
        </button>
      )}

      {databases.length === 0 ? (
        <div style={{ padding: '20px 4px', textAlign: 'center', color: 'var(--t3)', fontSize: 'var(--fs-foot)' }}>
          Інших баз ще немає. Введіть назву вгорі — обрані об&apos;єкти переїдуть у нову.
        </div>
      ) : (
        <div className="sheet-group">
          {databases.map((db) => (
            <div key={db.id} className="sheet-row" onClick={() => onPick(db)}>
              <span className="sheet-ic"><GlassDbIcon type={db.type} color={db.color} size={24} /></span>
              <span className="sheet-lbl">{db.name}</span>
              <span className="bdg bdg-info">{db._property_count ?? 0} об.</span>
            </div>
          ))}
        </div>
      )}

      <button className="sheet-cancel" onClick={onClose}>Скасувати</button>
    </Modal>
  )
}

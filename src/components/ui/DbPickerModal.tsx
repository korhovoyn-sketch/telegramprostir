'use client'

import Modal from '@/components/ui/Modal'
import SheetCreateRow from '@/components/ui/SheetCreateRow'
import { GlassDbIcon } from '@/components/Icons'
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
  return (
    <Modal
      title="Перенести в базу"
      subtitle={`${count} ${objectsWord(count)} буде переміщено`}
      onClose={onClose}
      // «Скасувати» саме через actions, а не власна .sheet-cancel у тілі: звідти
      // приходить sticky-позиція, safe-area (кнопка більше не лягає під
      // home-індикатор) і клавіатурна корекція — `clearStickyActions` у Modal
      // виходить одразу, якщо `.modal-actions` у шиті немає взагалі.
      actions={[{ label: 'Скасувати', variant: 'secondary', onClick: onClose }]}
    >
      <SheetCreateRow
        collapsedLabel="Нова база з обраних"
        fieldLabel="Назва нової бази"
        placeholder="Назва нової бази…"
        confirmLabel="Створити"
        maxLength={60}
        onCreate={async (name) => {
          const created = await onCreate(name)
          if (created) onPick(created)
          return !!created
        }}
      />

      {databases.length === 0 ? (
        <div className="sheet-empty">
          Інших баз ще немає. Введіть назву вгорі — обрані об&apos;єкти переїдуть у нову.
        </div>
      ) : (
        <div className="sheet-group">
          {databases.map((db) => (
            <button key={db.id} type="button" className="sheet-row" onClick={() => onPick(db)}>
              <span className="sheet-ic"><GlassDbIcon type={db.type} color={db.color} size={24} /></span>
              <span className="sheet-lbl">{db.name}</span>
              <span className="bdg bdg-info">{db._property_count ?? 0} об.</span>
            </button>
          ))}
        </div>
      )}
    </Modal>
  )
}

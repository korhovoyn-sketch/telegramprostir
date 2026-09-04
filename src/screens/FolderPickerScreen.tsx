'use client'

import { useEffect, useState } from 'react'
import { useAppStore } from '@/store/appStore'
import { useFolders } from '@/hooks/useFolders'
import { useProperties } from '@/hooks/useProperties'
import Header from '@/components/ui/Header'
import RetryState from '@/components/ui/RetryState'
import { IconFolder, IconInbox, IconPlus } from '@/components/Icons'
import { objectsWord, scrollFocusedIntoView } from '@/lib/utils'
import { offlineGuard } from '@/lib/offline'

/**
 * Повноекранний вибір папки для пакетного переміщення — заміна колишньої
 * `<Modal>` (фаза 4). Переміщення виконує сам екран; чому саме так —
 * див. коментар у `DbPickerScreen`.
 *
 * ВИБІР ПАПКИ У ФОРМІ ОБʼЄКТА СЮДИ НЕ ХОДИТЬ, і це важливо: там значення
 * потрібне НЕЗБЕРЕЖЕНІЙ формі, а перехід на інший екран розмонтував би її
 * разом з усіма правками (чернетка є лише в режимі створення). Тому у формі
 * список папок розгортається інлайново.
 */
export default function FolderPickerScreen() {
  const { screenParams, back } = useAppStore()
  const dbId = screenParams.dbId as string | undefined
  const ids = (screenParams.propertyIds as string[] | undefined) ?? []

  const { folders, error: loadErr, loadFolders, createFolder } = useFolders(dbId)
  const { moveToFolder } = useProperties(dbId)

  useEffect(() => {
    loadFolders()
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [dbId])

  const [newName, setNewName] = useState('')
  const [busy, setBusy] = useState(false)

  async function pick(folderId: string | null) {
    if (busy || offlineGuard()) return
    setBusy(true)
    await moveToFolder(ids, folderId)
    setBusy(false)
    back()
  }

  // Створення тут ЗАВЕРШУЄ вибір: нова папка одразу стає цільовою.
  async function createAndPick() {
    const name = newName.trim()
    if (!name || busy || offlineGuard()) return
    setBusy(true)
    const created = await createFolder(name)
    if (!created) { setBusy(false); return }
    await moveToFolder(ids, created.id)
    setBusy(false)
    back()
  }

  return (
    <div className="scr bg-blue">
      <Header
        title={`Перемістити ${ids.length} ${objectsWord(ids.length)}`}
        subtitle="Оберіть папку або створіть нову"
        onBack={back}
      />

      <div className="body has-flow-cta" onFocusCapture={scrollFocusedIntoView}>
        <div className="fg glass-s">
          <div className="fr">
            <span className="fr-l" style={{ display: 'flex', alignItems: 'center', gap: 5 }}>
              <IconPlus size={14} color="var(--t3)" />Нова
            </span>
            <input
              className="fr-i"
              aria-label="Назва нової папки"
              placeholder="Назва папки…"
              value={newName}
              maxLength={40}
              onChange={(e) => setNewName(e.target.value)}
              onKeyDown={(e) => { if (e.key === 'Enter') void createAndPick() }}
            />
          </div>
        </div>

        <div className="sheet-group">
          <button type="button" className="sheet-row" disabled={busy} onClick={() => void pick(null)}>
            <span className="sheet-ic"><IconInbox size={16} /></span>
            <span className="sheet-lbl">Без папки</span>
          </button>
          {/* Той самий розподіл, що в керуванні папками: збій завантаження не
              сміє виглядати як «папок немає» — інакше обʼєкт їде в «Без
              папки» тому, що список не доїхав. */}
          {loadErr && folders.length === 0 && (
            <RetryState subtitle={loadErr} onRetry={() => loadFolders(dbId)} />
          )}
          {folders.map((f) => (
            <button key={f.id} type="button" className="sheet-row" disabled={busy} onClick={() => void pick(f.id)}>
              <span className="sheet-ic"><IconFolder size={16} /></span>
              <span className="sheet-lbl">{f.name}</span>
            </button>
          ))}
        </div>

        <button
          className="mbtn mbtn-flow"
          disabled={!newName.trim() || busy}
          aria-busy={busy}
          onClick={() => void createAndPick()}
        >
          Створити й перемістити
        </button>
      </div>
    </div>
  )
}

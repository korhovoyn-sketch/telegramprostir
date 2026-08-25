'use client'

import { useEffect, useState } from 'react'
import { useAppStore } from '@/store/appStore'
import { useDatabases } from '@/hooks/useDatabases'
import { useProperties } from '@/hooks/useProperties'
import Header from '@/components/ui/Header'
import SkeletonLoader from '@/components/ui/SkeletonLoader'
import RetryState from '@/components/ui/RetryState'
import { GlassDbIcon, IconPlus } from '@/components/Icons'
import { objectsWord, scrollFocusedIntoView } from '@/lib/utils'
import { offlineGuard } from '@/lib/offline'
import type { Database } from '@/types'

/**
 * Повноекранний вибір бази-приймача для пакетного переносу — заміна колишньої
 * `<Modal>` (фаза 4).
 *
 * ПЕРЕНІС ВИКОНУЄ САМ ЦЕЙ ЕКРАН, а не викликач, і це не стиль, а структура:
 * `selectedIds` живуть у стані `DatabaseObjectsScreen`, який при навігації
 * розмонтовується. Повернення туди перемонтовує його з чистим станом і свіжим
 * запитом — тобто результат видно одразу, а «повернути значення нагору»
 * не потрібно (той самий висновок, що у фазі 2 про оптимістичний апдейт).
 */
export default function DbPickerScreen() {
  const { screenParams, back } = useAppStore()
  const dbId = screenParams.dbId as string | undefined
  const ids = (screenParams.propertyIds as string[] | undefined) ?? []

  const { databases, loading, error, loadDatabases, createDatabase } = useDatabases()
  const { moveToDatabase } = useProperties(dbId)

  useEffect(() => {
    loadDatabases()
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  const current = databases.find((d) => d.id === dbId)
  const targets = databases.filter((d) => d.id !== dbId)

  const [newName, setNewName] = useState('')
  const [busy, setBusy] = useState(false)

  async function move(target: Database) {
    if (busy || offlineGuard()) return
    setBusy(true)
    const ok = await moveToDatabase(ids, target.id, target.owner_id, target.name)
    setBusy(false)
    if (ok) back()
  }

  // Нова база під перенос успадковує тип і колір поточної — обрані обʼєкти майже
  // завжди тієї ж природи (форма обʼєкта залежить від типу бази).
  async function createAndMove() {
    const name = newName.trim()
    // Без поточної бази тип і колір нової взяти нізвідки — оригінал так само
    // повертав null, а не вигадував дефолт (тип бази визначає форму обʼєкта).
    if (!name || busy || !current || offlineGuard()) return
    setBusy(true)
    const created = await createDatabase(
      { name, address: current.address, type: current.type, color: current.color },
      { navigate: false },
    )
    if (!created) { setBusy(false); return }
    const ok = await moveToDatabase(ids, created.id, created.owner_id, created.name)
    setBusy(false)
    if (ok) back()
  }

  return (
    <div className="scr bg-blue">
      <Header
        title="Перенести в базу"
        subtitle={`${ids.length} ${objectsWord(ids.length)} буде переміщено`}
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
              aria-label="Назва нової бази"
              placeholder="Назва нової бази…"
              value={newName}
              maxLength={60}
              onChange={(e) => setNewName(e.target.value)}
              onKeyDown={(e) => { if (e.key === 'Enter') void createAndMove() }}
            />
          </div>
        </div>

        {loading && databases.length === 0 ? (
          <SkeletonLoader rows={3} rowHeight={69} />
        ) : error ? (
          <RetryState
            title="Не вдалося завантажити бази"
            subtitle={error}
            onRetry={() => void loadDatabases()}
          />
        ) : targets.length === 0 ? (
          <div className="sheet-empty">
            Інших баз ще немає. Введіть назву вгорі — обрані об&apos;єкти переїдуть у нову.
          </div>
        ) : (
          <div className="sheet-group">
            {targets.map((d) => (
              <button
                key={d.id}
                type="button"
                className="sheet-row"
                disabled={busy}
                onClick={() => void move(d)}
              >
                <span className="sheet-ic"><GlassDbIcon type={d.type} color={d.color} size={24} /></span>
                <span className="sheet-lbl">{d.name}</span>
                <span className="bdg bdg-info">{d._property_count ?? 0} об.</span>
              </button>
            ))}
          </div>
        )}

        <button
          className="mbtn mbtn-flow"
          disabled={!newName.trim() || busy || !current}
          aria-busy={busy}
          onClick={() => void createAndMove()}
        >
          Створити й перенести
        </button>
      </div>
    </div>
  )
}

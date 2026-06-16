'use client'

import { useState, useEffect } from 'react'
import { useAppStore } from '@/store/appStore'
import { useDatabases } from '@/hooks/useDatabases'
import Header from '@/components/ui/Header'
import { IconMapPin, IconBuilding, IconLayoutGrid, IconAdjustments, IconEye, GlassDbIcon } from '@/components/Icons'
import { DB_COLORS, scrollFocusedIntoView } from '@/lib/utils'
import type { DatabaseType } from '@/types'

const TYPES: { id: DatabaseType; label: string; desc: string; neon: 'blue' | 'green' | 'pink' | 'orange' | 'teal' | 'purple' }[] = [
  { id: 'business_center', label: 'Бізнес-центр', desc: 'Офіси з нумерацією', neon: 'blue' },
  { id: 'residential', label: 'ЖК', desc: 'Квартири, пентхауси', neon: 'green' },
  { id: 'retail', label: 'Рітейл', desc: 'Магазини, бутики', neon: 'pink' },
  { id: 'warehouse', label: 'Склади', desc: 'Логістика', neon: 'orange' },
  { id: 'individual', label: 'Приватне', desc: 'Будинки, ділянки', neon: 'teal' },
  { id: 'parking', label: 'Паркінг', desc: 'Паркувальні місця', neon: 'purple' },
]

const COLOR_NAMES = Object.keys(DB_COLORS)

export default function CreateDatabaseScreen() {
  const { screenParams, databases, navigate } = useAppStore()
  const { createDatabase, updateDatabase, loading } = useDatabases()

  const editId = screenParams.dbId
  const isEdit = !!editId
  const existing = databases.find((d) => d.id === editId)

  useEffect(() => {
    const tg = window.Telegram?.WebApp
    tg?.enableClosingConfirmation()
    return () => { tg?.disableClosingConfirmation() }
  }, [])

  const [name, setName] = useState('')
  const [address, setAddress] = useState('')
  const [type, setType] = useState<DatabaseType | null>(null)
  const [color, setColor] = useState('purple')

  useEffect(() => {
    if (isEdit && existing) {
      setName(existing.name)
      setAddress(existing.address ?? '')
      setType(existing.type)
      setColor(existing.color)
    }
  }, [isEdit, existing])

  const canCreate = name.trim().length > 0 && type !== null

  async function handleSave() {
    if (!canCreate || !type) return
    window.Telegram?.WebApp?.HapticFeedback?.notificationOccurred('success')
    if (isEdit && editId) {
      await updateDatabase(editId, { name: name.trim(), address: address.trim() || undefined, type, color })
      navigate('db-objects', { dbId: editId })
    } else {
      await createDatabase({ name: name.trim(), address: address.trim() || undefined, type, color })
    }
  }

  return (
    <div className="scr bg-purple">
      <Header title={isEdit ? 'Редагувати базу' : 'Нова база'} backLabel={isEdit ? 'Назад' : 'Бази'} />

      <div className="body" onFocusCapture={scrollFocusedIntoView}>
        {/* Name & address */}
        <div className="over"><span style={{ display: 'flex', alignItems: 'center', gap: 6 }}><IconBuilding size={13} color="#7AB3FF" />Основне</span></div>
        <div className="fg glass-s" style={{ margin: '0 12px 16px' }}>
          <div className="fr">
            <span className="fr-l">Назва</span>
            <input
              className="fr-i"
              placeholder="БЦ Олімп"
              value={name}
              onChange={(e) => setName(e.target.value)}
              maxLength={100}
              autoFocus
            />
          </div>
          <div className="fr">
            <IconMapPin size={16} color="var(--t3)" />
            <span className="fr-l" style={{ marginLeft: 6 }}>Адреса</span>
            <input
              className="fr-i"
              placeholder="Хрещатик 22"
              value={address}
              onChange={(e) => setAddress(e.target.value)}
              maxLength={200}
            />
          </div>
        </div>

        {/* Type selection */}
        <div className="over"><span style={{ display: 'flex', alignItems: 'center', gap: 6 }}><IconLayoutGrid size={13} color="#a78bfa" />Тип нерухомості</span></div>
        <div className="type-grid">
          {TYPES.map((t) => (
            <div
              key={t.id}
              className={`type-card ${type === t.id ? 'sel' : ''}`}
              onClick={() => { window.Telegram?.WebApp?.HapticFeedback?.selectionChanged(); setType(t.id) }}
            >
              <GlassDbIcon type={t.id} color={t.neon} size={30} />
              <div className="type-n">{t.label}</div>
              <div className="type-s">{t.desc}</div>
            </div>
          ))}
        </div>

        {/* Color */}
        <div className="over"><span style={{ display: 'flex', alignItems: 'center', gap: 6 }}><IconAdjustments size={13} color="#fb923c" />Колір мітки</span></div>
        <div className="color-row">
          {COLOR_NAMES.map((c) => (
            <div
              key={c}
              className={`color-c ${color === c ? 'sel' : ''}`}
              style={{ background: DB_COLORS[c] }}
              onClick={() => { window.Telegram?.WebApp?.HapticFeedback?.selectionChanged(); setColor(c) }}
            />
          ))}
        </div>

        {/* Preview */}
        {name && type && (
          <div style={{ margin: '8px 12px 80px' }}>
            <div className="over" style={{ paddingTop: 12 }}><span style={{ display: 'flex', alignItems: 'center', gap: 6 }}><IconEye size={13} color="var(--t3)" />Попередній вигляд</span></div>
            <div className="row glass-s">
              <GlassDbIcon type={type ?? undefined} color={color} size={32} />
              <div className="row-mn">
                <div className="row-t">{name}</div>
                <div className="row-s">
                  <span className="fresh"><span className="fdot" />сьогодні</span>
                  <span>·</span>
                  <span>{TYPES.find(t => t.id === type)?.label}</span>
                </div>
              </div>
              <span className="bdg bdg-info">0 об.</span>
            </div>
          </div>
        )}
      </div>

      <button
        className={`mbtn success ${!canCreate || loading ? 'disabled' : ''} ${loading ? 'is-loading' : ''}`}
        onClick={handleSave}
        disabled={!canCreate || loading}
      >
        {!loading && (isEdit ? 'Зберегти зміни' : 'Створити базу')}
      </button>
    </div>
  )
}

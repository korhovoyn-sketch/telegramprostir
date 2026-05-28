'use client'

import { useState, useEffect } from 'react'
import { useAppStore } from '@/store/appStore'
import { useDatabases } from '@/hooks/useDatabases'
import Header from '@/components/ui/Header'
import { IconMapPin } from '@/components/Icons'
import { DB_COLORS } from '@/lib/utils'
import type { DatabaseType } from '@/types'

const TYPES: { id: DatabaseType; label: string; desc: string; emoji: string }[] = [
  { id: 'business_center', label: 'Бізнес-центр', desc: 'Офіси з нумерацією', emoji: '🏢' },
  { id: 'residential', label: 'ЖК', desc: 'Квартири, пентхауси', emoji: '🏘' },
  { id: 'retail', label: 'Рітейл', desc: 'Магазини, бутики', emoji: '🏪' },
  { id: 'warehouse', label: 'Склади', desc: 'Логістика', emoji: '🏭' },
  { id: 'individual', label: 'Приватне', desc: 'Будинки, ділянки', emoji: '🏠' },
  { id: 'parking', label: 'Паркінг', desc: 'Паркувальні місця', emoji: '🅿️' },
]

const COLOR_NAMES = Object.keys(DB_COLORS)

export default function CreateDatabaseScreen() {
  const { screenParams, databases, navigate } = useAppStore()
  const { createDatabase, updateDatabase, loading } = useDatabases()

  const editId = screenParams.dbId
  const isEdit = !!editId
  const existing = databases.find((d) => d.id === editId)

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

      <div className="body">
        {/* Name & address */}
        <div className="over">Основне</div>
        <div className="fg glass-s" style={{ margin: '0 12px 16px' }}>
          <div className="fr">
            <span className="fr-l">Назва</span>
            <input
              className="fr-i"
              placeholder="БЦ Олімп"
              value={name}
              onChange={(e) => setName(e.target.value)}
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
            />
          </div>
        </div>

        {/* Type selection */}
        <div className="over">Тип нерухомості</div>
        <div className="type-grid">
          {TYPES.map((t) => (
            <div
              key={t.id}
              className={`type-card ${type === t.id ? 'sel' : ''}`}
              onClick={() => setType(t.id)}
            >
              <div className="type-ic">{t.emoji}</div>
              <div className="type-n">{t.label}</div>
              <div className="type-s">{t.desc}</div>
            </div>
          ))}
        </div>

        {/* Color */}
        <div className="over">Колір мітки</div>
        <div className="color-row">
          {COLOR_NAMES.map((c) => (
            <div
              key={c}
              className={`color-c ${color === c ? 'sel' : ''}`}
              style={{ background: DB_COLORS[c] }}
              onClick={() => setColor(c)}
            />
          ))}
        </div>

        {/* Preview */}
        {name && type && (
          <div style={{ margin: '8px 12px 80px' }}>
            <div className="over" style={{ paddingTop: 12 }}>Попередній вигляд</div>
            <div className="row glass-s">
              <div className="row-ic" style={{ background: DB_COLORS[color] }}>
                <span style={{ fontSize: 18 }}>{TYPES.find(t => t.id === type)?.emoji}</span>
              </div>
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

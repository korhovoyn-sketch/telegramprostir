'use client'

import { useState, useEffect } from 'react'
import { useAppStore } from '@/store/appStore'
import { hapticSelection, hapticNotify } from '@/lib/telegram'
import { offlineGuard } from '@/lib/offline'
import { useDatabases } from '@/hooks/useDatabases'
import Header from '@/components/ui/Header'
import { IconCheck, IconMapPin, IconBuilding, IconLayoutGrid, IconAdjustments, IconEye, IconEdit, IconUser, GlassDbIcon } from '@/components/Icons'
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
const COLOR_LABELS: Record<string, string> = {
  purple: 'Фіолетовий', blue: 'Синій', green: 'Зелений',
  orange: 'Помаранчевий', pink: 'Рожевий', teal: 'Бірюзовий',
}

export default function CreateDatabaseScreen() {
  const { screenParams, databases, backThenReplace } = useAppStore()
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
  const [landlord, setLandlord] = useState('')

  useEffect(() => {
    if (isEdit && existing) {
      setName(existing.name)
      setAddress(existing.address ?? '')
      setType(existing.type)
      setColor(existing.color)
      setLandlord(existing.landlord_name ?? '')
    }
  }, [isEdit, existing])

  const canCreate = name.trim().length > 0 && type !== null

  async function handleSave() {
    if (!canCreate || !type) return
    if (offlineGuard()) return
    hapticNotify('success')
    // Порожнє поле — це `null`, а НЕ `undefined`: `JSON.stringify` викидає
    // ключі з `undefined`, тож очищена адреса просто не доїжджала до PATCH —
    // колонка лишалась старою, а тост казав «Базу оновлено». Сусідній
    // `landlord_name` уже писався правильно, тобто правило знали й застосували
    // лише до нової колонки. Той самий клас лікує `blank()` у формі обʼєкта.
    const payload = {
      name: name.trim(),
      address: address.trim() || null,
      type,
      color,
      landlord_name: landlord.trim() || null,
    }
    if (isEdit && editId) {
      await updateDatabase(editId, payload)
      backThenReplace('db-objects', { dbId: editId })
    } else {
      await createDatabase(payload)
    }
  }

  return (
    <div className="scr bg-purple">
      <Header title={isEdit ? 'Редагувати базу' : 'Нова база'} backLabel={isEdit ? 'Назад' : 'Бази'} />

      <div className="body has-flow-cta" onFocusCapture={scrollFocusedIntoView}>
        {/* Name & address */}
        <div className="over"><span style={{ display: 'flex', alignItems: 'center', gap: 6 }}><IconBuilding size={14} color="var(--info)" />Основне</span></div>
        <div className="fg glass-s" style={{ margin: '0 12px 16px' }}>
          <div className="fr">
            <span className="fr-l" style={{ display: 'flex', alignItems: 'center', gap: 5 }}><IconEdit size={14} color="var(--t3)" />Назва</span>
            <input
              aria-label="Назва бази"
              className="fr-i"
              placeholder="БЦ Олімп"
              value={name}
              onChange={(e) => setName(e.target.value)}
              maxLength={100}
              autoFocus
            />
          </div>
          <div className="fr">
            <span className="fr-l" style={{ display: 'flex', alignItems: 'center', gap: 5 }}><IconMapPin size={14} color="var(--t3)" />Адреса</span>
            <input
              aria-label="Адреса бази"
              className="fr-i"
              placeholder="Хрещатик 22"
              value={address}
              onChange={(e) => setAddress(e.target.value)}
              maxLength={200}
            />
          </div>
          {/* Орендодавець БАЗИ — дефолт на всі її обʼєкти; кожен може
              перевизначити своїм значенням (064). */}
          <div className="fr">
            <span className="fr-l" style={{ display: 'flex', alignItems: 'center', gap: 5 }}><IconUser size={14} color="var(--t3)" />Орендодавець</span>
            <input
              aria-label="Орендодавець бази"
              className="fr-i"
              placeholder="ТОВ або ФОП"
              value={landlord}
              onChange={(e) => setLandlord(e.target.value)}
              maxLength={200}
            />
          </div>
        </div>

        {/* Type selection */}
        <div className="over"><span style={{ display: 'flex', alignItems: 'center', gap: 6 }}><IconLayoutGrid size={14} color="var(--violet)" />Тип нерухомості</span></div>
        <div className="type-grid">
          {TYPES.map((t) => (
            <div
              key={t.id}
              className={`type-card ${type === t.id ? 'sel' : ''}`}
              onClick={() => { hapticSelection(); setType(t.id) }}
            >
              <GlassDbIcon type={t.id} color={t.neon} size={32} />
              <div className="type-n">{t.label}</div>
              <div className="type-s">{t.desc}</div>
            </div>
          ))}
        </div>

        {/* Color */}
        <div className="over"><span style={{ display: 'flex', alignItems: 'center', gap: 6 }}><IconAdjustments size={14} color="#fb923c" />Колір мітки</span></div>
        <div className="color-row" role="radiogroup" aria-label="Колір мітки">
          {COLOR_NAMES.map((c) => (
            <div
              key={c}
              role="radio"
              aria-checked={color === c}
              aria-label={COLOR_LABELS[c] ?? c}
              className={`color-c ${color === c ? 'sel' : ''}`}
              style={{ background: DB_COLORS[c] }}
              onClick={() => { hapticSelection(); setColor(c) }}
            >
              {/* ✓ на вибраній: біла обводка слабко читається на світлих градієнтах */}
              {color === c && (
                <span style={{ position: 'absolute', inset: 0, display: 'flex', alignItems: 'center', justifyContent: 'center', filter: 'drop-shadow(0 1px 2px rgba(0,0,0,.45))' }}>
                  <IconCheck size={16} color="var(--t1)" />
                </span>
              )}
            </div>
          ))}
        </div>

        {/* Preview */}
        {name && type && (
          <div style={{ margin: '8px 12px 80px' }}>
            <div className="over" style={{ paddingTop: 12 }}><span style={{ display: 'flex', alignItems: 'center', gap: 6 }}><IconEye size={14} color="var(--t3)" />Попередній вигляд</span></div>
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
        {/* CTA — у ПОТОЦІ тіла, а не окремим блоком під ним: інакше вона лежить
            у смузі голого градієнта, і при відкритій клавіатурі над нею проявляється
            шов на межі панелі форми. */}
        <button
          className={`mbtn success mbtn-flow ${!canCreate || loading ? 'disabled' : ''} ${loading ? 'is-loading' : ''}`}
          onClick={handleSave}
          disabled={!canCreate || loading}
          aria-busy={loading}
        >
          {isEdit ? 'Зберегти зміни' : 'Створити базу'}
        </button>

      </div>
    </div>
  )
}

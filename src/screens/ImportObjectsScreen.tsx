'use client'

import { useEffect, useMemo, useRef, useState } from 'react'
import { useAppStore } from '@/store/appStore'
import { useProperties } from '@/hooks/useProperties'
import { offlineGuard } from '@/lib/offline'
import { hapticSelection, hapticNotify } from '@/lib/telegram'
import Header from '@/components/ui/Header'
import { parseCsv } from '@/lib/csv'
import { sanitizeDecimal, objectsWord, STATUS_LABELS } from '@/lib/utils'
import { IconFile, IconCheck, IconBan, IconLayoutGrid } from '@/components/Icons'
import type { Property, PropertyStatus } from '@/types'

/**
 * ІМПОРТ ОБʼЄКТІВ ІЗ CSV.
 *
 * Експорт у застосунку був завжди, зворотного шляху не було — власник із 40
 * офісами в таблиці мусив вводити їх руками, і саме це найдорожче в онбордингу.
 *
 * Формат — CSV, а не XLSX, і це не спрощення: `XLSX.read` не викликається в
 * проєкті НАВМИСНО (див. `src/lib/csv.ts` і `dependency-surface.test.ts`).
 *
 * Заголовки збігаються з експортними, тож файл, вивантажений із застосунку,
 * заходить назад без ручного зіставлення.
 */

type Field =
  | 'name' | 'floor' | 'status' | 'tenant_name' | 'landlord_name'
  | 'area_useful' | 'area_total' | 'rent_rate' | 'utilities_rate'
  | 'sale_price' | 'address' | 'description'

const FIELDS: { id: Field; label: string; aliases: string[] }[] = [
  { id: 'name',           label: 'Назва',                 aliases: ['назва', 'name', 'обʼєкт', 'обєкт', 'объект', 'номер місця'] },
  { id: 'floor',          label: 'Поверх',                aliases: ['поверх', 'floor', 'рівень'] },
  { id: 'status',         label: 'Статус',                aliases: ['статус', 'status'] },
  { id: 'tenant_name',    label: 'Орендар',               aliases: ['орендар', 'tenant', 'арендатор'] },
  { id: 'landlord_name',  label: 'Орендодавець',          aliases: ['орендодавець', 'landlord'] },
  { id: 'area_useful',    label: 'Площа корисна',         aliases: ['площа корисна (м²)', 'площа корисна', 'корисна площа', 'корисна'] },
  { id: 'area_total',     label: 'Площа розрахункова',    aliases: ['площа розрахункова (м²)', 'площа розрахункова', 'розрахункова площа', 'загальна площа', 'розрахункова'] },
  { id: 'rent_rate',      label: 'Ставка оренди',         aliases: ['ставка оренди', 'ставка', 'оренда'] },
  { id: 'utilities_rate', label: 'Ставка експлуатаційних', aliases: ['ставка експлуатаційних', 'експлуатаційні', 'комунальні'] },
  { id: 'sale_price',     label: 'Ціна продажу',          aliases: ['ціна продажу', 'ціна'] },
  { id: 'address',        label: 'Адреса',                aliases: ['адреса', 'address'] },
  { id: 'description',    label: 'Опис',                  aliases: ['опис', 'description', 'примітка'] },
]

const STATUS_ALIAS: Record<string, PropertyStatus> = {
  'вільно': 'free', 'вільний': 'free', 'free': 'free', 'вакантно': 'free',
  'зайнято': 'occupied', 'зайнятий': 'occupied', 'occupied': 'occupied', 'орендовано': 'occupied',
  'продаж': 'for_sale', 'на продаж': 'for_sale', 'for_sale': 'for_sale', 'продається': 'for_sale',
}

/** Заголовок → поле. Порівняння без регістру й зайвих пробілів. */
function autoMap(headers: string[]): (Field | null)[] {
  const norm = (v: string) => v.toLowerCase().replace(/\s+/g, ' ').trim()
  const used = new Set<Field>()
  return headers.map((h) => {
    const n = norm(h)
    const hit = FIELDS.find((f) => !used.has(f.id) && f.aliases.some((a) => norm(a) === n))
    if (hit) { used.add(hit.id); return hit.id }
    return null
  })
}

const num = (v: string | undefined): number | null => {
  if (!v) return null
  const clean = sanitizeDecimal(v.replace(/\s/g, ''))
  const n = parseFloat(clean)
  return Number.isFinite(n) ? n : null
}

export default function ImportObjectsScreen() {
  const { screenParams, databases, showToast } = useAppStore()
  const dbId = screenParams.dbId as string
  const db = databases.find((d) => d.id === dbId)
  const { properties, createProperties, loadProperties, loading } = useProperties(dbId)

  // Без цього список наявних імен ПОРОЖНІЙ, і перевірка дублікатів мовчки не
  // робить нічого: екран відкривається окремим маршрутом, тобто стор від
  // `db-objects` тут не гарантований (холодний вхід, повернення назад).
  // Знайдено гардом, не оглядом: обидва рядки заходили як нові.
  useEffect(() => { void loadProperties() }, [loadProperties])

  const fileRef = useRef<HTMLInputElement>(null)
  const [rows, setRows] = useState<string[][] | null>(null)
  const [mapping, setMapping] = useState<(Field | null)[]>([])
  const [fileName, setFileName] = useState('')

  const headers = rows?.[0] ?? []
  const body = useMemo(() => rows?.slice(1) ?? [], [rows])
  const nameCol = mapping.indexOf('name')

  // Зайняті імена пропускаються, а не перезаписують: імпорт — це ДОДАВАННЯ, і
  // мовчазне затирання наявного обʼєкта було б найдорожчою з можливих
  // інтерпретацій «імпортувати».
  const existing = useMemo(
    () => new Set(properties.map((p) => p.name.trim().toLowerCase())),
    [properties],
  )

  const parsed = useMemo(() => {
    if (nameCol < 0) return { ok: [] as Record<string, unknown>[], skipped: [] as string[], noName: 0 }
    const ok: Record<string, unknown>[] = []
    const skipped: string[] = []
    const seen = new Set<string>()
    let noName = 0
    for (const r of body) {
      const name = (r[nameCol] ?? '').trim()
      if (!name) { noName++; continue }
      const key = name.toLowerCase()
      if (existing.has(key) || seen.has(key)) { skipped.push(name); continue }
      seen.add(key)

      const val = (f: Field) => {
        const i = mapping.indexOf(f)
        return i >= 0 ? (r[i] ?? '').trim() : ''
      }
      const rawStatus = val('status').toLowerCase()
      const status: PropertyStatus = STATUS_ALIAS[rawStatus] ?? 'free'
      ok.push({
        db_id: dbId,
        name,
        floor: val('floor') || null,
        status,
        area_useful: num(val('area_useful')),
        area_total: num(val('area_total')),
        area_basis: 'total',
        rent_type: 'per_m2',
        rent_rate: num(val('rent_rate')),
        utilities_rate: num(val('utilities_rate')),
        sale_price: num(val('sale_price')),
        // Орендар має сенс лише в зайнятого: інакше в базі осідає «вільний
        // обʼєкт з орендарем» — саме та суміш, що вже їхала в експорт і на /v.
        tenant_name: status === 'occupied' ? (val('tenant_name') || null) : null,
        landlord_name: val('landlord_name') || null,
        address: val('address') || null,
        description: val('description') || null,
        has_parking: false,
        parking_spaces: 0,
        folder_id: null,
        utilities: null,
        lease_start_date: null,
        lease_end_date: null,
        sort_order: 0,
      })
    }
    return { ok, skipped, noName }
  }, [body, mapping, nameCol, dbId, existing])

  async function handleFile(file: File) {
    const text = await file.text()
    const grid = parseCsv(text)
    if (grid.length < 2) {
      showToast({ type: 'error', title: 'Порожній файл', subtitle: 'Потрібен рядок заголовків і хоча б один обʼєкт' })
      return
    }
    setFileName(file.name)
    setRows(grid)
    setMapping(autoMap(grid[0]))
    hapticSelection()
  }

  async function handleImport() {
    if (parsed.ok.length === 0 || offlineGuard()) return
    const base = properties.length
    const payloads = parsed.ok.map((p, i) => ({
      ...p, sort_order: (base + i + 1) * 100,
    })) as unknown as Omit<Property, 'id' | 'owner_id' | 'created_at' | 'updated_at' | 'photos'>[]
    hapticNotify('success')
    await createProperties(payloads)
  }

  const busy = loading

  return (
    <div className="scr bg-purple">
      <Header title="Імпорт із CSV" subtitle={db?.name} backLabel="Назад" />

      <div className="body has-flow-cta">
        {!rows ? (
          <>
            <div className="over"><span style={{ display: 'flex', alignItems: 'center', gap: 6 }}><IconFile size={14} color="var(--info)" />Файл</span></div>
            <div className="fg glass-s" style={{ margin: '0 12px 16px', padding: 'var(--pad-card)' }}>
              <div style={{ fontSize: 'var(--fs-foot)', color: 'var(--t2)', lineHeight: 'var(--lh-relax)' }}>
                Перший рядок — заголовки колонок. Якщо файл вивантажено з цього
                застосунку, колонки зіставляться самі.
              </div>
              <div style={{ fontSize: 'var(--fs-cap1)', color: 'var(--t3)', marginTop: 8 }}>
                Обовʼязкова лише «Назва». Обʼєкти з назвами, які вже є в базі, буде пропущено.
              </div>
            </div>
            <input
              ref={fileRef}
              type="file"
              accept=".csv,text/csv,text/plain"
              aria-label="Файл CSV"
              style={{ display: 'none' }}
              onChange={(e) => { const f = e.target.files?.[0]; if (f) void handleFile(f) }}
            />
            <button className="mbtn mbtn-flow" onClick={() => fileRef.current?.click()}>
              Обрати файл
            </button>
          </>
        ) : (
          <>
            <div className="over">
              <span style={{ display: 'flex', alignItems: 'center', gap: 6 }}><IconLayoutGrid size={14} color="var(--violet)" />Колонки</span>
              <span className="over-a">{fileName}</span>
            </div>
            <div className="fg glass-s" style={{ margin: '0 12px 16px' }}>
              {headers.map((h, i) => (
                <div className="fr" key={i}>
                  <span className="fr-l" style={{ minWidth: 0, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{h || `Колонка ${i + 1}`}</span>
                  <select
                    className="fr-i"
                    aria-label={`Куди імпортувати колонку «${h || i + 1}»`}
                    value={mapping[i] ?? ''}
                    onChange={(e) => {
                      const v = (e.target.value || null) as Field | null
                      setMapping((m) => m.map((x, j) => (j === i ? v : (v && x === v ? null : x))))
                    }}
                    style={{ marginLeft: 'auto', maxWidth: 190 }}
                  >
                    <option value="">— не імпортувати —</option>
                    {FIELDS.map((f) => <option key={f.id} value={f.id}>{f.label}</option>)}
                  </select>
                </div>
              ))}
            </div>

            <div className="over"><span style={{ display: 'flex', alignItems: 'center', gap: 6 }}><IconCheck size={14} color="var(--ok-fg)" />Буде імпортовано</span></div>
            <div className="fg glass-s" style={{ margin: '0 12px 16px', padding: 'var(--pad-card)' }}>
              {nameCol < 0 ? (
                <div style={{ display: 'flex', alignItems: 'center', gap: 6, color: 'var(--err-fg)', fontSize: 'var(--fs-foot)' }}>
                  <IconBan size={14} />Вкажіть, яка колонка містить назву
                </div>
              ) : (
                <>
                  <div style={{ fontSize: 'var(--fs-t3)', fontWeight: 'var(--fw-semi)', color: 'var(--t1)' }}>
                    {parsed.ok.length} {objectsWord(parsed.ok.length)}
                  </div>
                  {/* Пропуски перелічуються ПОІМЕННО, а не числом: «пропущено 7»
                      не дає жодного шляху дізнатись, що саме не заїхало. */}
                  {parsed.skipped.length > 0 && (
                    <div style={{ fontSize: 'var(--fs-cap1)', color: 'var(--t3)', marginTop: 6 }}>
                      Пропущено (назва вже є): {parsed.skipped.slice(0, 8).join(', ')}
                      {parsed.skipped.length > 8 ? ` та ще ${parsed.skipped.length - 8}` : ''}
                    </div>
                  )}
                  {parsed.noName > 0 && (
                    <div style={{ fontSize: 'var(--fs-cap1)', color: 'var(--t3)', marginTop: 4 }}>
                      Рядків без назви: {parsed.noName}
                    </div>
                  )}
                  {parsed.ok.length > 0 && (
                    <div style={{ fontSize: 'var(--fs-cap1)', color: 'var(--t3)', marginTop: 8 }}>
                      Перший: {String(parsed.ok[0].name)}
                      {parsed.ok[0].floor ? ` · ${String(parsed.ok[0].floor)} поверх` : ''}
                      {` · ${STATUS_LABELS[parsed.ok[0].status as PropertyStatus]}`}
                    </div>
                  )}
                </>
              )}
            </div>

            <div style={{ display: 'flex', gap: 8, margin: '0 12px 8px' }}>
              <button
                className="mbtn mbtn-flow"
                style={{ flex: 1 }}
                onClick={() => { setRows(null); setFileName(''); if (fileRef.current) fileRef.current.value = '' }}
              >
                Інший файл
              </button>
            </div>
            <button
              className={`mbtn success mbtn-flow ${parsed.ok.length === 0 || busy ? 'disabled' : ''} ${busy ? 'is-loading' : ''}`}
              disabled={parsed.ok.length === 0 || busy}
              aria-busy={busy}
              onClick={handleImport}
            >
              Імпортувати
            </button>
          </>
        )}
      </div>
    </div>
  )
}

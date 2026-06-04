'use client'

import { useState } from 'react'
import { useAppStore } from '@/store/appStore'
import { supabase } from '@/lib/supabase'
import Header from '@/components/ui/Header'
import Toggle from '@/components/ui/Toggle'
import { IconFileExport, IconFile, IconAdjustments } from '@/components/Icons'
import { calcRent, calcUtilities, DB_TYPE_LABELS, STATUS_LABELS, formatDate } from '@/lib/utils'
import type { Property, Database } from '@/types'

const FORMATS = [
  { id: 'pdf',   label: 'PDF Документ',   desc: 'Презентація з таблицею для клієнта', emoji: '📄' },
  { id: 'excel', label: 'Excel таблиця',   desc: 'Аналітика, розрахунки — .xlsx',      emoji: '📊' },
]

const TEMPLATES = [
  { id: 'classic', label: 'Класик',  accent: '#3478F6' },
  { id: 'modern',  label: 'Модерн',  accent: '#7B30EB' },
  { id: 'minimal', label: 'Мінімал', accent: '#1a1a2e' },
]

// ── PDF generation ────────────────────────────────────────────────────────────

async function generatePDF(
  db: Database,
  properties: Property[],
  template: string,
  onlyFree: boolean,
  showContacts: boolean,
  ownerName: string,
  ownerPhone: string,
  ownerEmail: string,
) {
  const { jsPDF, GState } = await import('jspdf')
  const { applyPlugin } = await import('jspdf-autotable')
  applyPlugin(jsPDF)

  const rows = onlyFree ? properties.filter(p => p.status === 'free') : properties
  const tpl = TEMPLATES.find(t => t.id === template) ?? TEMPLATES[0]
  const accent = tpl.accent

  // Hex → rgb tuple
  const hexRgb = (hex: string): [number, number, number] => {
    const n = parseInt(hex.slice(1), 16)
    return [(n >> 16) & 255, (n >> 8) & 255, n & 255]
  }
  const [ar, ag, ab] = hexRgb(accent)

  const doc = new jsPDF({ orientation: 'portrait', unit: 'mm', format: 'a4' })
  const W = doc.internal.pageSize.getWidth()

  // ── Header band ──────────────────────────────────────────────────────────
  doc.setFillColor(ar, ag, ab)
  doc.rect(0, 0, W, 38, 'F')

  // PropSpace label
  doc.setFont('helvetica', 'bold')
  doc.setFontSize(9)
  doc.setTextColor(255, 255, 255)
  doc.setGState(new GState({ opacity: 0.65 }))
  doc.text('PropSpace', 14, 10)
  doc.setGState(new GState({ opacity: 1 }))

  // DB name
  doc.setFontSize(18)
  doc.text(db.name, 14, 22)

  // Subtitle row
  doc.setFontSize(9)
  doc.setFont('helvetica', 'normal')
  doc.setGState(new GState({ opacity: 0.8 }))
  const typeLabel = DB_TYPE_LABELS[db.type] ?? db.type
  const dateStr = new Date().toLocaleDateString('uk-UA', { day: 'numeric', month: 'long', year: 'numeric' })
  doc.text(`${typeLabel}  ·  ${rows.length} об'єктів  ·  ${dateStr}`, 14, 30)
  doc.setGState(new GState({ opacity: 1 }))

  // ── Summary row ───────────────────────────────────────────────────────────
  const freeCount    = rows.filter(p => p.status === 'free').length
  const occupiedCount = rows.filter(p => p.status === 'occupied').length
  const saleCount    = rows.filter(p => p.status === 'for_sale').length

  const stats: [string, string, string][] = [
    ['Вільно', String(freeCount), '#34C759'],
    ['Зайнято', String(occupiedCount), '#FF9500'],
    ['Продаж', String(saleCount), '#5AC8FA'],
  ]
  const boxW = (W - 28) / 3
  stats.forEach(([label, val, color], i) => {
    const x = 14 + i * (boxW + 4)
    const [cr, cg, cb] = hexRgb(color)
    doc.setFillColor(245, 245, 250)
    doc.roundedRect(x, 44, boxW, 16, 2, 2, 'F')
    doc.setFillColor(cr, cg, cb)
    doc.rect(x, 44, 3, 16, 'F')
    doc.setFont('helvetica', 'bold')
    doc.setFontSize(13)
    doc.setTextColor(30, 30, 50)
    doc.text(val, x + 8, 54)
    doc.setFont('helvetica', 'normal')
    doc.setFontSize(7.5)
    doc.setTextColor(100, 100, 120)
    doc.text(label, x + 8, 58)
  })

  // ── Table ─────────────────────────────────────────────────────────────────
  const statusColor = (s: string) => {
    if (s === 'free')     return [52,  199, 89]  as [number,number,number]
    if (s === 'occupied') return [255, 149, 0]   as [number,number,number]
    return                       [90,  200, 250]  as [number,number,number]
  }

  const tableRows = rows.map(p => {
    const rent  = p.rent_rate && p.area_useful ? calcRent(p.area_useful, p.rent_rate, p.rent_type) : 0
    const utils = p.utilities_rate && p.area_total ? calcUtilities(p.area_total, p.utilities_rate) : 0
    const total = rent + utils
    return [
      p.name,
      p.floor ?? '—',
      STATUS_LABELS[p.status] ?? p.status,
      p.area_useful ? `${p.area_useful}` : '—',
      p.area_total  ? `${p.area_total}`  : '—',
      rent  ? `$${rent}`  : '—',
      utils ? `$${utils}` : '—',
      total ? `$${total}` : '—',
    ]
  })

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  ;(doc as unknown as any).autoTable({
    startY: 68,
    head: [["Назва", "Пов.", "Статус", "Корисна\nм²", "Загальна\nм²", "Оренда\n$/міс", "Комун.\n$/міс", "Разом\n$/міс"]],
    body: tableRows,
    styles: {
      font: 'helvetica',
      fontSize: 8.5,
      cellPadding: 3,
      textColor: [30, 30, 50],
      lineColor: [220, 220, 235],
      lineWidth: 0.2,
    },
    headStyles: {
      fillColor: [ar, ag, ab],
      textColor: [255, 255, 255],
      fontStyle: 'bold',
      fontSize: 8,
      halign: 'center',
    },
    alternateRowStyles: { fillColor: [248, 248, 252] },
    columnStyles: {
      0: { cellWidth: 45 },
      2: { halign: 'center' },
      3: { halign: 'right' },
      4: { halign: 'right' },
      5: { halign: 'right' },
      6: { halign: 'right' },
      7: { halign: 'right', fontStyle: 'bold' },
    },
    // Colour the Status cell
    didParseCell: (data: { section: string; column: { index: number }; row: { index: number }; cell: { styles: { fillColor: [number,number,number]; textColor: [number,number,number] } } }) => {
      if (data.section === 'body' && data.column.index === 2) {
        const status = rows[data.row.index]?.status
        const [r, g, b] = statusColor(status)
        data.cell.styles.fillColor = [r, g, b] as [number,number,number]
        data.cell.styles.textColor = [255, 255, 255]
      }
    },
  })

  // ── Footer (contacts) ─────────────────────────────────────────────────────
  if (showContacts && (ownerPhone || ownerEmail)) {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const finalY = (doc as unknown as any).lastAutoTable.finalY ?? 200
    const footerY = Math.min(finalY + 10, doc.internal.pageSize.getHeight() - 30)
    doc.setDrawColor(ar, ag, ab)
    doc.setLineWidth(0.4)
    doc.line(14, footerY, W - 14, footerY)
    doc.setFont('helvetica', 'bold')
    doc.setFontSize(8)
    doc.setTextColor(ar, ag, ab)
    doc.text('Контакти власника', 14, footerY + 6)
    doc.setFont('helvetica', 'normal')
    doc.setTextColor(60, 60, 80)
    const parts = [ownerName, ownerPhone, ownerEmail].filter(Boolean)
    doc.text(parts.join('  ·  '), 14, footerY + 12)
  }

  // ── Page numbers ──────────────────────────────────────────────────────────
  const pageCount = doc.getNumberOfPages()
  for (let i = 1; i <= pageCount; i++) {
    doc.setPage(i)
    doc.setFont('helvetica', 'normal')
    doc.setFontSize(7)
    doc.setTextColor(160, 160, 180)
    doc.text(`Стор. ${i} / ${pageCount}`, W - 14, doc.internal.pageSize.getHeight() - 6, { align: 'right' })
    doc.text('PropSpace', 14, doc.internal.pageSize.getHeight() - 6)
  }

  doc.save(`${db.name}_${new Date().toISOString().slice(0,10)}.pdf`)
}

// ── Excel generation ──────────────────────────────────────────────────────────

async function generateExcel(
  db: Database,
  properties: Property[],
  onlyFree: boolean,
) {
  const XLSX = await import('xlsx')
  const rows = onlyFree ? properties.filter(p => p.status === 'free') : properties

  // Sheet 1 — property list
  const sheetData: (string | number)[][] = []

  // Title block
  sheetData.push([`База: ${db.name}`])
  sheetData.push([`Тип: ${DB_TYPE_LABELS[db.type] ?? db.type}`])
  sheetData.push([`Дата: ${new Date().toLocaleDateString('uk-UA')}`])
  sheetData.push([`Об'єктів: ${rows.length}`])
  sheetData.push([]) // blank

  // Header
  const headers = [
    '№', 'Назва', 'Поверх', 'Статус',
    'Площа корисна (м²)', 'Площа загальна (м²)',
    'Ставка оренди', 'Тип ставки',
    'Оренда на місяць ($)', 'Комунальні на місяць ($)',
    'Разом на місяць ($)',
    'Паркінг', 'Місць паркінгу',
    'Опис', 'Додано',
  ]
  sheetData.push(headers)

  const headerRowIndex = sheetData.length // 1-based for xlsx (row 6)

  // Data rows
  rows.forEach((p, idx) => {
    const rent  = p.rent_rate && p.area_useful ? calcRent(p.area_useful, p.rent_rate, p.rent_type) : 0
    const utils = p.utilities_rate && p.area_total ? calcUtilities(p.area_total, p.utilities_rate) : 0
    sheetData.push([
      idx + 1,
      p.name,
      p.floor ?? '',
      STATUS_LABELS[p.status] ?? p.status,
      p.area_useful ?? '',
      p.area_total  ?? '',
      p.rent_rate   ?? '',
      p.rent_type === 'per_m2' ? '$/м²/міс' : 'фіксована $/міс',
      rent  || '',
      utils || '',
      rent + utils || '',
      p.has_parking ? 'Так' : 'Ні',
      p.parking_spaces || '',
      p.description ?? '',
      formatDate(p.created_at),
    ])
  })

  // Totals row
  const dataStart = headerRowIndex + 1
  const dataEnd   = sheetData.length
  if (rows.length > 0) {
    sheetData.push([
      '', 'РАЗОМ', '', '',
      { f: `SUM(E${dataStart}:E${dataEnd})` } as unknown as number,
      { f: `SUM(F${dataStart}:F${dataEnd})` } as unknown as number,
      '', '',
      { f: `SUM(I${dataStart}:I${dataEnd})` } as unknown as number,
      { f: `SUM(J${dataStart}:J${dataEnd})` } as unknown as number,
      { f: `SUM(K${dataStart}:K${dataEnd})` } as unknown as number,
      '', '', '', '',
    ])
  }

  const ws = XLSX.utils.aoa_to_sheet(sheetData)

  // Column widths
  ws['!cols'] = [
    { wch: 4  }, // №
    { wch: 30 }, // Назва
    { wch: 8  }, // Поверх
    { wch: 12 }, // Статус
    { wch: 18 }, // Площа корисна
    { wch: 18 }, // Площа загальна
    { wch: 14 }, // Ставка
    { wch: 18 }, // Тип ставки
    { wch: 18 }, // Оренда
    { wch: 18 }, // Комунальні
    { wch: 18 }, // Разом
    { wch: 10 }, // Паркінг
    { wch: 12 }, // Місць
    { wch: 35 }, // Опис
    { wch: 16 }, // Додано
  ]

  // Freeze header row so columns stay visible while scrolling
  ws['!freeze'] = { xSplit: 0, ySplit: headerRowIndex, topLeftCell: `A${headerRowIndex + 1}` }

  // Sheet 2 — summary by status
  const summaryData: (string | number)[][] = [
    ['Зведена таблиця', `${db.name}`],
    [],
    ['Статус', 'Кількість', 'Загальна площа (м²)', 'Сума оренди ($/міс)'],
  ]
  const statuses: Array<{ key: string; label: string }> = [
    { key: 'free',     label: 'Вільно'  },
    { key: 'occupied', label: 'Зайнято' },
    { key: 'for_sale', label: 'Продаж'  },
  ]
  statuses.forEach(({ key, label }) => {
    const group = properties.filter(p => p.status === key)
    const totalArea = group.reduce((s, p) => s + (p.area_useful ?? 0), 0)
    const totalRent = group.reduce((s, p) => {
      const r = p.rent_rate && p.area_useful ? calcRent(p.area_useful, p.rent_rate, p.rent_type) : 0
      return s + r
    }, 0)
    summaryData.push([label, group.length, totalArea, totalRent])
  })
  summaryData.push([
    'ВСЬОГО',
    properties.length,
    properties.reduce((s, p) => s + (p.area_useful ?? 0), 0),
    properties.reduce((s, p) => {
      const r = p.rent_rate && p.area_useful ? calcRent(p.area_useful, p.rent_rate, p.rent_type) : 0
      return s + r
    }, 0),
  ])

  const wsSummary = XLSX.utils.aoa_to_sheet(summaryData)
  wsSummary['!cols'] = [{ wch: 14 }, { wch: 12 }, { wch: 22 }, { wch: 22 }]

  const wb = XLSX.utils.book_new()
  XLSX.utils.book_append_sheet(wb, ws, 'Об\'єкти')
  XLSX.utils.book_append_sheet(wb, wsSummary, 'Зведена')

  XLSX.writeFile(wb, `${db.name}_${new Date().toISOString().slice(0,10)}.xlsx`)
}

// ── Screen component ──────────────────────────────────────────────────────────

export default function ExportScreen() {
  const { screenParams, showToast, user, databases } = useAppStore()
  const { dbId } = screenParams
  const [format, setFormat]           = useState('pdf')
  const [template, setTemplate]       = useState('classic')
  const [onlyFree, setOnlyFree]       = useState(false)
  const [contacts, setContacts]       = useState(true)
  const [loading, setLoading]         = useState(false)

  const db = databases.find(d => d.id === dbId)

  async function handleExport() {
    if (!dbId) { showToast({ type: 'error', title: 'Не вказано базу' }); return }
    setLoading(true)
    try {
      const { data: propertiesRaw, error } = await supabase
        .from('properties')
        .select('*, photos:property_photos(*)')
        .eq('db_id', dbId)
        .order('name')

      if (error) throw error
      const properties = (propertiesRaw ?? []) as Property[]
      const dbRecord = db ?? ({ name: 'База', type: 'business_center', color: 'purple' } as Database)

      if (format === 'pdf') {
        await generatePDF(
          dbRecord,
          properties,
          template,
          onlyFree,
          contacts,
          user ? `${user.first_name} ${user.last_name ?? ''}`.trim() : '',
          user?.phone ?? '',
          user?.email ?? '',
        )
        showToast({ type: 'success', title: 'PDF збережено ✓' })
      } else {
        await generateExcel(dbRecord, properties, onlyFree)
        showToast({ type: 'success', title: 'Excel збережено ✓' })
      }
    } catch (e) {
      showToast({ type: 'error', title: 'Помилка експорту', subtitle: (e as Error).message })
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="scr bg-teal">
      <Header title="Експорт" backLabel="Назад" />

      <div className="body">
        {/* Format */}
        <div className="over">
          <span style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
            <IconFileExport size={13} color="#7AB3FF" />Формат файлу
          </span>
        </div>
        <div className="format-list">
          {FORMATS.map((f) => (
            <div
              key={f.id}
              className={`format-card ${format === f.id ? 'sel' : ''}`}
              onClick={() => setFormat(f.id)}
            >
              <div className="format-ic glass-s">
                <span style={{ fontSize: 19 }}>{f.emoji}</span>
              </div>
              <div className="format-mn">
                <div className="format-n">{f.label}</div>
                <div className="format-s">{f.desc}</div>
              </div>
              {format === f.id && <div className="format-r">✓</div>}
            </div>
          ))}
        </div>

        {/* Template — PDF only */}
        {format === 'pdf' && (
          <>
            <div className="over" style={{ marginTop: 8 }}>
              <span style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                <IconFile size={13} color="#fb923c" />Стиль PDF
              </span>
            </div>
            <div className="tmpl-row">
              {TEMPLATES.map((t) => (
                <div
                  key={t.id}
                  className={`tmpl ${template === t.id ? 'sel' : ''}`}
                  onClick={() => setTemplate(t.id)}
                >
                  <div className="tmpl-ph">
                    <div style={{ height: 10, borderRadius: 3, background: t.accent, marginBottom: 5 }} />
                    <div className="tmpl-bar" style={{ width: '80%' }} />
                    <div className="tmpl-bar" style={{ width: '60%' }} />
                    <div style={{ flex: 1, background: '#f0f0f0', borderRadius: 3, marginTop: 4, minHeight: 20 }} />
                    <div className="tmpl-bar" style={{ width: '70%', marginTop: 4 }} />
                    <div className="tmpl-bar" style={{ width: '45%' }} />
                  </div>
                  <div className="tmpl-l">{t.label}</div>
                </div>
              ))}
            </div>
          </>
        )}

        {/* Options */}
        <div className="over" style={{ marginTop: 8 }}>
          <span style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
            <IconAdjustments size={13} color="#a78bfa" />Налаштування
          </span>
        </div>
        <div className="fg glass-s" style={{ margin: '0 12px 16px' }}>
          <div className="fr">
            <span className="fr-l">Тільки вільні об&apos;єкти</span>
            <Toggle value={onlyFree} onChange={setOnlyFree} />
          </div>
          {format === 'pdf' && (
            <div className="fr">
              <span className="fr-l">Контакти власника</span>
              <Toggle value={contacts} onChange={setContacts} />
            </div>
          )}
        </div>

        {/* Preview hint */}
        <div style={{
          margin: '0 12px 16px',
          padding: '12px 14px',
          borderRadius: 12,
          background: 'rgba(90,200,250,.08)',
          border: '0.5px solid rgba(90,200,250,.25)',
          fontSize: 12,
          color: 'var(--t3)',
          lineHeight: 1.5,
        }}>
          {format === 'pdf'
            ? '📄 PDF містить шапку з назвою бази, зведену статистику по статусах, таблицю об\'єктів з кольоровими статусами та підвал з контактами.'
            : '📊 Excel містить два аркуші: повний список об\'єктів з формулами підсумків та зведена таблиця по статусах.'
          }
        </div>

        <div style={{ height: 80 }} />
      </div>

      <button
        className={`mbtn ${loading ? 'is-loading' : ''}`}
        onClick={handleExport}
        disabled={loading}
      >
        {!loading && <IconFileExport size={18} />}
        {!loading && (format === 'pdf' ? 'Завантажити PDF' : 'Завантажити Excel')}
      </button>
    </div>
  )
}

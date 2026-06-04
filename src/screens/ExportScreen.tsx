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

  const H = doc.internal.pageSize.getHeight()
  const MARGIN = 14
  const COL_L = MARGIN           // left column x
  const COL_R = W / 2 + 2        // right column x
  const COL_W = W / 2 - MARGIN - 2

  const statusColor = (s: string): [number, number, number] => {
    if (s === 'free')     return [52,  199,  89]
    if (s === 'occupied') return [255, 149,   0]
    return                       [90,  200, 250]
  }

  // ── Page 1: compact summary table ─────────────────────────────────────────
  const tableRows = rows.map(p => {
    const rent  = p.rent_rate && p.area_useful ? calcRent(p.area_useful, p.rent_rate, p.rent_type) : 0
    const utils = p.utilities_rate && p.area_total ? calcUtilities(p.area_total, p.utilities_rate) : 0
    return [
      p.name,
      p.floor ?? '—',
      STATUS_LABELS[p.status] ?? p.status,
      p.area_useful  ? `${p.area_useful} м²`  : '—',
      p.area_total   ? `${p.area_total} м²`   : '—',
      p.rent_rate    ? (p.rent_type === 'per_m2' ? `${p.rent_rate} $/м²` : `${p.rent_rate} $/міс`) : '—',
      utils          ? `$${utils}`  : '—',
      rent + utils   ? `$${rent + utils}` : '—',
    ]
  })

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  ;(doc as unknown as any).autoTable({
    startY: 68,
    head: [['Назва', 'Пов.', 'Статус', 'Корисна', 'Загальна', 'Ставка', 'Комун.', 'Разом/міс']],
    body: tableRows,
    styles:     { font: 'helvetica', fontSize: 8, cellPadding: 2.5, textColor: [30, 30, 50], lineColor: [220, 220, 235], lineWidth: 0.2 },
    headStyles: { fillColor: [ar, ag, ab], textColor: [255, 255, 255], fontStyle: 'bold', fontSize: 7.5, halign: 'center' },
    alternateRowStyles: { fillColor: [248, 248, 252] },
    columnStyles: {
      0: { cellWidth: 42 },
      2: { halign: 'center' },
      3: { halign: 'right' },
      4: { halign: 'right' },
      5: { halign: 'right' },
      6: { halign: 'right' },
      7: { halign: 'right', fontStyle: 'bold' },
    },
    didParseCell: (data: { section: string; column: { index: number }; row: { index: number }; cell: { styles: { fillColor: [number,number,number]; textColor: [number,number,number] } } }) => {
      if (data.section === 'body' && data.column.index === 2) {
        const [r, g, b] = statusColor(rows[data.row.index]?.status)
        data.cell.styles.fillColor = [r, g, b]
        data.cell.styles.textColor = [255, 255, 255]
      }
    },
  })

  // ── Pages 2+: detailed card per property ──────────────────────────────────
  const drawPageHeader = (title: string) => {
    doc.setFillColor(ar, ag, ab)
    doc.rect(0, 0, W, 14, 'F')
    doc.setFont('helvetica', 'bold')
    doc.setFontSize(8)
    doc.setTextColor(255, 255, 255)
    doc.text('PropSpace  ·  ' + db.name, MARGIN, 9)
    doc.setFont('helvetica', 'normal')
    doc.text(title, W - MARGIN, 9, { align: 'right' })
  }

  const drawFieldRow = (label: string, value: string, x: number, y: number, w: number) => {
    doc.setFont('helvetica', 'normal')
    doc.setFontSize(7)
    doc.setTextColor(120, 120, 140)
    doc.text(label, x, y)
    doc.setFont('helvetica', 'bold')
    doc.setFontSize(9)
    doc.setTextColor(20, 20, 40)
    const lines = doc.splitTextToSize(value, w - 2)
    doc.text(lines.slice(0, 2), x, y + 5)
    return y + 5 + (lines.length > 1 ? 5 : 0)
  }

  rows.forEach((p, idx) => {
    doc.addPage()
    drawPageHeader(`Детальна картка об'єкту`)

    const rent  = p.rent_rate && p.area_useful ? calcRent(p.area_useful, p.rent_rate, p.rent_type) : 0
    const utils = p.utilities_rate && p.area_total ? calcUtilities(p.area_total, p.utilities_rate) : 0
    const total = rent + utils

    // ── Object title bar ──────────────────────────────────────────────────
    let y = 22
    doc.setFillColor(245, 245, 252)
    doc.roundedRect(MARGIN, y, W - MARGIN * 2, 18, 2, 2, 'F')

    // Status badge
    const [sr, sg, sb] = statusColor(p.status)
    doc.setFillColor(sr, sg, sb)
    doc.roundedRect(MARGIN + 2, y + 4, 22, 10, 2, 2, 'F')
    doc.setFont('helvetica', 'bold')
    doc.setFontSize(7)
    doc.setTextColor(255, 255, 255)
    doc.text(STATUS_LABELS[p.status] ?? p.status, MARGIN + 13, y + 10.5, { align: 'center' })

    // Object name
    doc.setFont('helvetica', 'bold')
    doc.setFontSize(13)
    doc.setTextColor(20, 20, 40)
    doc.text(p.name, MARGIN + 28, y + 12)

    // Object number
    doc.setFont('helvetica', 'normal')
    doc.setFontSize(8)
    doc.setTextColor(160, 160, 180)
    doc.text(`#${idx + 1}  ·  База: ${db.name}`, W - MARGIN, y + 8, { align: 'right' })
    doc.text(new Date(p.updated_at).toLocaleDateString('uk-UA'), W - MARGIN, y + 14, { align: 'right' })

    y += 26

    // ── Section: Площа ───────────────────────────────────────────────────
    doc.setFont('helvetica', 'bold')
    doc.setFontSize(8)
    doc.setTextColor(ar, ag, ab)
    doc.text('ПЛОЩА', MARGIN, y)
    doc.setDrawColor(ar, ag, ab)
    doc.setLineWidth(0.3)
    doc.line(MARGIN + 22, y - 1, W - MARGIN, y - 1)
    y += 5

    const areaLeft = p.area_useful ? `${p.area_useful} м²` : '—'
    const areaRight = p.area_total  ? `${p.area_total} м²`  : '—'
    const floorVal  = p.floor       ? `${p.floor} поверх`   : '—'

    let yL = drawFieldRow('Корисна площа', areaLeft,  COL_L, y, COL_W)
    let yR = drawFieldRow('Загальна площа', areaRight, COL_R, y, COL_W)
    y = Math.max(yL, yR) + 4
    yL = drawFieldRow('Поверх', floorVal, COL_L, y, COL_W)
    y = yL + 4

    // ── Section: Фінанси ─────────────────────────────────────────────────
    doc.setFont('helvetica', 'bold')
    doc.setFontSize(8)
    doc.setTextColor(ar, ag, ab)
    doc.text('ФІНАНСИ', MARGIN, y)
    doc.setLineWidth(0.3)
    doc.line(MARGIN + 26, y - 1, W - MARGIN, y - 1)
    y += 5

    const rentTypeLabel = p.rent_type === 'per_m2' ? '$/м²/міс' : 'фіксована $/міс'
    const rentRateVal   = p.rent_rate ? `${p.rent_rate} ${rentTypeLabel}` : '—'
    const monthlyRent   = rent  ? `$${rent}`  : '—'
    const monthlyUtils  = utils ? `$${utils}` : '—'
    const monthlyTotal  = total ? `$${total}` : '—'
    const utilsRate     = p.utilities_rate ? `${p.utilities_rate} $/м²/міс` : '—'

    yL = drawFieldRow('Ставка оренди', rentRateVal,  COL_L, y, COL_W)
    yR = drawFieldRow('Оренда на місяць', monthlyRent, COL_R, y, COL_W)
    y = Math.max(yL, yR) + 4

    yL = drawFieldRow('Ставка комунальних', utilsRate,   COL_L, y, COL_W)
    yR = drawFieldRow('Комунальні на місяць', monthlyUtils, COL_R, y, COL_W)
    y = Math.max(yL, yR) + 4

    // Total highlight box
    doc.setFillColor(ar, ag, ab)
    doc.setGState(new GState({ opacity: 0.08 }))
    doc.roundedRect(MARGIN, y, W - MARGIN * 2, 14, 2, 2, 'F')
    doc.setGState(new GState({ opacity: 1 }))
    doc.setFont('helvetica', 'normal')
    doc.setFontSize(8)
    doc.setTextColor(80, 80, 100)
    doc.text('Разом на місяць (оренда + комунальні):', MARGIN + 4, y + 9)
    doc.setFont('helvetica', 'bold')
    doc.setFontSize(13)
    doc.setTextColor(ar, ag, ab)
    doc.text(monthlyTotal, W - MARGIN - 4, y + 9, { align: 'right' })
    y += 20

    // ── Section: Паркінг ─────────────────────────────────────────────────
    doc.setFont('helvetica', 'bold')
    doc.setFontSize(8)
    doc.setTextColor(ar, ag, ab)
    doc.text('ПАРКІНГ', MARGIN, y)
    doc.setLineWidth(0.3)
    doc.line(MARGIN + 26, y - 1, W - MARGIN, y - 1)
    y += 5

    yL = drawFieldRow('Паркінг', p.has_parking ? 'Так' : 'Ні', COL_L, y, COL_W)
    yR = p.has_parking
      ? drawFieldRow('Кількість місць', String(p.parking_spaces || 0), COL_R, y, COL_W)
      : y
    y = Math.max(yL, yR) + 4

    // ── Section: Опис ────────────────────────────────────────────────────
    if (p.description) {
      doc.setFont('helvetica', 'bold')
      doc.setFontSize(8)
      doc.setTextColor(ar, ag, ab)
      doc.text('ОПИС', MARGIN, y)
      doc.setLineWidth(0.3)
      doc.line(MARGIN + 16, y - 1, W - MARGIN, y - 1)
      y += 5

      doc.setFont('helvetica', 'normal')
      doc.setFontSize(9)
      doc.setTextColor(40, 40, 60)
      const descLines = doc.splitTextToSize(p.description, W - MARGIN * 2)
      doc.text(descLines.slice(0, 8), MARGIN, y)
      y += descLines.slice(0, 8).length * 5 + 4
    }

    // ── Contacts footer ───────────────────────────────────────────────────
    if (showContacts && (ownerPhone || ownerEmail)) {
      const fY = Math.max(y + 6, H - 28)
      doc.setDrawColor(200, 200, 220)
      doc.setLineWidth(0.3)
      doc.line(MARGIN, fY, W - MARGIN, fY)
      doc.setFont('helvetica', 'bold')
      doc.setFontSize(7.5)
      doc.setTextColor(ar, ag, ab)
      doc.text('Контакти власника:', MARGIN, fY + 6)
      doc.setFont('helvetica', 'normal')
      doc.setTextColor(60, 60, 80)
      const parts = [ownerName, ownerPhone, ownerEmail].filter(Boolean)
      doc.text(parts.join('  ·  '), MARGIN + 40, fY + 6)
    }
  })

  // ── Page numbers on every page ─────────────────────────────────────────────
  const pageCount = doc.getNumberOfPages()
  for (let i = 1; i <= pageCount; i++) {
    doc.setPage(i)
    doc.setFont('helvetica', 'normal')
    doc.setFontSize(7)
    doc.setTextColor(160, 160, 180)
    doc.text(`${i} / ${pageCount}`, W - MARGIN, H - 5, { align: 'right' })
    if (i > 1) doc.text('PropSpace', MARGIN, H - 5)
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

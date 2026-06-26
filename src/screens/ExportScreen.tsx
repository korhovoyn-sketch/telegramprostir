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
  { id: 'pdf',   label: 'PDF Документ',   desc: 'Брендований PDF — зберігається та шериться', emoji: '📄' },
  { id: 'excel', label: 'Excel таблиця',   desc: 'Аналітика, розрахунки — .xlsx',               emoji: '📊' },
]

const TEMPLATES = [
  { id: 'classic', label: 'Класик',  accent: '#7AB3FF', accentDark: '#2255CC' },
  { id: 'modern',  label: 'Модерн',  accent: '#A87CFF', accentDark: '#5B1FD4' },
  { id: 'dark',    label: 'Нічний',  accent: '#5AC8FA', accentDark: '#1A6A8A' },
]

// ── save / share PDF blob on mobile ──────────────────────────────────────────

async function sharePDF(blob: Blob, fileName: string) {
  // iOS/Android: use native Web Share API so user can save to Files or send anywhere
  const file = new File([blob], fileName, { type: 'application/pdf' })
  if (
    typeof navigator !== 'undefined' &&
    typeof navigator.share === 'function' &&
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    (navigator as any).canShare?.({ files: [file] })
  ) {
    await navigator.share({ files: [file], title: fileName.replace('.pdf', '') })
    return
  }
  // Fallback: direct download (desktop / unsupported)
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = fileName
  document.body.appendChild(a)
  a.click()
  document.body.removeChild(a)
  setTimeout(() => URL.revokeObjectURL(url), 5000)
}

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
  const tpl  = TEMPLATES.find(t => t.id === template) ?? TEMPLATES[1]

  // ── Design tokens (dark-themed, matches the app) ──────────────────────────
  const BG:      [number,number,number] = [9,  8,  31]   // #09081f
  const CARD:    [number,number,number] = [20, 18, 52]   // #141234
  const BORDER:  [number,number,number] = [42, 38, 96]   // #2a2660
  const TXPRI:   [number,number,number] = [232,232,248]  // near-white
  const TXSEC:   [number,number,number] = [140,140,180]  // muted
  const TXMUT:   [number,number,number] = [80, 80, 120]  // very muted

  const hexRgb = (hex: string): [number,number,number] => {
    const n = parseInt(hex.slice(1), 16)
    return [(n >> 16) & 255, (n >> 8) & 255, n & 255]
  }
  const ACC = hexRgb(tpl.accent)      // accent bright
  const ACD = hexRgb(tpl.accentDark)  // accent dark (for fills)

  const STATUS_STYLE: Record<string, { bg: [number,number,number]; fg: [number,number,number] }> = {
    free:     { bg: [20, 60, 30],  fg: [52,  199, 89]  },
    occupied: { bg: [60, 35,  8],  fg: [255, 149,  0]  },
    for_sale: { bg: [10, 40, 70],  fg: [90,  200, 250] },
  }

  const doc = new jsPDF({ orientation: 'portrait', unit: 'mm', format: 'a4' })
  const W = doc.internal.pageSize.getWidth()
  const H = doc.internal.pageSize.getHeight()
  const M = 14  // margin

  // ── Embed Roboto for Cyrillic support ────────────────────────────────────────
  const toBase64 = (buf: ArrayBuffer): string => {
    const bytes = new Uint8Array(buf)
    const chunks: string[] = []
    const SZ = 8192
    for (let i = 0; i < bytes.length; i += SZ) {
      chunks.push(String.fromCharCode(...Array.from(bytes.subarray(i, i + SZ))))
    }
    return btoa(chunks.join(''))
  }
  const [regBuf, boldBuf] = await Promise.all([
    fetch('/fonts/Roboto-Regular.ttf').then(r => r.arrayBuffer()),
    fetch('/fonts/Roboto-Bold.ttf').then(r => r.arrayBuffer()),
  ])
  doc.addFileToVFS('Roboto-Regular.ttf', toBase64(regBuf))
  doc.addFont('Roboto-Regular.ttf', 'Roboto', 'normal')
  doc.addFileToVFS('Roboto-Bold.ttf', toBase64(boldBuf))
  doc.addFont('Roboto-Bold.ttf', 'Roboto', 'bold')
  doc.setFont('Roboto', 'normal')

  // Fill every new page with dark background via hook
  const fillBg = () => {
    doc.setFillColor(...BG)
    doc.rect(0, 0, W, H, 'F')
  }

  // ── PAGE 1: cover + summary table ────────────────────────────────────────
  fillBg()

  // Header gradient band
  doc.setFillColor(...ACD)
  doc.rect(0, 0, W, 44, 'F')
  // Diagonal accent stripe inside header
  doc.setFillColor(...ACC)
  doc.setGState(new GState({ opacity: 0.12 }))
  doc.triangle(W - 60, 0, W, 0, W, 44, 'F')
  doc.setGState(new GState({ opacity: 1 }))

  // "PropSpace" wordmark
  doc.setFont('Roboto', 'bold')
  doc.setFontSize(8)
  doc.setTextColor(...TXMUT)
  doc.text('PROPSPACE', M, 11)

  // DB name
  doc.setFontSize(20)
  doc.setTextColor(...TXPRI)
  const dbNameLines = doc.splitTextToSize(db.name, W - M * 2 - 20)
  doc.text(dbNameLines[0] as string, M, 26)

  // Subtitle
  doc.setFontSize(8.5)
  doc.setFont('Roboto', 'normal')
  doc.setTextColor(...TXSEC)
  const typeLabel = DB_TYPE_LABELS[db.type] ?? db.type
  const dateStr   = new Date().toLocaleDateString('uk-UA', { day: 'numeric', month: 'long', year: 'numeric' })
  doc.text(`${typeLabel}  ·  ${rows.length} об'єктів  ·  ${dateStr}`, M, 38)

  // Address (if any)
  if (db.address) {
    doc.setFontSize(7.5)
    doc.setTextColor(...TXMUT)
    doc.text('📍 ' + db.address, M, 50)
  }

  // ── Summary stat cards ─────────────────────────────────────────────────
  const freeCount     = rows.filter(p => p.status === 'free').length
  const occupiedCount = rows.filter(p => p.status === 'occupied').length
  const saleCount     = rows.filter(p => p.status === 'for_sale').length
  const totalRent     = rows.reduce((s, p) => {
    const r = p.rent_rate && p.area_useful ? calcRent(p.area_useful, p.rent_rate, p.rent_type) : 0
    return s + r
  }, 0)

  const cardY = db.address ? 56 : 48
  const cards: [string, string, [number,number,number]][] = [
    ['Вільно',  String(freeCount),     STATUS_STYLE.free.fg],
    ['Зайнято', String(occupiedCount), STATUS_STYLE.occupied.fg],
    ['Продаж',  String(saleCount),     STATUS_STYLE.for_sale.fg],
    ['Оренда',  `$${totalRent.toLocaleString('uk-UA')}`, ACC],
  ]
  const cardW = (W - M * 2 - 9) / 4
  cards.forEach(([label, val, color], i) => {
    const cx = M + i * (cardW + 3)
    doc.setFillColor(...CARD)
    doc.roundedRect(cx, cardY, cardW, 18, 2, 2, 'F')
    doc.setDrawColor(...BORDER)
    doc.setLineWidth(0.3)
    doc.roundedRect(cx, cardY, cardW, 18, 2, 2, 'S')
    doc.setFont('Roboto', 'bold')
    doc.setFontSize(14)
    doc.setTextColor(...color)
    doc.text(val, cx + cardW / 2, cardY + 11, { align: 'center' })
    doc.setFont('Roboto', 'normal')
    doc.setFontSize(7)
    doc.setTextColor(...TXSEC)
    doc.text(label, cx + cardW / 2, cardY + 16, { align: 'center' })
  })

  // ── Summary table ─────────────────────────────────────────────────────
  const tableY = cardY + 24

  const tableRows = rows.map(p => {
    const rent  = p.rent_rate && p.area_useful ? calcRent(p.area_useful, p.rent_rate, p.rent_type) : 0
    const utils = p.utilities_rate && p.area_total ? calcUtilities(p.area_total, p.utilities_rate) : 0
    return [
      p.name,
      p.floor ?? '—',
      STATUS_LABELS[p.status] ?? p.status,
      p.area_useful ? `${p.area_useful}` : '—',
      p.area_total  ? `${p.area_total}`  : '—',
      p.rent_rate   ? `${p.rent_rate}${p.rent_type === 'per_m2' ? '/м²' : ''}` : '—',
      utils ? `$${utils}`  : '—',
      rent + utils ? `$${rent + utils}` : '—',
    ]
  })

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  ;(doc as unknown as any).autoTable({
    startY: tableY,
    head: [['Назва', 'Пов.', 'Статус', 'Корисна', 'Загальна', 'Ставка', 'Комун.', 'Разом/міс']],
    body: tableRows,
    styles: {
      font: 'Roboto',
      fontSize: 8,
      cellPadding: 2.8,
      textColor: TXPRI,
      lineColor: BORDER,
      lineWidth: 0.2,
      fillColor: BG,
    },
    headStyles: {
      fillColor: ACD,
      textColor: [255, 255, 255],
      fontStyle: 'bold',
      fontSize: 7.5,
      halign: 'center',
    },
    alternateRowStyles: { fillColor: CARD },
    columnStyles: {
      0: { cellWidth: 40 },
      2: { halign: 'center' },
      3: { halign: 'right' },
      4: { halign: 'right' },
      5: { halign: 'right' },
      6: { halign: 'right' },
      7: { halign: 'right', fontStyle: 'bold' },
    },
    didParseCell: (data: {
      section: string; column: { index: number }; row: { index: number }
      cell: { styles: { fillColor: [number,number,number]; textColor: [number,number,number]; fontStyle: string } }
    }) => {
      if (data.section === 'body' && data.column.index === 2) {
        const s  = rows[data.row.index]?.status
        const st = STATUS_STYLE[s] ?? STATUS_STYLE.free
        data.cell.styles.fillColor = st.bg
        data.cell.styles.textColor = st.fg
        data.cell.styles.fontStyle = 'bold'
      }
      if (data.section === 'body' && data.column.index === 7) {
        data.cell.styles.textColor = ACC
      }
    },
  })

  // ── PAGES 2+: full detail card per property ───────────────────────────────
  const drawDetailPage = (p: Property, idx: number) => {
    doc.addPage()
    fillBg()

    const rent  = p.rent_rate && p.area_useful ? calcRent(p.area_useful, p.rent_rate, p.rent_type) : 0
    const utils = p.utilities_rate && p.area_total ? calcUtilities(p.area_total, p.utilities_rate) : 0
    const total = rent + utils
    const st    = STATUS_STYLE[p.status] ?? STATUS_STYLE.free

    // Slim top bar
    doc.setFillColor(...ACD)
    doc.rect(0, 0, W, 12, 'F')
    doc.setFont('Roboto', 'bold')
    doc.setFontSize(7.5)
    doc.setTextColor(255, 255, 255)
    doc.text('PROPSPACE  ·  ' + db.name.toUpperCase(), M, 8)
    doc.setFont('Roboto', 'normal')
    doc.setTextColor(...TXSEC)
    doc.text(`${idx + 1} / ${rows.length}`, W - M, 8, { align: 'right' })

    let y = 20

    // ── Object title card ────────────────────────────────────────────────
    doc.setFillColor(...CARD)
    doc.roundedRect(M, y, W - M * 2, 22, 3, 3, 'F')
    doc.setDrawColor(...BORDER)
    doc.setLineWidth(0.3)
    doc.roundedRect(M, y, W - M * 2, 22, 3, 3, 'S')

    // Status pill
    doc.setFillColor(...st.bg)
    doc.roundedRect(M + 4, y + 6, 24, 10, 2, 2, 'F')
    doc.setFont('Roboto', 'bold')
    doc.setFontSize(7)
    doc.setTextColor(...st.fg)
    doc.text(STATUS_LABELS[p.status] ?? p.status, M + 16, y + 12.5, { align: 'center' })

    // Object name
    doc.setFont('Roboto', 'bold')
    doc.setFontSize(14)
    doc.setTextColor(...TXPRI)
    const objNameLines = doc.splitTextToSize(p.name, W - M * 2 - 40)
    doc.text((objNameLines[0] as string), M + 32, y + 13)

    // Updated date
    doc.setFont('Roboto', 'normal')
    doc.setFontSize(7.5)
    doc.setTextColor(...TXMUT)
    doc.text(new Date(p.updated_at).toLocaleDateString('uk-UA'), W - M - 4, y + 8, { align: 'right' })

    y += 28

    // helper: draw a labelled field in a two-column grid
    const drawField = (label: string, value: string, x: number, fy: number, w: number): number => {
      doc.setFont('Roboto', 'normal')
      doc.setFontSize(7)
      doc.setTextColor(...TXMUT)
      doc.text(label.toUpperCase(), x, fy)
      doc.setFont('Roboto', 'bold')
      doc.setFontSize(9.5)
      doc.setTextColor(...TXPRI)
      const lines = doc.splitTextToSize(value || '—', w - 2)
      doc.text(lines.slice(0, 2) as string[], x, fy + 5.5)
      return fy + 5.5 + (lines.length > 1 ? 5 : 0)
    }

    // helper: section label with accent line
    const drawSection = (label: string, sy: number) => {
      doc.setFont('Roboto', 'bold')
      doc.setFontSize(7.5)
      doc.setTextColor(...ACC)
      doc.text(label, M, sy)
      doc.setDrawColor(...ACC)
      doc.setGState(new GState({ opacity: 0.35 }))
      doc.setLineWidth(0.3)
      doc.line(M + doc.getTextWidth(label) + 3, sy - 1, W - M, sy - 1)
      doc.setGState(new GState({ opacity: 1 }))
    }

    const CL = M           // left col x
    const CR = W / 2 + 2   // right col x
    const CW = W / 2 - M - 2

    // ── ПЛОЩА ─────────────────────────────────────────────────────────
    drawSection('ПЛОЩА', y)
    y += 5
    const yL1 = drawField('Корисна площа', p.area_useful ? `${p.area_useful} м²` : '—', CL, y, CW)
    const yR1 = drawField('Загальна площа', p.area_total  ? `${p.area_total} м²`  : '—', CR, y, CW)
    y = Math.max(yL1, yR1) + 3
    const yL2 = drawField('Поверх', p.floor ? `${p.floor} поверх` : '—', CL, y, CW)
    y = yL2 + 6

    // ── ОРЕНДА ────────────────────────────────────────────────────────
    drawSection('ОРЕНДА', y)
    y += 5
    const rentRateStr = p.rent_rate
      ? `${p.rent_rate} ${p.rent_type === 'per_m2' ? '$ / м² / міс' : '$ / міс (фіксована)'}`
      : '—'
    const yL3 = drawField('Ставка оренди',    rentRateStr,            CL, y, CW)
    const yR3 = drawField('Оренда на місяць', rent  ? `$${rent}`  : '—', CR, y, CW)
    y = Math.max(yL3, yR3) + 3
    const utilsRateStr = p.utilities_rate ? `${p.utilities_rate} $ / м² / міс` : '—'
    const yL4 = drawField('Ставка комунальних',    utilsRateStr,          CL, y, CW)
    const yR4 = drawField('Комунальні на місяць',  utils ? `$${utils}` : '—', CR, y, CW)
    y = Math.max(yL4, yR4) + 4

    // Total highlight box
    doc.setFillColor(...ACD)
    doc.setGState(new GState({ opacity: 0.22 }))
    doc.roundedRect(M, y, W - M * 2, 16, 3, 3, 'F')
    doc.setGState(new GState({ opacity: 1 }))
    doc.setDrawColor(...ACC)
    doc.setGState(new GState({ opacity: 0.4 }))
    doc.setLineWidth(0.3)
    doc.roundedRect(M, y, W - M * 2, 16, 3, 3, 'S')
    doc.setGState(new GState({ opacity: 1 }))

    doc.setFont('Roboto', 'normal')
    doc.setFontSize(8.5)
    doc.setTextColor(...TXSEC)
    doc.text('Разом на місяць (оренда + комунальні)', M + 5, y + 10)
    doc.setFont('Roboto', 'bold')
    doc.setFontSize(16)
    doc.setTextColor(...ACC)
    doc.text(total ? `$${total.toLocaleString('uk-UA')}` : '—', W - M - 4, y + 11, { align: 'right' })
    y += 22

    // ── ПАРКІНГ ───────────────────────────────────────────────────────
    drawSection('ПАРКІНГ', y)
    y += 5
    const yL5 = drawField('Наявність',      p.has_parking ? 'Так ✓' : 'Немає', CL, y, CW)
    const yR5 = p.has_parking
      ? drawField('Кількість місць', String(p.parking_spaces || 0),    CR, y, CW)
      : y
    y = Math.max(yL5, yR5) + 6

    // ── ОПИС ──────────────────────────────────────────────────────────
    if (p.description) {
      drawSection('ОПИС', y)
      y += 5
      doc.setFont('Roboto', 'normal')
      doc.setFontSize(9)
      doc.setTextColor(...TXSEC)
      const descLines = doc.splitTextToSize(p.description, W - M * 2)
      doc.text(descLines.slice(0, 10) as string[], M, y)
      y += descLines.slice(0, 10).length * 5 + 6
    }

    // ── Contacts ──────────────────────────────────────────────────────
    if (showContacts && (ownerPhone || ownerEmail)) {
      const fY = Math.max(y + 4, H - 26)
      doc.setDrawColor(...BORDER)
      doc.setLineWidth(0.3)
      doc.line(M, fY, W - M, fY)
      doc.setFont('Roboto', 'bold')
      doc.setFontSize(7.5)
      doc.setTextColor(...ACC)
      doc.text('Контакти власника:', M, fY + 7)
      doc.setFont('Roboto', 'normal')
      doc.setTextColor(...TXSEC)
      const parts = [ownerName, ownerPhone, ownerEmail].filter(Boolean)
      doc.text(parts.join('  ·  '), M + 42, fY + 7)
    }
  }

  rows.forEach((p, idx) => drawDetailPage(p, idx))

  // ── Page numbers ──────────────────────────────────────────────────────────
  const pageCount = doc.getNumberOfPages()
  for (let i = 1; i <= pageCount; i++) {
    doc.setPage(i)
    doc.setFont('Roboto', 'normal')
    doc.setFontSize(7)
    doc.setTextColor(...TXMUT)
    doc.text(`${i} / ${pageCount}`, W - M, H - 5, { align: 'right' })
    doc.text('prostir', M, H - 5)
  }

  // ── Save: use Web Share API on mobile, fallback to download ───────────────
  const fileName = `${db.name.replace(/[^a-zA-Zа-яА-ЯіІїЇєЄ0-9]/g, '_')}_${new Date().toISOString().slice(0, 10)}.pdf`
  const blob = new Blob([doc.output('arraybuffer')], { type: 'application/pdf' })
  await sharePDF(blob, fileName)
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
  const { screenParams, showToast, user, databases, isOnline } = useAppStore()
  const { dbId } = screenParams
  const [format, setFormat]           = useState('pdf')
  const [template, setTemplate]       = useState('classic')
  const [onlyFree, setOnlyFree]       = useState(false)
  const [contacts, setContacts]       = useState(true)
  const [loading, setLoading]         = useState(false)

  const db = databases.find(d => d.id === dbId)

  async function handleExport() {
    if (!dbId) { showToast({ type: 'error', title: 'Не вказано базу' }); return }
    if (!isOnline) { showToast({ type: 'error', title: 'Немає інтернету', subtitle: 'Експорт недоступний офлайн' }); return }
    setLoading(true)
    try {
      const { data: propertiesRaw, error } = await supabase
        .from('properties')
        .select('id,db_id,owner_id,name,floor,status,area_useful,area_total,rent_type,rent_rate,utilities_rate,has_parking,parking_spaces,description,address,utilities,sale_price,tenant_name,lease_start_date,lease_end_date,sort_order,share_token,share_expires_at,created_at,updated_at,photos:property_photos(id,property_id,storage_path,sort_order,created_at)')
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
                    <div className="tmpl-block" />
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

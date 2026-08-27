'use client'

import { useState } from 'react'
import { useAppStore } from '@/store/appStore'
import { offlineGuard } from '@/lib/offline'
import { supabase } from '@/lib/supabase'
import Header from '@/components/ui/Header'
import Toggle from '@/components/ui/Toggle'
import { IconFileExport, IconFile, IconAdjustments, IconChartBar, IconCheck } from '@/components/Icons'
import { withSortedPhotos, calcRentUtils, currencySymbol, rentUnitLabel, objectsWord, DB_TYPE_LABELS, STATUS_LABELS, formatLeaseDate, humanizeDbError, safeFileName, photoUrl } from '@/lib/utils'
import { UTILITY_META } from '@/lib/utilityMeta'
import type { Property, Database } from '@/types'

const FORMATS = [
  { id: 'pdf',   label: 'PDF Документ',   desc: 'Брендований PDF — зберігається та шериться', icon: <IconFile size={20} color="var(--info)" /> },
  { id: 'excel', label: 'Excel таблиця',   desc: 'Аналітика, розрахунки — .xlsx',               icon: <IconChartBar size={20} color="var(--ok-fg)" /> },
]

type Rgb = [number, number, number]

/**
 * Палітра сторінки — ЧАСТИНА теми, а не константа.
 *
 * Раніше тема задавала лише пару акцентів, а тло/картки/текст були намертво
 * темні (#09081f заливкою на КОЖНІЙ сторінці). Для документа, який власник
 * надсилає клієнту і час від часу друкує, це дорогий дефолт: чорний аркуш
 * зʼїдає картридж і на папері читається гірше за екран. Тому «Класик» і
 * «Модерн» тепер світлі, а темна подача лишається окремим вибором — «Нічний».
 */
interface PdfTheme {
  id: string
  label: string
  /** Акцент для заголовків секцій і сум. */
  accent: string
  /** Насичений акцент для шапки й заливок. */
  accentDark: string
  bg: Rgb
  card: Rgb
  border: Rgb
  /** Основний текст. */
  tx1: Rgb
  /** Другорядний. */
  tx2: Rgb
  /** Підписи полів. */
  tx3: Rgb
  /** Текст на заливці `accentDark` — на світлій темі шапка лишається кольоровою. */
  onAccent: Rgb
}

const TEMPLATES: PdfTheme[] = [
  {
    id: 'classic', label: 'Класик', accent: '#1D4ED8', accentDark: '#1E3A8A',
    bg: [255, 255, 255], card: [246, 248, 252], border: [214, 222, 235],
    tx1: [17, 24, 39], tx2: [71, 85, 105], tx3: [128, 141, 160], onAccent: [255, 255, 255],
  },
  {
    id: 'modern', label: 'Модерн', accent: '#6D28D9', accentDark: '#4C1D95',
    bg: [255, 255, 255], card: [249, 246, 254], border: [223, 214, 240],
    tx1: [24, 18, 43], tx2: [82, 71, 105], tx3: [140, 130, 160], onAccent: [255, 255, 255],
  },
  {
    id: 'dark', label: 'Нічний', accent: '#5AC8FA', accentDark: '#1A6A8A',
    bg: [9, 8, 31], card: [20, 18, 52], border: [42, 38, 96],
    tx1: [232, 232, 248], tx2: [140, 140, 180], tx3: [110, 110, 150], onAccent: [255, 255, 255],
  },
]

/** RGB-триплет шаблона → CSS. Один опис шаблона живить і PDF, і його превʼю. */
const rgbCss = (c: readonly number[]) => `rgb(${c[0]},${c[1]},${c[2]})`

// ── save / share generated file on mobile ────────────────────────────────────

const XLSX_MIME = 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'

/**
 * ЄДИНИЙ шлях віддачі згенерованого файлу — і він мусить бути єдиним.
 *
 * Webview Telegram ІГНОРУЄ атрибут `download`: замість збереження він просто
 * переходить на blob-URL. Для .xlsx це означає, що користувач бачив вміст
 * ZIP-контейнера (`xl/worksheets/sheet1.xml`, `xl/styles.xml`…) сирим текстом
 * прямо в застосунку — скріншот власника. PDF цього не мав лише тому, що йшов
 * через Web Share API; Excel зберігався `XLSX.writeFile()`, який усередині
 * клацає той самий мертвий `<a download>`.
 *
 * Тому обидва формати тепер ідуть сюди: спершу нативний шит «Поділитись»
 * (там є «Зберегти у Файли»), і лише як фолбек для десктопа — прямий лінк.
 */
async function shareFile(blob: Blob, fileName: string, mimeType: string) {
  const file = new File([blob], fileName, { type: mimeType })
  if (
    typeof navigator !== 'undefined' &&
    typeof navigator.share === 'function' &&
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    (navigator as any).canShare?.({ files: [file] })
  ) {
    await navigator.share({ files: [file], title: fileName.replace(/\.[^.]+$/, '') })
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

// ── Фото для PDF ──────────────────────────────────────────────────────────────

/** Головне фото + до трьох у смужці. Більше на сторінку А4 просто не лізе. */
const PHOTOS_PER_OBJECT = 4

/**
 * Пропорції двох боксів, у які лягають фото. Кадрування робиться ЗАЗДАЛЕГІДЬ
 * під них, а не кліпом усередині PDF: `doc.clip()` у jsPDF вимагає окремої
 * побудови шляху і `discardPath()`, і при найменшій помилці мовчки НЕ обрізає —
 * зображення тоді вилазить за рамку й накриває пів сторінки (спостережено).
 * Обрізаний заздалегідь кадр не може вилізти в принципі.
 */
const HERO_ASPECT = 182 / 52
const THUMB_ASPECT = 58 / 20

interface LoadedPhoto { hero: string; thumb: string; fmt: string }

/** Обрізає під задану пропорцію по центру (cover) і віддає dataURL. */
function cropTo(img: HTMLImageElement, aspect: number, outW: number): string {
  const cv = document.createElement('canvas')
  cv.width = outW
  cv.height = Math.round(outW / aspect)
  const ctx = cv.getContext('2d')!
  const srcAspect = img.naturalWidth / img.naturalHeight
  let sw = img.naturalWidth, sh = img.naturalHeight, sx = 0, sy = 0
  if (srcAspect > aspect) { sw = img.naturalHeight * aspect; sx = (img.naturalWidth - sw) / 2 }
  else { sh = img.naturalWidth / aspect; sy = (img.naturalHeight - sh) / 2 }
  ctx.drawImage(img, sx, sy, sw, sh, 0, 0, cv.width, cv.height)
  // JPEG якості .82 — компроміс між вагою файлу і тим, щоб фото не «сипалось»
  // на друку. PNG тут дав би вчетверо важчий документ ні за що.
  return cv.toDataURL('image/jpeg', 0.82)
}

/**
 * Тягне фото обʼєкта й переводить у dataURL для `doc.addImage`.
 *
 * Бакет `photos` публічний (той самий `photoUrl`, що малює застосунок), тож
 * підписані URL не потрібні. **Кожне фото — fail-open:** мережевий збій чи
 * прибраний файл НЕ мають валити весь експорт, інакше один осиротілий рядок
 * позбавляв би власника всього документа. Пропущене фото — просто менша
 * смужка, і це видно на око.
 */
async function loadPhotos(paths: string[]): Promise<LoadedPhoto[]> {
  const out = await Promise.all(paths.slice(0, PHOTOS_PER_OBJECT).map(async (path) => {
    try {
      const res = await fetch(photoUrl(path))
      if (!res.ok) return null
      const blob = await res.blob()
      const dataUrl = await new Promise<string>((resolve, reject) => {
        const fr = new FileReader()
        fr.onload = () => resolve(fr.result as string)
        fr.onerror = () => reject(fr.error)
        fr.readAsDataURL(blob)
      })
      const img = await new Promise<HTMLImageElement | null>((resolve) => {
        const im = new Image()
        im.onload = () => resolve(im)
        im.onerror = () => resolve(null)
        im.src = dataUrl
      })
      if (!img?.naturalWidth || !img.naturalHeight) return null
      return {
        hero: cropTo(img, HERO_ASPECT, 1100),
        thumb: cropTo(img, THUMB_ASPECT, 420),
        fmt: 'JPEG',
      }
    } catch {
      return null
    }
  }))
  return out.filter((p): p is LoadedPhoto => p !== null)
}

// ── PDF generation ────────────────────────────────────────────────────────────

/** Паркінг тримає `utilities_rate` як ПЛАСКУ СУМУ, решта — як ставку $/м².
 *  Рядок обʼєкта цього не розрізняє, тож одиницю задає тип бази. */
const isFlat = (db: Database) => db.type === 'parking'

async function generatePDF(
  db: Database,
  properties: Property[],
  template: string,
  onlyFree: boolean,
  showContacts: boolean,
  ownerName: string,
  ownerPhone: string,
  ownerEmail: string,
  // Символ валюти ВЛАСНИКА. Раніше тут скрізь стояв literal '$', тож власник,
  // який веде ціни в ₴/€, завантажував звіт із чужою валютою — той самий клас,
  // що вже ловили на публічній /v (правило проєкту: ніколи literal '$').
  cur: string,
) {
  const isFlatUtils = isFlat(db)
  const { jsPDF, GState } = await import('jspdf')
  const { applyPlugin } = await import('jspdf-autotable')
  applyPlugin(jsPDF)

  const rows = onlyFree ? properties.filter(p => p.status === 'free') : properties
  const tpl  = TEMPLATES.find(t => t.id === template) ?? TEMPLATES[1]

  // ── Design tokens — з ТЕМИ, а не захардкоджені ────────────────────────────
  const BG     = tpl.bg
  const CARD   = tpl.card
  const BORDER = tpl.border
  const TXPRI  = tpl.tx1
  const TXSEC  = tpl.tx2
  const TXMUT  = tpl.tx3
  const isDark = tpl.id === 'dark'

  const hexRgb = (hex: string): Rgb => {
    const n = parseInt(hex.slice(1), 16)
    return [(n >> 16) & 255, (n >> 8) & 255, n & 255]
  }
  const ACC = hexRgb(tpl.accent)      // accent bright
  const ACD = hexRgb(tpl.accentDark)  // accent dark (for fills)

  // Статусна пігулка мусить читатись на СВОЄМУ тлі: на темній сторінці це
  // глухий колір + яскравий текст, на світлій — навпаки, світла плашка й
  // насичений текст. Одна пара на обидві теми давала або невидимий текст,
  // або чорний прямокутник посеред білого аркуша.
  const STATUS_STYLE: Record<string, { bg: Rgb; fg: Rgb }> = isDark
    ? {
        free:     { bg: [20, 60, 30], fg: [52, 199, 89] },
        occupied: { bg: [60, 35,  8], fg: [255, 149, 0] },
        for_sale: { bg: [10, 40, 70], fg: [90, 200, 250] },
      }
    : {
        free:     { bg: [223, 246, 229], fg: [22, 122, 60] },
        occupied: { bg: [255, 238, 214], fg: [166, 90, 0] },
        for_sale: { bg: [222, 240, 253], fg: [17, 94, 145] },
      }

  const doc = new jsPDF({ orientation: 'portrait', unit: 'mm', format: 'a4' })
  const W = doc.internal.pageSize.getWidth()
  const H = doc.internal.pageSize.getHeight()
  const M = 14  // margin

  // Один форматер на весь документ. Плитка «Оренда» на обкладинці розділяла
  // тисячі, а ті самі гроші в таблиці й на сторінці обʼєкта — ні: «$26 800»
  // проти «$25000» в одному файлі читалось як два різні документи.
  const money = (n: number) => `${cur}${n.toLocaleString('uk-UA')}`
  // Ставка несе ОДИНИЦЮ, а не речення: підпис поля вже сказав «Ставка
  // оренди», тож «25000 $ / міс (фіксована)» повторював сам себе, а пробіли
  // навколо скісних рвали число й одиницю на три окремі слова.
  const rateOf = (n: number, type: string) =>
    `${n.toLocaleString('uk-UA')} ${cur}/${type === 'per_m2' ? 'м²' : type === 'per_day' ? 'добу' : 'міс'}`

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
  // `fetch` НЕ кидає на 404 — він віддає `ok:false` і тіло сторінки помилки.
  // Саме через це відсутність шрифтів була невидимою: замість файлу в VFS
  // лягала HTML-сторінка 404, jsPDF падав уже десь усередині, і користувач не
  // отримував ані PDF, ані зрозумілої причини. Шрифти обовʼязкові — весь
  // інтерфейс українською, а вбудовані шрифти jsPDF кирилиці не мають.
  const [regRes, boldRes] = await Promise.all([
    fetch('/fonts/Roboto-Regular.ttf'),
    fetch('/fonts/Roboto-Bold.ttf'),
  ])
  if (!regRes.ok || !boldRes.ok) {
    throw new Error('Не вдалося завантажити шрифт для PDF')
  }
  const [regBuf, boldBuf] = await Promise.all([regRes.arrayBuffer(), boldRes.arrayBuffer()])
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

  // Смуга росте під адресу: тримати адресу ПІД смугою означало лишити її
  // самотнім рядком на білому між шапкою і плитками — вона читалась як
  // відірваний підпис, а не як частина шапки.
  const bandH = db.address ? 52 : 44

  // Header gradient band
  doc.setFillColor(...ACD)
  doc.rect(0, 0, W, bandH, 'F')
  // Diagonal accent stripe inside header
  doc.setFillColor(...ACC)
  doc.setGState(new GState({ opacity: 0.12 }))
  doc.triangle(W - 60, 0, W, 0, W, bandH, 'F')
  doc.setGState(new GState({ opacity: 1 }))

  // "PropSpace" wordmark
  doc.setFont('Roboto', 'bold')
  doc.setFontSize(8)
  // Текст НА кольоровій смузі бере власний колір теми: `TXMUT`/`TXSEC` — це
  // сірі теми СТОРІНКИ, і на синій заливці вони майже зникали.
  doc.setTextColor(...tpl.onAccent)
  doc.setGState(new GState({ opacity: 0.62 }))
  doc.text('PROPSPACE', M, 11)
  doc.setGState(new GState({ opacity: 1 }))

  // DB name
  doc.setFontSize(20)
  // `TXPRI` — колір тексту СТОРІНКИ (#111827), а назва лежить на кольоровій
  // смузі: заміряно 1.63:1, тобто заголовок усього документа був фактично
  // нечитабельний. На смузі колір може бути лише `onAccent` — те саме
  // правило, що вже застосоване до вордмарка й підзаголовка нижче.
  doc.setTextColor(...tpl.onAccent)
  const dbNameLines = doc.splitTextToSize(db.name, W - M * 2 - 20)
  doc.text(dbNameLines[0] as string, M, 26)

  // Subtitle
  doc.setFontSize(8.5)
  doc.setFont('Roboto', 'normal')
  doc.setTextColor(...tpl.onAccent)
  doc.setGState(new GState({ opacity: 0.78 }))
  const typeLabel = DB_TYPE_LABELS[db.type] ?? db.type
  const dateStr   = new Date().toLocaleDateString('uk-UA', { day: 'numeric', month: 'long', year: 'numeric' })
  doc.text(`${typeLabel}  ·  ${rows.length} ${objectsWord(rows.length)}  ·  ${dateStr}`, M, 38)
  doc.setGState(new GState({ opacity: 1 }))

  // Address (if any) — без емодзі: у вбудованому Roboto гліфа «📍» немає,
  // тож він друкувався порожнечею, і рядок починався з видимого відступу.
  if (db.address) {
    doc.setFontSize(7.5)
    doc.setTextColor(...tpl.onAccent)
    doc.setGState(new GState({ opacity: 0.62 }))
    doc.text(doc.splitTextToSize(db.address, W - M * 2)[0] as string, M, 47)
    doc.setGState(new GState({ opacity: 1 }))
  }

  // ── Summary stat cards ─────────────────────────────────────────────────
  const freeCount     = rows.filter(p => p.status === 'free').length
  const occupiedCount = rows.filter(p => p.status === 'occupied').length
  const saleCount     = rows.filter(p => p.status === 'for_sale').length
  // total (нормалізований до місяця) мінус utils, НЕ сире .rent — інакше
  // per_day-обʼєкт додав би сюди добову ставку, а не місячний еквівалент.
  const totalRent     = rows.reduce((s, p) => {
    const { total, utils } = calcRentUtils(p.area_useful, p.area_total, p.rent_rate, p.rent_type, p.utilities_rate, p.area_basis, isFlatUtils)
    return s + (total - utils)
  }, 0)

  const cardY = bandH + 12
  const cards: [string, string, [number,number,number]][] = [
    ['Вільно',  String(freeCount),     STATUS_STYLE.free.fg],
    ['Зайнято', String(occupiedCount), STATUS_STYLE.occupied.fg],
    ['Продаж',  String(saleCount),     STATUS_STYLE.for_sale.fg],
    ['Оренда',  money(totalRent), ACC],
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
    const { utils, total } = calcRentUtils(p.area_useful, p.area_total, p.rent_rate, p.rent_type, p.utilities_rate, p.area_basis, isFlatUtils)
    return [
      p.name,
      p.floor ?? '—',
      STATUS_LABELS[p.status] ?? p.status,
      p.area_useful ? `${p.area_useful}` : '—',
      p.area_total  ? `${p.area_total}`  : '—',
      p.rent_rate   ? `${p.rent_rate.toLocaleString('uk-UA')}${p.rent_type === 'fixed' ? '' : rentUnitLabel(p.rent_type)}` : '—',
      utils ? money(utils) : '—',
      // total — з calcRentUtils, УЖЕ нормалізований до місяця (per_day
      // множиться на 30 всередині) — рахувати rent+utils тут САМОСТІЙНО
      // означало б знову змішати добову ставку з місячними експлуатаційними.
      total ? money(total) : '—',
    ]
  })

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  ;(doc as unknown as any).autoTable({
    startY: tableY,
    head: [['Назва', 'Пов.', 'Статус', 'Корисна', 'Розрах.', 'Ставка', 'Експл.', 'Разом/міс']],
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
  const drawDetailPage = (p: Property, idx: number, shots: LoadedPhoto[]) => {
    doc.addPage()
    fillBg()

    const { utils, total } = calcRentUtils(p.area_useful, p.area_total, p.rent_rate, p.rent_type, p.utilities_rate, p.area_basis, isFlatUtils)
    const st    = STATUS_STYLE[p.status] ?? STATUS_STYLE.free

    // Slim top bar
    doc.setFillColor(...ACD)
    doc.rect(0, 0, W, 12, 'F')
    doc.setFont('Roboto', 'bold')
    doc.setFontSize(7.5)
    doc.setTextColor(255, 255, 255)
    doc.text('PROPSPACE  ·  ' + db.name.toUpperCase(), M, 8)
    doc.setFont('Roboto', 'normal')
    doc.setTextColor(...tpl.onAccent)
    doc.setGState(new GState({ opacity: 0.7 }))
    doc.text(`Обʼєкт ${idx + 1} з ${rows.length}`, W - M, 8, { align: 'right' })
    doc.setGState(new GState({ opacity: 1 }))

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
    // `suffix` малюється ПІСЛЯ значення приглушеним і тонким — саме тому це
    // не частина рядка значення: маркер бази розрахунку в тій самій жирній
    // подачі читався як друге значення поля, а не як позначка на першому.
    const drawField = (label: string, value: string, x: number, fy: number, w: number, suffix?: string): number => {
      doc.setFont('Roboto', 'normal')
      doc.setFontSize(7)
      doc.setTextColor(...TXMUT)
      doc.text(label.toUpperCase(), x, fy)
      doc.setFont('Roboto', 'bold')
      doc.setFontSize(9.5)
      doc.setTextColor(...TXPRI)
      const lines = doc.splitTextToSize(value || '—', w - 2)
      doc.text(lines.slice(0, 2) as string[], x, fy + 5.5)
      if (suffix && lines.length === 1) {
        // Ширину значення міряємо ПОКИ активний його власний шрифт:
        // `getTextWidth` рахує за поточним кеглем, тож замір після переходу на
        // 7pt дав би ширину чужого рядка й підпис поїхав би на значення.
        const vw = doc.getTextWidth(lines[0] as string)
        doc.setFont('Roboto', 'normal')
        doc.setFontSize(7)
        doc.setTextColor(...TXMUT)
        doc.text(suffix, x + vw + 5, fy + 5.5)
      }
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
    // Ритм рядків. Було 3мм між парами, тобто підпис наступного поля стояв
    // упритул під значенням попереднього і читався як його продовження
    // («100 м²  /  ПОВЕРХ»). Секційний відступ мусить бути помітно більшим
    // за внутрішній, інакше межі секцій зникають.
    const ROW = 6.5
    const SEC = 9

    // ── ПЛОЩА І РОЗТАШУВАННЯ ──────────────────────────────────────────
    drawSection('ПЛОЩА І РОЗТАШУВАННЯ', y)
    y += 5
    // Позначка бази розрахунку — не декор: саме вона каже, на яку з двох площ
    // множиться ставка $/м². Без неї читач бачить дві площі й суму, і не може
    // звести їх між собою.
    // Маркер бази йде до ЗНАЧЕННЯ, а не в підпис: у підписі він читався як
    // друга назва поля («КОРИСНА ПЛОЩА  БАЗА РОЗРАХУНКУ») і плутав.
    const basis = p.area_basis ?? 'total'
    const areaVal = (v: number | null | undefined) => (v ? `${v} м²` : '—')
    const basisMark = (which: 'useful' | 'total') => (basis === which ? 'база розрахунку' : undefined)
    const yL1 = drawField('Корисна площа', areaVal(p.area_useful), CL, y, CW, basisMark('useful'))
    const yR1 = drawField('Розрахункова площа', areaVal(p.area_total), CR, y, CW, basisMark('total'))
    y = Math.max(yL1, yR1) + ROW
    const yL2 = drawField('Поверх', p.floor ? `${p.floor} поверх` : '—', CL, y, CW)
    const yR2 = p.address ? drawField('Адреса', p.address, CR, y, CW) : y
    y = Math.max(yL2, yR2) + SEC

    // ── ОРЕНДАР І ДОГОВІР ─────────────────────────────────────────────
    // Обʼєкт із орендарем без ІМЕНІ орендаря — це half-документ: у застосунку
    // ця інформація на картці є, а в PDF її не було взагалі, як і дат
    // договору. Секція йде ПЕРЕД грошима, бо це перше, що питають.
    if (p.tenant_name || p.lease_start_date || p.lease_end_date) {
      drawSection('ОРЕНДАР', y)
      y += 5
      const leaseStr = p.lease_start_date || p.lease_end_date
        ? `${p.lease_start_date ? formatLeaseDate(p.lease_start_date) : '—'} – ${p.lease_end_date ? formatLeaseDate(p.lease_end_date) : '—'}`
        : '—'
      const yT1 = drawField('Орендар', p.tenant_name || '—', CL, y, CW)
      const yT2 = leaseStr === '—' ? y : drawField('Договір', leaseStr, CR, y, CW)
      y = Math.max(yT1, yT2) + SEC
    }

    // ── ПРОДАЖ ────────────────────────────────────────────────────────
    // Обʼєкт на продаж раніше діставав секцію «Оренда» з суцільними «—» і
    // великий блок «Разом на місяць: —», а ЦІНИ не показував ніде. Тобто
    // сторінка продажу була порожньою — найгірший випадок усього документа.
    if (p.status === 'for_sale' || p.sale_price) {
      drawSection('ПРОДАЖ', y)
      y += 5
      doc.setFillColor(...ACD)
      doc.setGState(new GState({ opacity: isDark ? 0.22 : 0.10 }))
      doc.roundedRect(M, y - 1, W - M * 2, 16, 3, 3, 'F')
      doc.setGState(new GState({ opacity: 1 }))
      doc.setFont('Roboto', 'normal')
      doc.setFontSize(8.5)
      doc.setTextColor(...TXSEC)
      doc.text('Ціна продажу', M + 5, y + 9)
      doc.setFont('Roboto', 'bold')
      doc.setFontSize(16)
      doc.setTextColor(...ACC)
      doc.text(p.sale_price ? money(p.sale_price) : '—', W - M - 4, y + 10, { align: 'right' })
      y += 22
    }

    // ── ОРЕНДА ────────────────────────────────────────────────────────
    // Тільки якщо є ЩО показати. Обʼєкт на продаж не має ані ставки, ані
    // експлуатаційних, тож раніше діставав секцію з чотирьох «—» і великий
    // блок «Разом на місяць: —» — половину сторінки порожнечі під цінником,
    // який щойно домалювали вище.
    const hasRent = !!(p.rent_rate || p.utilities_rate)
    if (hasRent) {
    drawSection('ОРЕНДА', y)
    y += 5
    const rentRateStr = p.rent_rate ? rateOf(p.rent_rate, p.rent_type) : '—'
    const yL3 = drawField('Ставка оренди',    rentRateStr,            CL, y, CW)
    // «на місяць» у підписі — для per_day сире `rent` лишається ДОБОВОЮ
    // ставкою (Ставка оренди рядком вище її й показує), тут потрібен
    // нормалізований еквівалент: total мінус utils.
    const monthlyRentOnly = total - utils
    const yR3 = drawField('Оренда на місяць', monthlyRentOnly ? money(monthlyRentOnly) : '—', CR, y, CW)
    y = Math.max(yL3, yR3)
    // Рядок експлуатаційних малюється, ЛИШЕ якщо в ньому є що читати. Обʼєкт
    // із фіксованою орендою без комуналки інакше діставав пару полів із двома
    // «—» — тобто підпис стверджував, що дані мали б бути, а їх нема.
    if (p.utilities_rate || utils) {
      y += ROW
      const yL4 = drawField('Ставка експлуатаційних',
        p.utilities_rate ? rateOf(p.utilities_rate, 'per_m2') : '—', CL, y, CW)
      const yR4 = drawField('Експлуатаційні на місяць', utils ? money(utils) : '—', CR, y, CW)
      y = Math.max(yL4, yR4)
    }
    y += 5

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
    doc.text('Разом на місяць (оренда + експлуатаційні)', M + 5, y + 10)
    doc.setFont('Roboto', 'bold')
    doc.setFontSize(16)
    doc.setTextColor(...ACC)
    doc.text(total ? money(total) : '—', W - M - 4, y + 11, { align: 'right' })
    y += 22
    }

    // ── ПАРКІНГ ───────────────────────────────────────────────────────
    drawSection('ПАРКІНГ', y)
    y += 5
    const yL5 = drawField('Наявність',      p.has_parking ? 'Так' : 'Немає', CL, y, CW)
    const yR5 = p.has_parking
      ? drawField('Кількість місць', String(p.parking_spaces || 0),    CR, y, CW)
      : y
    y = Math.max(yL5, yR5) + SEC

    // ── ЕКСПЛУАТАЦІЙНІ ПОСЛУГИ ────────────────────────────────────────
    // Список послуг є на картці обʼєкта в застосунку, але в документ не
    // потрапляв — а це саме те, про що питає орендар («світло є? газ є?»).
    const utilList = (p.utilities ?? [])
      .map((uid) => UTILITY_META.find((m) => m.id === uid)?.label)
      .filter((l): l is string => !!l)
    if (utilList.length > 0) {
      drawSection('ЕКСПЛУАТАЦІЙНІ ПОСЛУГИ', y)
      y += 5
      let px = M
      doc.setFont('Roboto', 'normal')
      doc.setFontSize(8)
      for (const label of utilList) {
        const wLbl = doc.getTextWidth(label) + 8
        if (px + wLbl > W - M) { px = M; y += 8 }
        doc.setFillColor(...CARD)
        doc.roundedRect(px, y - 4, wLbl, 7, 2, 2, 'F')
        doc.setDrawColor(...BORDER)
        doc.setLineWidth(0.2)
        doc.roundedRect(px, y - 4, wLbl, 7, 2, 2, 'S')
        doc.setTextColor(...TXSEC)
        doc.text(label, px + 4, y + 0.8)
        px += wLbl + 3
      }
      y += 10
    }

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

    // ── ФОТО ──────────────────────────────────────────────────────────
    // Фото тягнулись із БД разом з обʼєктом і мовчки викидались — документ
    // про нерухомість без жодного знімка. Головне велике + до трьох у смужці:
    // більше на А4 під рештою секцій просто не лишається місця.
    if (shots.length > 0) {
      drawSection('ФОТО', y)
      y += 5
      const gap = 3
      const fullW = W - M * 2
      const rest = shots.slice(1, 4)
      // Місце під контакти й колонтитул лишається за ними — інакше фото
      // налазить на підпис власника внизу сторінки.
      const room = H - 30 - y

      // Блок фото МАСШТАБУЄТЬСЯ під залишок сторінки, а не зникає по частинах.
      // Жорсткі висоти давали найгірший з можливих результатів: на щільній
      // сторінці смужка не влазила на кілька міліметрів і мовчки не малювалась
      // узагалі — тобто обʼєкт із трьома фото показував одне, і причину цього
      // не було видно ніде. Пропорції беруться з попереднього кропу, тож
      // однаковий множник на ширину й висоту їх зберігає.
      const wantH = fullW / HERO_ASPECT
        + (rest.length > 0 ? gap + (fullW - gap * 2) / 3 / THUMB_ASPECT : 0)
      const k = Math.min(1, room / wantH)

      // Нижче 0.55 знімок перестає щось показувати — краще чесно не малювати
      // блок, ніж лишити смужку висотою в рядок тексту.
      if (k >= 0.55) {
        const heroW = fullW * k
        const heroH = heroW / HERO_ASPECT
        // Зменшений блок ЦЕНТРУЄТЬСЯ: притиснутий до лівого поля, він читався
        // не як менше фото, а як зʼїхала верстка — решта сторінки йде від
        // краю до краю, і вужчий блок при лівому вирівнюванні лишає вирву
        // саме праворуч, куди око йде за наступним рядком.
        const hx = M + (fullW - heroW) / 2
        doc.addImage(shots[0].hero, shots[0].fmt, hx, y, heroW, heroH)
        doc.setDrawColor(...BORDER)
        doc.setLineWidth(0.3)
        doc.roundedRect(hx, y, heroW, heroH, 3, 3, 'S')
        y += heroH + gap

        if (rest.length > 0) {
          // Смужка ЗАВЖДИ на три колонки, скільки б фото не було: при діленні
          // на фактичну кількість одна мініатюра розтягувалась на всю ширину
          // і ставала вищою за головне фото.
          const tw = (heroW - gap * 2) / 3
          const th = tw / THUMB_ASPECT
          rest.forEach((sh, i) => {
            const x = hx + i * (tw + gap)
            doc.addImage(sh.thumb, sh.fmt, x, y, tw, th)
            doc.setDrawColor(...BORDER)
            doc.setLineWidth(0.3)
            doc.roundedRect(x, y, tw, th, 2, 2, 'S')
          })
          y += th + 4
        }
      }
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

  // Фото тягнуться ПАРАЛЕЛЬНО для всіх обʼєктів, а не по одному на сторінку:
  // послідовно 30 обʼєктів × 4 фото = 120 запитів у чергу, тобто десятки
  // секунд очікування з нерухомою кнопкою.
  const shotsByProperty = await Promise.all(
    // Порядок фото в документі мусить збігатись із застосунком і з /v:
    // вбудоване відношення приходить несортованим, тож перше фото — довільне.
    rows.map((p) => loadPhotos((withSortedPhotos(p).photos ?? []).map((ph) => ph.storage_path)))
  )
  rows.forEach((p, idx) => drawDetailPage(p, idx, shotsByProperty[idx]))

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
  const fileName = safeFileName(db.name, 'pdf')
  const blob = new Blob([doc.output('arraybuffer')], { type: 'application/pdf' })
  await shareFile(blob, fileName, 'application/pdf')
}
// ── Excel generation ──────────────────────────────────────────────────────────

async function generateExcel(
  db: Database,
  properties: Property[],
  onlyFree: boolean,
  cur: string,
) {
  const isFlatUtils = isFlat(db)
  const XLSX = await import('xlsx')
  const rows = onlyFree ? properties.filter(p => p.status === 'free') : properties

  // Sheet 1 — property list
  const sheetData: (string | number)[][] = []

  // Title block
  sheetData.push([`База: ${db.name}`])
  sheetData.push([`Тип: ${DB_TYPE_LABELS[db.type] ?? db.type}`])
  sheetData.push([`Дата: ${new Date().toLocaleDateString('uk-UA')}`])
  sheetData.push([`Обʼєктів: ${rows.length}`])
  sheetData.push([]) // blank

  // Header
  const headers = [
    '№', 'Назва', 'Поверх', 'Статус',
    // Орендар і договір були відсутні: на картці обʼєкта в застосунку вони є,
    // а в таблиці — ні, тож зведення «хто де сидить і до якого числа» з
    // експорту зробити було неможливо.
    'Орендар', 'Договір з', 'Договір до',
    'Площа корисна (м²)', 'Площа розрахункова (м²)', 'База розрахунку',
    'Ставка оренди', 'Тип ставки',
    `Оренда на місяць (${cur})`, `Експлуатаційні на місяць (${cur})`,
    `Разом на місяць (${cur})`,
    // Ціна продажу не потрапляла нікуди — обʼєкт на продаж їхав у файл із
    // порожніми орендними колонками і без жодної цифри.
    `Ціна продажу (${cur})`,
    'Паркінг', 'Місць паркінгу',
    'Адреса', 'Експлуатаційні послуги',
    'Опис', 'Додано',
  ]

  /**
   * Літера колонки за НАЗВОЮ заголовка, а не жорстким «E»/«I».
   *
   * Підсумковий рядок унизу підбиває SUM по колонках, і поки літери стояли в
   * коді константами, будь-яка вставка колонки посеред таблиці мовчки зсувала
   * суму на сусідній стовпець — помилка в ГРОШАХ, яку в готовому файлі видно
   * тільки якщо перерахувати вручну.
   */
  const colLetter = (header: string): string => {
    const i = headers.indexOf(header)
    return String.fromCharCode(65 + i)
  }
  sheetData.push(headers)

  const headerRowIndex = sheetData.length // 1-based for xlsx (row 6)

  // Data rows
  rows.forEach((p, idx) => {
    const { utils, total } = calcRentUtils(p.area_useful, p.area_total, p.rent_rate, p.rent_type, p.utilities_rate, p.area_basis, isFlatUtils)
    sheetData.push([
      idx + 1,
      p.name,
      p.floor ?? '',
      STATUS_LABELS[p.status] ?? p.status,
      p.tenant_name ?? '',
      p.lease_start_date ? formatLeaseDate(p.lease_start_date) : '',
      p.lease_end_date ? formatLeaseDate(p.lease_end_date) : '',
      p.area_useful ?? '',
      p.area_total  ?? '',
      (p.area_basis ?? 'total') === 'useful' ? 'корисна' : 'розрахункова',
      p.rent_rate   ?? '',
      p.rent_type === 'per_m2' ? `${cur}/м²/міс` : p.rent_type === 'per_day' ? `${cur}/добу` : `фіксована ${cur}/міс`,
      // «Оренда на місяць» — заголовок каже "на місяць", тож потрібен
      // нормалізований еквівалент (total - utils), НЕ сире rent (для per_day
      // це добова ставка — вона вже показана в «Ставка оренди»/«Тип ставки»).
      (total - utils) || '',
      utils || '',
      // total — нормалізований до місяця в calcRentUtils; rent+utils тут
      // самостійно знову змішав би добову ставку per_day з місячними
      // експлуатаційними в колонці, підписаній «Разом на місяць».
      total || '',
      p.sale_price || '',
      p.has_parking ? 'Так' : 'Ні',
      p.parking_spaces || '',
      p.address ?? '',
      (p.utilities ?? [])
        .map((uid) => UTILITY_META.find((m) => m.id === uid)?.label)
        .filter(Boolean).join(', '),
      p.description ?? '',
      formatLeaseDate(p.created_at),
    ])
  })

  // Totals row
  const dataStart = headerRowIndex + 1
  const dataEnd   = sheetData.length
  if (rows.length > 0) {
    // Рядок будується за ІНДЕКСОМ заголовка, а не позиційним переліком: інакше
    // додана колонка зсуває всі значення праворуч, і «РАЗОМ» опиняється не під
    // своїм стовпцем.
    const SUMMED = [
      'Площа корисна (м²)', 'Площа розрахункова (м²)',
      `Оренда на місяць (${cur})`, `Експлуатаційні на місяць (${cur})`,
      `Разом на місяць (${cur})`, `Ціна продажу (${cur})`,
    ]
    const totalsRow: (string | number)[] = headers.map((h, i) => {
      if (i === 1) return 'РАЗОМ'
      if (!SUMMED.includes(h)) return ''
      const L = colLetter(h)
      return { f: `SUM(${L}${dataStart}:${L}${dataEnd})` } as unknown as number
    })
    sheetData.push(totalsRow)
  }

  const ws = XLSX.utils.aoa_to_sheet(sheetData)

  // Column widths
  // Ширини — за НАЗВОЮ колонки, щоб додана колонка не зсувала всі решта.
  const COL_W: Record<string, number> = {
    '№': 4, 'Назва': 30, 'Поверх': 8, 'Статус': 12,
    'Орендар': 24, 'Договір з': 13, 'Договір до': 13,
    'Площа корисна (м²)': 18, 'Площа розрахункова (м²)': 20, 'База розрахунку': 16,
    'Ставка оренди': 14, 'Тип ставки': 18,
    [`Оренда на місяць (${cur})`]: 18,
    [`Експлуатаційні на місяць (${cur})`]: 22,
    [`Разом на місяць (${cur})`]: 18,
    [`Ціна продажу (${cur})`]: 18,
    'Паркінг': 10, 'Місць паркінгу': 12,
    'Адреса': 30, 'Експлуатаційні послуги': 32,
    'Опис': 35, 'Додано': 12,
  }
  ws['!cols'] = headers.map((h) => ({ wch: COL_W[h] ?? 14 }))

  // Freeze header row so columns stay visible while scrolling
  ws['!freeze'] = { xSplit: 0, ySplit: headerRowIndex, topLeftCell: `A${headerRowIndex + 1}` }

  // Sheet 2 — summary by status
  const summaryData: (string | number)[][] = [
    ['Зведена таблиця', `${db.name}`],
    [],
    ['Статус', 'Кількість', 'Розрахункова площа (м²)', `Сума оренди (${cur}/міс)`],
  ]
  const statuses: Array<{ key: string; label: string }> = [
    { key: 'free',     label: 'Вільно'  },
    { key: 'occupied', label: 'Зайнято' },
    { key: 'for_sale', label: 'Продаж'  },
  ]
  // Місячна ставка БЕЗ експлуатаційних: total (нормалізований до місяця в
  // calcRentUtils) мінус utils, а не сире .rent — для per_day .rent лишається
  // ДОБОВОЮ ставкою (навмисно, для показу поряд із «/добу»), і підсумовування
  // її напряму в колонку «Сума оренди ($/міс)» рахувало б $150/добу як $150/міс.
  const monthlyRentOnly = (p: Property) => {
    const { total, utils } = calcRentUtils(p.area_useful, p.area_total, p.rent_rate, p.rent_type, p.utilities_rate, p.area_basis, isFlatUtils)
    return total - utils
  }
  statuses.forEach(({ key, label }) => {
    const group = properties.filter(p => p.status === key)
    const totalArea = group.reduce((s, p) => s + (p.area_useful ?? 0), 0)
    const totalRent = group.reduce((s, p) => s + monthlyRentOnly(p), 0)
    summaryData.push([label, group.length, totalArea, totalRent])
  })
  summaryData.push([
    'ВСЬОГО',
    properties.length,
    properties.reduce((s, p) => s + (p.area_useful ?? 0), 0),
    properties.reduce((s, p) => {
      const r = monthlyRentOnly(p)
      return s + r
    }, 0),
  ])

  const wsSummary = XLSX.utils.aoa_to_sheet(summaryData)
  wsSummary['!cols'] = [{ wch: 14 }, { wch: 12 }, { wch: 22 }, { wch: 22 }]

  const wb = XLSX.utils.book_new()
  XLSX.utils.book_append_sheet(wb, ws, 'Обʼєкти')
  XLSX.utils.book_append_sheet(wb, wsSummary, 'Зведена')

  // НЕ `XLSX.writeFile()`: він усередині клацає `<a download>`, а webview
  // Telegram цей атрибут ігнорує — замість збереження відкривався blob-URL, і
  // користувач бачив ZIP-нутрощі .xlsx сирим текстом. Той самий шлях, що в PDF.
  const out = XLSX.write(wb, { bookType: 'xlsx', type: 'array' }) as ArrayBuffer
  await shareFile(new Blob([out], { type: XLSX_MIME }), safeFileName(db.name, 'xlsx'), XLSX_MIME)
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
    if (offlineGuard('Експорт недоступний офлайн')) return
    setLoading(true)
    try {
      const { data: propertiesRaw, error } = await supabase
        .from('properties')
        // share_token deliberately NOT selected: exported files travel outside
        // the app and must never carry live share credentials.
        //
        // `area_basis` тут ОБОВʼЯЗКОВИЙ, і його відсутність була грошовим
        // дефектом: `basisArea()` при `undefined` мовчки падає на РОЗРАХУНКОВУ
        // площу, тож обʼєкт, якому власник задав базою корисну, рахувався в
        // документі по іншій площі, ніж у застосунку. На 100/120 м² і $18/м²
        // це $1 800 на екрані проти $2 160 у PDF — 20% розбіжності у файлі,
        // який власник надсилає клієнту, без жодного натяку.
        .select('id,db_id,owner_id,name,floor,status,area_useful,area_total,area_basis,rent_type,rent_rate,utilities_rate,has_parking,parking_spaces,description,address,utilities,sale_price,tenant_name,lease_start_date,lease_end_date,sort_order,created_at,updated_at,photos:property_photos(id,property_id,storage_path,sort_order,created_at)')
        .eq('db_id', dbId)
        // Порядок мусить збігатися з застосунком (`useProperties` — sort_order),
        // інакше ручний «Змінити порядок» на документ не впливає ВЗАГАЛІ, а
        // лексикографічне сортування ще й ставить «Офіс 10» перед «Офіс 2».
        // Той самий клас міграція 040 вже виправила для публічної /v.
        .order('sort_order', { ascending: true })
        .order('created_at', { ascending: true })

      if (error) throw error
      const properties = (propertiesRaw ?? []) as Property[]

      // Nothing to export — a file with 0 rows is pointless. Tell the user
      // instead of downloading an empty PDF/Excel.
      const exportable = onlyFree ? properties.filter(p => p.status === 'free') : properties
      if (exportable.length === 0) {
        showToast({ type: 'error', title: 'Немає обʼєктів для експорту', subtitle: onlyFree ? 'У базі немає вільних обʼєктів' : 'Спершу додайте обʼєкти до бази' })
        return
      }

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
          currencySymbol(user?.currency),
        )
        showToast({ type: 'success', title: 'PDF збережено' })
      } else {
        await generateExcel(dbRecord, properties, onlyFree, currencySymbol(user?.currency))
        showToast({ type: 'success', title: 'Excel збережено' })
      }
    } catch (e) {
      showToast({ type: 'error', title: 'Помилка експорту', subtitle: humanizeDbError(e) })
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
            <IconFileExport size={14} color="var(--info)" />Формат файлу
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
                {f.icon}
              </div>
              <div className="format-mn">
                <div className="format-n">{f.label}</div>
                <div className="format-s">{f.desc}</div>
              </div>
              {format === f.id && <div className="format-r"><IconCheck size={16} /></div>}
            </div>
          ))}
        </div>

        {/* Template — PDF only */}
        {format === 'pdf' && (
          <>
            <div className="over" style={{ marginTop: 8 }}>
              <span style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                <IconFile size={14} color="#fb923c" />Стиль PDF
              </span>
            </div>
            <div className="tmpl-row">
              {TEMPLATES.map((t) => (
                <div
                  key={t.id}
                  className={`tmpl ${template === t.id ? 'sel' : ''}`}
                  onClick={() => setTemplate(t.id)}
                >
                  {/* Кольори превʼю беруться з ТОГО САМОГО опису шаблона, що
                      малює сам PDF. Доти вони були захардкоджені в CSS —
                      білий аркуш для всіх трьох, — тож «Нічний» показував
                      світлу сторінку: превʼю стверджувало протилежне тому, що
                      користувач отримає. */}
                  <div className="tmpl-ph" style={{ background: rgbCss(t.bg) }}>
                    <div style={{ height: 10, borderRadius: 3, background: t.accent, marginBottom: 5 }} />
                    <div className="tmpl-bar" style={{ width: '80%', background: rgbCss(t.tx3) }} />
                    <div className="tmpl-bar" style={{ width: '60%', background: rgbCss(t.tx3) }} />
                    <div className="tmpl-block" style={{ background: rgbCss(t.card), border: `.5px solid ${rgbCss(t.border)}` }} />
                    <div className="tmpl-bar" style={{ width: '70%', marginTop: 4, background: rgbCss(t.tx3) }} />
                    <div className="tmpl-bar" style={{ width: '45%', background: rgbCss(t.tx3) }} />
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
            <IconAdjustments size={14} color="var(--violet)" />Налаштування
          </span>
        </div>
        <div className="fg glass-s" style={{ margin: '0 12px 16px' }}>
          <div className="fr">
            <span className="fr-l">Тільки вільні обʼєкти</span>
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
          fontSize: 'var(--fs-cap1)',
          color: 'var(--t3)',
          lineHeight: 1.5,
        }}>
          {format === 'pdf'
            ? 'PDF містить шапку з назвою бази, зведену статистику по статусах, таблицю обʼєктів з кольоровими статусами та підвал з контактами.'
            : 'Excel містить два аркуші: повний список обʼєктів з формулами підсумків та зведена таблиця по статусах.'
          }
        </div>

        <div style={{ height: 80 }} />
      </div>

      <button
        className={`mbtn ${loading ? 'is-loading' : ''}`}
        onClick={handleExport}
        disabled={loading}
        aria-busy={loading}
      >
        {/* Іконка йде під час запиту (вона декоративна і `currentColor` робить
            її невидимою під `is-loading`), а ПІДПИС лишається: інакше кнопка
            втрачає доступну назву саме тоді, коли щось відбувається. */}
        {!loading && <IconFileExport size={18} />}
        {format === 'pdf' ? 'Завантажити PDF' : 'Завантажити Excel'}
      </button>
    </div>
  )
}

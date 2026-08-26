import { describe, it, expect } from 'vitest'
import { readFileSync, readdirSync, statSync } from 'node:fs'
import { join } from 'node:path'

// Іконки розповзлись саме так: чотири з них малювали власний <svg> повз базу,
// дашборд тримав окремий набір шляхів з іншою товщиною обведення, а по екранах
// були рукописні галочки й шеврони. Плюс чотирнадцять різних розмірів.
// Тест тримає три інваріанти: одна база, один набір, одна шкала розмірів.

// Парні розміри: 2px обведення на непарному боксі дає півпіксельні краї.
const SIZE_SCALE = new Set([12, 14, 16, 18, 20, 24, 26, 32, 34, 40])

// Векторна графіка, яка НЕ є іконкою: ілюстрації, діаграми, індикатори прогресу
// та публічна сторінка з власною версткою.
const VECTOR_ALLOWED = [
  'src/components/Icons.tsx',
  'src/components/ProxMascot.tsx',
  'src/components/Confetti.tsx',
  'src/app/v/page.tsx',
  'src/screens/SharingAnalyticsScreen.tsx',  // графік переглядів
  'src/screens/PhotoUploadScreen.tsx',       // кільце прогресу
]

function walk(dir: string, out: string[] = []): string[] {
  for (const name of readdirSync(dir)) {
    const p = join(dir, name)
    if (statSync(p).isDirectory()) walk(p, out)
    else if (/\.tsx$/.test(name)) out.push(p)
  }
  return out
}

const files = walk('src')

describe('система іконок', () => {
  it('розмір іконки — лише зі шкали', () => {
    const bad: string[] = []
    for (const file of files) {
      const txt = readFileSync(file, 'utf8')
      for (const m of txt.matchAll(/<(Icon[A-Za-z]+|Glass[A-Za-z]+)\s+[^>]*?size=\{(\d+)\}/g)) {
        const size = Number(m[2])
        if (!SIZE_SCALE.has(size)) bad.push(`${file}: <${m[1]} size={${size}}>`)
      }
    }
    expect(bad, `дозволені розміри: ${[...SIZE_SCALE].join(', ')}`).toEqual([])
  })

  it('іконки не малюють поза бібліотекою', () => {
    const bad: string[] = []
    for (const file of files) {
      if (VECTOR_ALLOWED.some((a) => file.endsWith(a))) continue
      if (readFileSync(file, 'utf8').includes('<svg')) bad.push(file)
    }
    expect(bad, 'нова іконка додається в Icons.tsx, а не інлайном на екрані').toEqual([])
  })

  /**
   * ЕМОДЗІ Й ТЕКСТОВІ ГЛІФИ — НЕ ІКОНКИ.
   *
   * Гард «іконки не малюють поза бібліотекою» стежив за рукописними `<svg>` і
   * тому не бачив ГІРШОГО варіанта: емодзі. Наскрізний аудит знайшов їх у
   * КОНТРОЛАХ — сегменти календаря платежів («📅 Поточні»/«🗂 Архів»), іконка
   * КОЖНОГО рядка сповіщень, картки формату експорту, — плюс сирі «✓» і «×»
   * у десяти місцях, включно з кнопкою скасування платежу.
   *
   * Емодзі гірші за власний `<svg>` двічі: вони кольорові там, де вся система
   * монохромна лінійна, і кожна платформа малює їх по-своєму — тобто вигляд
   * застосунку залежить від ОС користувача.
   *
   * ДОЗВОЛЕНО в порожніх станах (`empty-ic`) і в `ErrorBoundary`: там це
   * ІЛЮСТРАЦІЯ на пів екрана, а не іконка в рядку, і саме так це вже
   * задокументовано для `design-system-runtime`.
   */
  it('емодзі та ✓/× не вживаються як іконки', () => {
    const GLYPH = /[\u{1F300}-\u{1FAFF}\u{2600}-\u{27BF}\u{2B00}-\u{2BFF}\u{FE0F}]|✓|✔/u
    const bad: string[] = []
    for (const file of files.filter((f) => /\.tsx$/.test(f))) {
      if (/ErrorBoundary/.test(file)) continue
      readFileSync(file, 'utf8').split('\n').forEach((line, i) => {
        const code = line.replace(/\/\/.*$/, '').replace(/\{\/\*.*?\*\/\}/g, '')
        // Дозволено рівно там, де гліф — ІЛЮСТРАЦІЯ на пів екрана: порожній
        // стан (`empty-ic`), його `emptyIcon`, і картинка `RetryState`. Усе
        // інше — позиція іконки, тобто місце бібліотеки.
        // Дозволено, коли гліф — ІЛЮСТРАЦІЯ: порожній стан (`empty-ic`,
        // `emptyIcon`), картинка `RetryState` (`icon=`/`icon:`) або великий
        // декоративний блок публічної /v (`v-float`, кегль ≥32). Усе інше —
        // позиція ІКОНКИ, тобто місце бібліотеки.
        if (/empty-ic|emptyIcon|\bicon=|\bicon: '|\bicon = '|v-float|fontSize: (?:4[0-9]|[5-9][0-9]|3[2-9])|--fs-t1/.test(code)) return
        // Рядок блокового коментаря (` * …`, `/** … */`) — не код.
        if (/^\s*(\*|\/\*)/.test(line)) return
        const m = code.match(GLYPH)
        if (m) bad.push(`${file}:${i + 1}: «${m[0]}»`)
      })
    }
    expect(bad, 'гліф замість іконки з бібліотеки').toEqual([])
  })

  it('усі іконки бібліотеки йдуть через спільну базу', () => {
    const src = readFileSync('src/components/Icons.tsx', 'utf8')
    // Дозволені сирі <svg>: база Icon, база GlassGlyph і дві вкладки таббару
    // (контур + заливка, які CSS перехрещує).
    expect((src.match(/<svg/g) ?? []).length,
      'кожна нова іконка — <Icon>…</Icon>, а не власний <svg>').toBe(4)
    // Товщина обведення задається однією функцією. Виняток — strokeWidth="0"
    // на залитих гліфах (filled-варіант тієї ж іконки: заливка без контуру).
    const literalStrokes = (src.match(/strokeWidth="[\d.]+"/g) ?? []).filter((w) => w !== 'strokeWidth="0"')
    expect(literalStrokes, 'strokeFor(size) — єдине джерело ваги').toEqual([])
  })
})

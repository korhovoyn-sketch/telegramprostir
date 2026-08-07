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
  'src/screens/PropertyDetailScreen.tsx',    // 3D-герой картки
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

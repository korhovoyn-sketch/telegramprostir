import { describe, it, expect } from 'vitest'
import { readdirSync, readFileSync } from 'node:fs'
import { join } from 'node:path'

/**
 * `{число && <JSX/>}` ДРУКУЄ «0».
 *
 * У JSX `0 && <span/>` обчислюється в `0`, а React виводить число як текст.
 * Тож збережена площа чи ставка 0 малювалась у рядку обʼєкта літеральною «0»
 * замість того, щоб не малювати нічого. Форма читає такі поля як
 * `parseFloat(x) || undefined` (тобто 0 — «не вказано»), і всі поверхні мусять
 * вести себе так само: `hasArea(x)`, `x != null && x > 0` або `!!x`.
 *
 * Гард джерельний: рендером це не закрити — потрібен обʼєкт зі збереженим 0
 * на кожному з десятка екранів, а фікстури тримають лише «нормальні» числа.
 */
const NUMERIC_FIELDS = [
  'area_useful', 'area_total', 'property_area_useful', 'property_area_total',
  'rent_rate', 'property_rent_rate', 'utilities_rate', 'property_utilities_rate',
  'sale_price', 'property_sale_price',
]
const BARE_TRUTHY = new RegExp(String.raw`\{\s*(?:[\w.?]+\.)?(?:${NUMERIC_FIELDS.join('|')})\s*&&`, 'g')

function walk(dir: string, out: string[] = []): string[] {
  for (const e of readdirSync(dir, { withFileTypes: true })) {
    const full = join(dir, e.name)
    if (e.isDirectory()) walk(full, out)
    else if (full.endsWith('.tsx')) out.push(full)
  }
  return out
}

describe('JSX не друкує нуль', () => {
  it('регулярка впізнає погану форму і не чіпає добрі (антивакуум)', () => {
    const bad = ['{p.area_useful && (', '{ data.property_utilities_rate && <b/>', '{p.rent_rate &&']
    const good = ['{hasArea(p.area_useful) && (', '{p.rent_rate != null && (', '{p.rent_rate > 0 && (', '{!!p.rent_rate && (',
                  '{p.property_sale_price ? <a/> : null}']
    for (const s of bad) expect(s.match(BARE_TRUTHY), `мусить спрацювати: ${s}`).not.toBeNull()
    for (const s of good) expect(s.match(BARE_TRUTHY), `не мусить спрацювати: ${s}`).toBeNull()
  })

  it('жоден екран не вішає рядок на голу істинність числового поля', () => {
    const files = walk('src')
    expect(files.length, 'обхід src нічого не знайшов').toBeGreaterThan(40)
    const offenders: string[] = []
    for (const f of files) {
      readFileSync(f, 'utf8').split('\n').forEach((line, i) => {
        if (BARE_TRUTHY.test(line)) offenders.push(`${f}:${i + 1}: ${line.trim().slice(0, 100)}`)
        BARE_TRUTHY.lastIndex = 0
      })
    }
    expect(offenders, 'число && JSX друкує «0»').toEqual([])
  })
})

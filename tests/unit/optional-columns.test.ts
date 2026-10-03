import { describe, it, expect } from 'vitest'
import { readFileSync, readdirSync, statSync } from 'node:fs'
import { join, relative } from 'node:path'
import {
  isMissingOptionalColumn, stripOptionalKeys, stripOptionalSelect, withOptionalColumns,
} from '@/lib/optionalColumns'

/**
 * Ретрай без колонок, яких може ще не бути в базі (043 `folder_id`,
 * 064 `landlord_name`). Рантайм-доказ — `pre064-writes.spec.ts`; тут
 * механіка модуля і ДЖЕРЕЛЬНЕ правило, яке закриває клас: запит, що згадує
 * опційну колонку, мусить іти через ретрай.
 */

describe('stripOptionalSelect', () => {
  it('прибирає колонки з обох форматів списку — з пробілами й без', () => {
    expect(stripOptionalSelect('id, name, folder_id, rent_type, landlord_name, lease_end_date'))
      .toBe('id, name, rent_type, lease_end_date')
    expect(stripOptionalSelect('id,name,tenant_name,landlord_name,lease_start_date'))
      .toBe('id,name,tenant_name,lease_start_date')
  })

  it('прибирає і останню колонку, не лишаючи висячої коми', () => {
    expect(stripOptionalSelect('id,name,landlord_name')).toBe('id,name')
  })

  it('не чіпає схожих імен і вкладених звʼязків', () => {
    const sel = 'id, landlord_name_note, photos:property_photos(id, storage_path)'
    expect(stripOptionalSelect(sel)).toBe(sel)
  })

  it('ріже лише верхній рівень: однойменна колонка у вкладеному виборі лишається', () => {
    expect(stripOptionalSelect('id,folder_id,f:property_folders(id,folder_id)'))
      .toBe('id,f:property_folders(id,folder_id)')
  })
})

describe('stripOptionalKeys', () => {
  it('ВИДАЛЯЄ ключ, а не лишає його з undefined', () => {
    // supabase-js будує `columns=` масової вставки з Object.keys — ключ зі
    // значенням undefined туди однаково потрапив би.
    const row = stripOptionalKeys({ name: 'Офіс', landlord_name: undefined, folder_id: null })
    expect(Object.keys(row)).toEqual(['name'])
  })
})

describe('isMissingOptionalColumn', () => {
  it('впізнає обидві форми відмови PostgREST', () => {
    expect(isMissingOptionalColumn({ code: '42703', message: 'column properties.landlord_name does not exist' })).toBe(true)
    expect(isMissingOptionalColumn({ code: 'PGRST204', message: "Could not find the 'landlord_name' column of 'properties' in the schema cache" })).toBe(true)
  })

  it('не плутає з іншими помилками', () => {
    expect(isMissingOptionalColumn({ code: '23505', message: 'duplicate key value' })).toBe(false)
    expect(isMissingOptionalColumn(null)).toBe(false)
  })
})

describe('withOptionalColumns', () => {
  it('повторює РІВНО раз і лише на невідомій колонці', async () => {
    const calls: boolean[] = []
    const res = await withOptionalColumns(async (pre) => {
      calls.push(pre)
      return pre ? { data: 1, error: null } : { data: null, error: { code: 'PGRST204', message: 'landlord_name' } }
    })
    expect(calls).toEqual([false, true])
    expect(res.data).toBe(1)
  })

  it('інша помилка не тригерить ретрай — її треба показати як є', async () => {
    const calls: boolean[] = []
    const res = await withOptionalColumns(async (pre) => {
      calls.push(pre)
      return { data: null, error: { code: '23505', message: 'duplicate key' } }
    })
    expect(calls).toEqual([false])
    expect(res.error).toBeTruthy()
  })
})

const SRC = join(__dirname, '..', '..', 'src')
function walk(dir: string, out: string[] = []): string[] {
  for (const e of readdirSync(dir)) {
    const p = join(dir, e)
    if (statSync(p).isDirectory()) walk(p, out)
    else if (/\.tsx?$/.test(p)) out.push(p)
  }
  return out
}

describe('джерельне правило', () => {
  it('кожен запит із повним списком колонок обʼєкта йде через ретрай', () => {
    // Константа зі списком колонок обʼєкта (з `landlord_name`) у `.select(…)`
    // без `withOptionalColumns`/фолбека поруч — рівно той дефект, що клав
    // збереження обʼєкта, базу рієлтора й підбірки на бекенді без 064.
    const bad: string[] = []
    let sites = 0
    for (const f of walk(SRC)) {
      const text = readFileSync(f, 'utf8')
      const re = /\.select\(\s*(?:pre\s*\?[^:]+:\s*)?(?:'[^']*\(' \+ )?\(?\s*(?:pre\s*\?\s*\w+\s*:\s*)?(PROPERTY_WITH_PHOTOS|PROPERTY_SELECT|EXPORT_SELECT|DB_COLUMNS)\b/g
      for (const m of text.matchAll(re)) {
        sites++
        // Вікно навколо виклику: ретрай-обгортка стоїть ДО нього (часто за
        // довгим коментарем), явна гілка фолбека — одразу ПІСЛЯ.
        const around = text.slice(Math.max(0, m.index! - 1200), m.index! + 700)
        const guarded = /withOptionalColumns|isMissingOptionalColumn|isMissingLandlordColumn/.test(around)
        if (!guarded) bad.push(`${relative(SRC, f)}: ${m[0]}`)
      }
    }
    expect(sites, 'антивакуум: гард мусить бачити реальні запити').toBeGreaterThan(8)
    expect(bad).toEqual([])
  })
})

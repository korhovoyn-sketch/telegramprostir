import { describe, it, expect, afterEach, vi } from 'vitest'
import { readdirSync, readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { loadLang } from '@/lib/i18n'

// viewTracking тягне клієнт Supabase; тут потрібен лише підпис.
vi.mock('@/lib/supabase', () => ({ supabase: {} }))
const { viewerLabel } = await import('@/lib/viewTracking')

/**
 * Публічне відкриття `/v` анонімне, і сервер пише замість імені СЛУЖБОВИЙ
 * підпис українською. Показаний як є, він давав англомовному власнику
 * «Веб-перегляд» у найчастішому рядку аналітики.
 */
describe('viewerLabel', () => {
  afterEach(async () => { await loadLang('uk') })

  it('службовий підпис перекладається, імʼя людини — ні', async () => {
    await loadLang('en')
    expect(viewerLabel('Веб-перегляд підбірки')).toBe('Collection web view')
    expect(viewerLabel('Веб-перегляд бази')).toBe('Database web view')
    expect(viewerLabel('Веб-перегляд')).toBe('Web view')
    expect(viewerLabel('Олена Стерта')).toBe('Олена Стерта')
    expect(viewerLabel(null)).toBe('Anonymous')
  })

  it('українською — без змін', () => {
    expect(viewerLabel('Веб-перегляд')).toBe('Веб-перегляд')
    expect(viewerLabel(null)).toBe('Анонім')
  })

  /**
   * Підписи пише СЕРВЕР, тож новий у міграції інакше зʼявився б
   * неперекладеним — і жоден рантайм-тест цього не побачив би.
   */
  it('кожен службовий підпис сервера має переклад', async () => {
    const dir = resolve(process.cwd(), 'supabase/migrations')
    const sql = readdirSync(dir).filter((f) => f.endsWith('.sql'))
      .map((f) => readFileSync(resolve(dir, f), 'utf8')).join('\n')
    const labels = [...new Set([...sql.matchAll(/'(Веб-перегляд[^']*)'/g)].map((m) => m[1]))]
    expect(labels.length, 'службових підписів у міграціях не знайдено — гард осліп').toBeGreaterThanOrEqual(3)
    await loadLang('en')
    for (const l of labels) {
      expect(viewerLabel(l), `«${l}» пише сервер, а клієнт показує його без перекладу`).not.toBe(l)
    }
  })
})

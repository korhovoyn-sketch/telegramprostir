import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'

/**
 * ЗАГОЛОВКИ — ЦЕ КОД, ЯКИЙ НІХТО НЕ ВИКОНУЄ, ТОЖ ЙОГО ЗНИКНЕННЯ МОВЧАЗНЕ.
 *
 * `vercel.json` несе CSP, HSTS, nosniff, Referrer-Policy і Permissions-Policy.
 * Жоден тест їх ніколи не читав: приберіть будь-який рядок — збірка зелена,
 * тести зелені, прод беззахисний. Клас той самий, що вже ловили на
 * пермісивних RLS-політиках: контроль існує, поки його ніхто не стер.
 *
 * ЧОМУ САМЕ REFERRER-POLICY ТУТ НАЙВАЖЛИВІШИЙ. Публічна сторінка `/v` несе
 * share-токен У QUERY — це і є її креденшл. З неї ведуть вихідні посилання
 * (`t.me`, `tel:`). При `unsafe-url` або `no-referrer-when-downgrade` браузер
 * віддав би повний URL разом із токеном СТОРОННЬОМУ домену. Токени не
 * ротуються, тож такий витік вічний.
 */

const vercel = JSON.parse(readFileSync(resolve(process.cwd(), 'vercel.json'), 'utf8'))

function headersFor(source: string): Record<string, string> {
  const block = vercel.headers?.find((h: { source: string }) => h.source === source)
  expect(block, `у vercel.json немає блоку заголовків для "${source}"`).toBeDefined()
  return Object.fromEntries(
    block.headers.map((h: { key: string; value: string }) => [h.key, h.value]))
}

describe('заголовки безпеки', () => {
  const H = headersFor('/(.*)')

  it('набір заголовків на місці', () => {
    for (const k of ['Content-Security-Policy', 'X-Content-Type-Options',
                     'Strict-Transport-Security', 'Referrer-Policy', 'Permissions-Policy']) {
      expect(H[k], `заголовок ${k} зник із vercel.json`).toBeTruthy()
    }
  })

  it('Referrer-Policy не виносить share-токен зі сторінки /v', () => {
    // Політики, за яких браузер віддає ПОВНИЙ URL (із query) стороннім:
    const LEAKY = ['unsafe-url', 'no-referrer-when-downgrade', 'origin-when-cross-origin']
    expect(LEAKY, `Referrer-Policy "${H['Referrer-Policy']}" віддав би токен із /v?prop=…`)
      .not.toContain(H['Referrer-Policy'])
    expect(['strict-origin-when-cross-origin', 'strict-origin', 'same-origin', 'no-referrer'])
      .toContain(H['Referrer-Policy'])
  })

  it('CSP тримає периметр: фрейми лише Telegram, жодних плагінів, без чужих доменів', () => {
    const csp = H['Content-Security-Policy']
    // Вбудовувати нас може лише Telegram — інакше клікджекінг поверх застосунку,
    // де вся автентифікація неявна (initData від клієнта).
    const frames = /frame-ancestors ([^;]+)/.exec(csp)?.[1] ?? ''
    expect(frames, 'frame-ancestors відсутні — вбудувати може будь-хто').toBeTruthy()
    expect(frames, 'frame-ancestors * — клікджекінг відкритий').not.toContain('*')
    expect(frames).toContain('telegram.org')
    expect(csp, "object-src 'none' знято — повертаються плагінні вектори").toContain("object-src 'none'")
    expect(csp, "base-uri знято — можна переписати базу відносних URL").toContain("base-uri 'self'")
    // Мережа — лише свій бекенд і Telegram. Поява стороннього домену в
    // connect-src означає, що дані застосунку можуть піти кудись іще.
    const connect = /connect-src ([^;]+)/.exec(csp)?.[1] ?? ''
    const ALLOWED = ["'self'", 'https://*.supabase.co', 'wss://*.supabase.co', 'https://api.telegram.org']
    expect(connect.trim().split(/\s+/).filter((d) => !ALLOWED.includes(d)),
      'у connect-src з\'явився сторонній домен — дані застосунку можуть піти туди').toEqual([])
  })

  it('камера й геолокація вимкнені для сторонніх фреймів', () => {
    expect(H['Permissions-Policy']).toMatch(/geolocation=\(\)/)
    expect(H['Permissions-Policy']).toMatch(/microphone=\(\)/)
  })
})

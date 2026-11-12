import { test, expect, type Page } from '@playwright/test'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import * as XLSX from 'xlsx'
import { skipCoachmarks } from './helpers/harness'
import { installLive, db, exec, type LiveLog, type Persona } from './live/live'

/**
 * ІНСТРУМЕНТ, не гард (`_`-префікс → у прогін не входить):
 *   bash tests/e2e/live/stand.sh start
 *   SHOTS_DIR=… PERF=1 CI=1 npx playwright test _live-lifecycle --workers=1
 *
 * ЖИТТЄВИЙ ЦИКЛ цілком на ЖИВІЙ базі (усі міграції, RLS, тригери): акаунт →
 * бази → обʼєкти → папки → команда → експорт → видалення всього у зворотному
 * порядку → видалення акаунта → повторна реєстрація. Кожна дія звіряється
 * запитом у базу від postgres, а після кожного ВИДАЛЕННЯ — ще й тим, що
 * екран не лишив користувача в тупику (є куди піти далі).
 *
 * Чим відрізняється від `_live`: той ходить ШИРОКО (усі ролі й екрани), цей
 * — ГЛИБОКО по одній осі «створив → видалив», де помилка коштує даних.
 */

const SHOTS = process.env.SHOTS_DIR
let shotN = 0
async function shot(page: Page, name: string) {
  if (!SHOTS) return
  await page.waitForTimeout(350)
  await page.screenshot({ path: `${SHOTS}/${String(++shotN).padStart(3, '0')}-${name}.png` })
}

const OWNER: Persona = { tg_id: 700000021, first_name: 'Марта', username: 'marta' }
const MATE: Persona = { tg_id: 700000022, first_name: 'Тарас', username: 'taras' }

test.skip(!process.env.PERF, 'інструмент: PERF=1')
test.describe.configure({ mode: 'serial', timeout: 240_000 })

let current: LiveLog | null = null
test.beforeEach(async ({ page }) => { page.setDefaultTimeout(15_000) })
test.afterEach(async ({}, info) => {
  if (!current) return
  const noise = /favicon|Download the React DevTools|net::ERR_ABORTED/
  const errs = current.errors.filter((e) => !noise.test(e))
  console.log(`── ${info.title}: ${current.requests.length} запитів, ${current.failed.length} помилок сервера, ${errs.length} помилок консолі`)
  for (const f of current.failed) console.log('  ✗ ' + f)
  for (const e of errs) console.log('  ! ' + e.slice(0, 300))
  current = null
})

async function open(page: Page, persona: Persona, startParam?: string) {
  current = await installLive(page, persona, { startParam })
  await skipCoachmarks(page)
  await page.goto('/')
}
async function reset(p: Persona) {
  await exec(`UPDATE property_views SET viewer_id = NULL WHERE viewer_id IN (SELECT id FROM users WHERE tg_id = ${p.tg_id});
    DELETE FROM users WHERE tg_id = ${p.tg_id};
    DELETE FROM auth.users WHERE email = '${p.tg_id}@telegram.propspace.app';`)
}
const back = (page: Page) => page.locator('.hdr-back').first().click()
const text = async (page: Page, n = 400) => (await page.locator('body').innerText()).slice(0, n).replace(/\n/g, ' | ')
async function toast(page: Page) {
  const t = page.locator('.toast').last()
  await t.waitFor({ state: 'visible', timeout: 8000 }).catch(() => {})
  return (await t.textContent({ timeout: 1000 }).catch(() => '')) ?? ''
}
async function menu(page: Page, item: string) {
  await page.getByLabel('Меню бази').click()
  await page.getByRole('dialog').getByText(item, { exact: true }).click()
}
async function confirm(page: Page, label: RegExp) {
  const dlg = page.getByRole('dialog').last()
  await dlg.waitFor({ state: 'visible', timeout: 5000 })
  await dlg.getByRole('button', { name: label }).click()
}
async function toDb(page: Page, name: string) {
  await expect(page.getByText('Мої бази')).toBeVisible({ timeout: 20_000 })
  await page.getByText(name, { exact: true }).first().click()
  await expect(page.getByLabel('Меню бази')).toBeVisible()
}
const mine = `(SELECT id FROM users WHERE tg_id = ${OWNER.tg_id})`
const count = async (sql: string) => (await db<{ n: number }[]>(`SELECT count(*)::int n FROM ${sql}`))[0].n

test('1. акаунт: реєстрація з нуля', async ({ page }) => {
  await reset(OWNER); await reset(MATE)
  await open(page, OWNER)
  await expect(page.getByText(/Хто ти\?/i)).toBeVisible({ timeout: 20_000 })
  await page.getByText('Власник', { exact: true }).first().click()
  await page.getByRole('button', { name: /Продовжити/i }).click()
  await expect(page.getByText('Контакти', { exact: true })).toBeVisible()
  await page.getByRole('button', { name: /Почати роботу/i }).click()
  await expect(page.getByText(/Немає жодної бази/i)).toBeVisible()
  await shot(page, 'empty-state')
  const u = await db<{ role: string; a: number }[]>(`SELECT role, (SELECT count(*)::int FROM auth.users WHERE email='${OWNER.tg_id}@telegram.propspace.app') a FROM users WHERE tg_id=${OWNER.tg_id}`)
  console.log('ACCOUNT:', JSON.stringify(u))
  expect(u).toEqual([{ role: 'owner', a: 1 }])
})

test('2. бази: створити дві, перейменувати, порожня назва не проходить', async ({ page }) => {
  await open(page, OWNER)
  await page.getByRole('button', { name: /Створити першу базу/i }).click()
  const cta = page.getByRole('button', { name: 'Створити базу' })
  console.log('порожня назва → кнопка неактивна:', await cta.isDisabled())
  await page.getByPlaceholder('БЦ Олімп').fill('БЦ Перший')
  await page.locator('.type-card', { hasText: 'Бізнес-центр' }).click()
  await cta.click()
  await expect(page.getByLabel('Меню бази')).toBeVisible()
  console.log('після створення:', await text(page, 160))
  await back(page)
  await expect(page.getByText('Мої бази')).toBeVisible()

  await page.getByRole('button', { name: /Створити базу/ }).first().click()
  await page.getByPlaceholder('БЦ Олімп').fill('Склад Другий')
  await page.locator('.type-card').nth(1).click()
  await page.getByRole('button', { name: 'Створити базу' }).click()
  await expect(page.getByLabel('Меню бази')).toBeVisible()
  await menu(page, 'Редагувати базу')
  await expect(page.locator('input').first()).toHaveValue('Склад Другий')
  await page.locator('input').first().fill('Склад Південний')
  await page.locator('.mbtn').first().click()
  await page.waitForTimeout(1500)
  console.log('після перейменування:', await text(page, 160))
  const dbs = await db<{ name: string }[]>(`SELECT name FROM databases WHERE owner_id=${mine} ORDER BY created_at`)
  console.log('DBS:', JSON.stringify(dbs))
  expect(dbs.map((d) => d.name)).toEqual(['БЦ Перший', 'Склад Південний'])
})

test('3. обʼєкти: один, масово три, дублікат, фото й документ', async ({ page }) => {
  await open(page, OWNER)
  await toDb(page, 'БЦ Перший')
  await page.getByRole('button', { name: 'Додати перший обʼєкт' }).click()
  await page.getByPlaceholder('Офіс 101').fill('Офіс 1')
  await page.getByPlaceholder('47').fill('50')
  await page.getByPlaceholder('52').fill('60')
  await page.getByPlaceholder('18').fill('20')
  await page.getByRole('button', { name: 'Додати обʼєкт' }).click()
  await expect(page.locator('.obj-t', { hasText: 'Офіс 1' })).toBeVisible()

  await page.getByLabel('Додати обʼєкт').click()
  await page.getByLabel('Назва обʼєкта', { exact: true }).fill('Офіс 10')
  await page.getByLabel('Більше обʼєктів').click(); await page.getByLabel('Більше обʼєктів').click()
  await expect(page.getByLabel('Назва обʼєкта 2')).toBeVisible()
  await shot(page, 'bulk-form')
  await page.locator('button.mbtn').first().click()
  await page.waitForTimeout(2000)
  console.log('BULK toast:', await toast(page))

  await page.getByLabel('Дії з обʼєктом «Офіс 1»').click()
  await page.locator('.sheet-row').filter({ hasText: 'Дублювати' }).click()
  await expect(page.getByLabel('Назва обʼєкта', { exact: true })).toHaveValue(/Офіс/)
  console.log('DUP name:', await page.getByLabel('Назва обʼєкта', { exact: true }).inputValue())
  await page.locator('button.mbtn').first().click()
  await page.waitForTimeout(2000)
  const props = await db<{ name: string; sort_order: number; rent_rate: number; area_useful: number; ok: boolean }[]>(
    `SELECT p.name, p.sort_order, p.rent_rate, p.area_useful, p.owner_id = d.owner_id ok FROM properties p JOIN databases d ON d.id=p.db_id WHERE d.owner_id=${mine} ORDER BY p.sort_order`)
  console.log('PROPS:', JSON.stringify(props))
  expect.soft(props.length).toBe(5)
  expect.soft(new Set(props.map((p) => p.sort_order)).size, 'sort_order без колізій').toBe(props.length)
  expect.soft(new Set(props.map((p) => p.name)).size, 'назви унікальні').toBe(props.length)
  expect.soft(props.every((p) => p.ok)).toBe(true)

  await page.locator('.obj-t', { hasText: /^Офіс 1$/ }).first().click()
  await expect(page.getByText('ФІНАНСИ')).toBeVisible()
  const png = readFileSync(join(__dirname, 'fixtures', 'photo.png'))
  await page.locator('input[type="file"][accept^="image"]').first().setInputFiles([
    { name: 'a.png', mimeType: 'image/png', buffer: png }, { name: 'b.png', mimeType: 'image/png', buffer: png }])
  await page.waitForTimeout(4000)
  if (await page.getByText('ФІНАНСИ').count() === 0) await back(page)
  await expect(page.getByText('ФІНАНСИ')).toBeVisible()
  await page.locator('input[type="file"][accept*="pdf"]').first().setInputFiles({ name: 'Договір.pdf', mimeType: 'application/pdf', buffer: Buffer.from('%PDF-1.4\n%%EOF\n') })
  await page.waitForTimeout(2500)
  console.log('STORAGE:', JSON.stringify(await db(`SELECT bucket_id b, count(*)::int n FROM storage.objects GROUP BY 1 ORDER BY 1`)))
  expect.soft(await count(`property_photos`)).toBe(2)
  expect.soft(await count(`property_files`)).toBe(1)
})

test('4. папки: створити, дубль назви, перейменувати, наповнити, видалити', async ({ page }) => {
  await open(page, OWNER)
  await toDb(page, 'БЦ Перший')
  await menu(page, 'Папки')
  const nf = page.getByLabel('Назва нової папки')
  await nf.press('Enter')
  console.log('порожня папка → рядків:', await count(`property_folders`))
  for (const n of ['Поверх 1', 'Поверх 2', 'Поверх 1']) { await nf.fill(n); await nf.press('Enter'); await page.waitForTimeout(900) }
  console.log('FOLDERS після дубля назви:', JSON.stringify(await db(`SELECT name, sort_order FROM property_folders ORDER BY sort_order`)), '| toast:', await toast(page))
  await shot(page, 'folders')
  await page.getByRole('button', { name: 'Перейменувати' }).first().click()
  await page.getByLabel(/Нова назва папки/).fill('Перший поверх')
  await page.getByRole('button', { name: 'Зберегти' }).click()
  await page.waitForTimeout(900)
  await back(page)

  await menu(page, 'Виділити обʼєкти')
  await page.locator('.obj-card').nth(0).click(); await page.locator('.obj-card').nth(1).click()
  await page.getByText('У папку', { exact: true }).click()
  await page.getByText('Перший поверх').click()
  await page.waitForTimeout(1500)
  const inFolder = await count(`properties WHERE folder_id IS NOT NULL`)
  console.log('у папці:', inFolder, '| екран:', await text(page, 200))
  expect.soft(inFolder).toBe(2)
  await shot(page, 'after-move')

  await menu(page, 'Папки')
  await page.getByLabel('Видалити').first().click()
  await confirm(page, /^Видалити$/)
  await page.waitForTimeout(1500)
  console.log('DEL FOLDER toast:', await toast(page))
  const after = await db(`SELECT (SELECT count(*)::int FROM property_folders WHERE name='Перший поверх') f, (SELECT count(*)::int FROM properties WHERE folder_id IS NOT NULL) inf, (SELECT count(*)::int FROM properties) p`)
  console.log('після видалення папки:', JSON.stringify(after))
  expect.soft(after).toEqual([{ f: 0, inf: 0, p: 5 }])
  await back(page)
  await expect(page.getByLabel('Меню бази')).toBeVisible()
})

let teamToken = ''
test('5. команда: запросити', async ({ page }) => {
  await open(page, OWNER)
  await toDb(page, 'БЦ Перший')
  await menu(page, 'Команда')
  await page.getByLabel('Запросити в команду').click()
  const create = page.getByRole('button', { name: /Створити/ })
  await page.getByPlaceholder('напр. Менеджер Оля').fill('Менеджер Тарас')
  await create.click()
  await page.waitForTimeout(1200)
  await shot(page, 'team-link')
  console.log('LINK екран:', await text(page, 260))
  teamToken = (await db<{ t: string }[]>(`SELECT invite_token t FROM db_members ORDER BY created_at DESC LIMIT 1`))[0]?.t ?? ''
  expect(teamToken).toBeTruthy()
  await back(page)
  console.log('TEAM список:', await text(page, 260))
})

test('6. команда: учасник приймає, пише обʼєкт; чужого не бачить', async ({ page }) => {
  await open(page, MATE, `team_${teamToken}`)
  await page.waitForTimeout(4000)
  console.log('MATE вхід:', await text(page, 300), '| toast:', await toast(page))
  await shot(page, 'mate-entry')
  await page.getByLabel('Додати обʼєкт').click()
  await page.getByPlaceholder('Офіс 101').fill('Склад Тараса')
  await page.getByPlaceholder('47').fill('30')
  await page.getByRole('button', { name: 'Додати обʼєкт' }).click()
  await page.waitForTimeout(2000)
  const row = await db(`SELECT p.owner_id = d.owner_id ok, m.status, m.member_name FROM properties p JOIN databases d ON d.id=p.db_id JOIN db_members m ON m.db_id=d.id WHERE p.name='Склад Тараса'`)
  console.log('MATE запис:', JSON.stringify(row))
  expect.soft(row).toEqual([{ ok: true, status: 'active', member_name: 'Тарас' }])
  // Друга база власниці учаснику не видна: членство лише в одній.
  await back(page)
  await page.waitForTimeout(1500)
  const home = await text(page, 400)
  console.log('MATE дім:', home)
  expect.soft(home).not.toContain('Склад Південний')
  expect.soft(home).toContain('БЦ Перший')
})

test('7. команда: відкликати → учасник без доступу; прибрати запис', async ({ page, browser }) => {
  await open(page, OWNER)
  await toDb(page, 'БЦ Перший')
  await menu(page, 'Команда')
  console.log('TEAM:', await text(page, 300))
  await page.getByRole('button', { name: /Відкликати/ }).first().click()
  await confirm(page, /Відкликати/)
  await page.waitForTimeout(1500)
  console.log('REVOKE toast:', await toast(page), JSON.stringify(await db(`SELECT status FROM db_members`)))

  const ctx = await browser.newContext({ viewport: { width: 375, height: 667 } })
  const mp = await ctx.newPage()
  mp.setDefaultTimeout(15_000)
  await installLive(mp, MATE); await skipCoachmarks(mp)
  await mp.goto('/')
  await mp.waitForTimeout(4500)
  const home = (await mp.locator('body').innerText()).slice(0, 300).replace(/\n/g, ' | ')
  console.log('MATE після відкликання:', home)
  expect.soft(home, 'відкликаний не бачить базу').not.toContain('БЦ Перший')
  // Тупик? У відкликаного мусить лишитись дія або навігація.
  console.log('MATE має вихід:', await mp.locator('.tabbar, .mbtn, .fbtn').count())
  await ctx.close()

  const sec = page.getByText(/Відкликані/).first()
  if (await sec.count()) await sec.click()
  await page.getByRole('button', { name: /Прибрати/ }).first().click()
  await confirm(page, /Прибрати/)
  await page.waitForTimeout(1500)
  console.log('REMOVE toast:', await toast(page), '| db_members:', await count('db_members'))
  expect.soft(await count('db_members')).toBe(0)
})

test('8. експорт: PDF, Excel, CSV — вміст звіряється з базою', async ({ page }) => {
  await page.addInitScript(() => {
    const w = window as unknown as { __files: { name: string; b64: string; size: number }[] }
    w.__files = []
    Object.defineProperty(navigator, 'canShare', { value: () => true, configurable: true })
    Object.defineProperty(navigator, 'share', {
      configurable: true,
      value: async (data: { files?: File[] }) => {
        for (const f of data.files ?? []) {
          const bytes = new Uint8Array(await f.arrayBuffer())
          let bin = ''; for (const b of bytes) bin += String.fromCharCode(b)
          w.__files.push({ name: f.name, b64: btoa(bin), size: f.size })
        }
      },
    })
  })
  await open(page, OWNER)
  await toDb(page, 'БЦ Перший')
  await menu(page, 'Експорт')
  for (const [fmt, btn] of [['PDF Документ', /Завантажити PDF/], ['Excel таблиця', /Завантажити Excel/], ['CSV таблиця', /Завантажити CSV/]] as const) {
    await page.getByText(fmt, { exact: true }).click()
    await page.getByRole('button', { name: btn }).click()
    await page.waitForTimeout(3000)
    console.log(`EXPORT ${fmt} toast:`, await toast(page))
  }
  const files = await page.evaluate(() => (window as unknown as { __files: { name: string; b64: string; size: number }[] }).__files)
  console.log('EXPORT files:', files.map((f) => `${f.name} ${f.size}B`).join(', '))
  expect.soft(files.length).toBe(3)
  const names = (await db<{ name: string }[]>(`SELECT p.name FROM properties p JOIN databases d ON d.id=p.db_id WHERE d.name='БЦ Перший' ORDER BY p.sort_order`)).map((r) => r.name)
  const pdf = files.find((f) => f.name.endsWith('.pdf'))
  if (pdf) expect.soft(Buffer.from(pdf.b64, 'base64').subarray(0, 5).toString()).toBe('%PDF-')
  const xl = files.find((f) => f.name.endsWith('.xlsx'))
  if (xl) {
    const wb = XLSX.read(Buffer.from(xl.b64, 'base64'))
    const rows = XLSX.utils.sheet_to_json<unknown[]>(wb.Sheets[wb.SheetNames[0]], { header: 1 })
    const flat = rows.map((r) => (r as unknown[]).join(' | '))
    console.log('XLSX аркуші:', wb.SheetNames.join(', '), '| рядків:', rows.length)
    for (const n of names) expect.soft(flat.some((l) => l.includes(n)), `XLSX містить «${n}»`).toBe(true)
    console.log('XLSX рядок Офіс 1:', flat.find((l) => l.includes('Офіс 1 ') || / Офіс 1 \|/.test(' ' + l)) ?? flat.find((l) => l.includes('Офіс 1')))
  }
  const csv = files.find((f) => f.name.endsWith('.csv'))
  if (csv) {
    const body = Buffer.from(csv.b64, 'base64').toString('utf8').replace(/^﻿/, '')
    const lines = body.split(/\r?\n/).filter(Boolean)
    console.log('CSV:', lines.length - 1, 'рядків даних; заголовок:', lines[0].slice(0, 140))
    expect.soft(lines.length - 1, 'CSV: рядок на обʼєкт').toBe(names.length)
  }
  await back(page)
  await expect(page.getByLabel('Меню бази')).toBeVisible()
})

test('9. видалення: обʼєкт із фото, пакет, база з усім, остання база', async ({ page }) => {
  await open(page, OWNER)
  await toDb(page, 'БЦ Перший')
  await page.locator('.obj-t', { hasText: /^Офіс 1$/ }).first().click()
  await expect(page.getByText('ФІНАНСИ')).toBeVisible()
  await page.getByLabel(/Редагувати/).first().click()
  await page.getByRole('button', { name: /Видалити/ }).last().click()
  await confirm(page, /^Видалити$/)
  await page.waitForTimeout(2000)
  console.log('DEL PROP toast:', await toast(page), '| екран:', await text(page, 140))
  const s1 = await db(`SELECT (SELECT count(*)::int FROM properties WHERE name='Офіс 1') p, (SELECT count(*)::int FROM storage.objects) s, (SELECT count(*)::int FROM property_photos) ph, (SELECT count(*)::int FROM property_files) f`)
  console.log('після видалення обʼєкта:', JSON.stringify(s1))
  expect.soft(s1, 'файли обʼєкта пішли разом із рядком').toEqual([{ p: 0, s: 0, ph: 0, f: 0 }])
  await expect(page.getByLabel('Меню бази')).toBeVisible()

  const before = await count('properties')
  await menu(page, 'Виділити обʼєкти')
  await page.locator('.obj-card').nth(0).click(); await page.locator('.obj-card').nth(1).click()
  await page.locator('.batch-pill.err').click()
  await confirm(page, /^Видалити \(\d+\)$/)
  await page.waitForTimeout(2000)
  console.log('BATCH DEL toast:', await toast(page), '| було', before, 'стало', await count('properties'))
  expect.soft(await count('properties')).toBe(before - 2)

  // Навантажити базу перед видаленням: гостьовий лінк, папка, розклад, фото.
  await exec(`INSERT INTO guest_links (owner_id, db_id, label) SELECT owner_id, id, 'Гість' FROM databases WHERE name='БЦ Перший';
    INSERT INTO property_folders (db_id, owner_id, name) SELECT id, owner_id, 'Тека' FROM databases WHERE name='БЦ Перший';
    INSERT INTO rent_payments (property_id, owner_id, due_day) SELECT p.id, p.owner_id, 5 FROM properties p LIMIT 1;
    INSERT INTO property_photos (property_id, storage_path, sort_order) SELECT p.id, p.id || '/x.png', 0 FROM properties p LIMIT 1;
    INSERT INTO storage.objects (bucket_id, name) SELECT 'photos', p.id || '/x.png' FROM properties p LIMIT 1;`)
  await page.reload()
  await toDb(page, 'БЦ Перший')
  await menu(page, 'Видалити базу')
  await shot(page, 'delete-db-confirm')
  console.log('DEL DB підтвердження:', (await page.getByRole('dialog').last().innerText()).replace(/\n/g, ' | ').slice(0, 220))
  await confirm(page, /^Видалити$/)
  await expect(page.getByText('Мої бази')).toBeVisible()
  console.log('DEL DB toast:', await toast(page))
  const s2 = await db(`SELECT (SELECT count(*)::int FROM databases WHERE name='БЦ Перший') d, (SELECT count(*)::int FROM properties) p, (SELECT count(*)::int FROM property_folders) f,
    (SELECT count(*)::int FROM guest_links) g, (SELECT count(*)::int FROM rent_payments) r, (SELECT count(*)::int FROM property_photos) ph, (SELECT count(*)::int FROM storage.objects) s`)
  console.log('після видалення бази:', JSON.stringify(s2))
  expect.soft(s2, 'каскад і файли').toEqual([{ d: 0, p: 0, f: 0, g: 0, r: 0, ph: 0, s: 0 }])

  await toDb(page, 'Склад Південний')
  await menu(page, 'Видалити базу')
  await confirm(page, /^Видалити$/)
  await page.waitForTimeout(2500)
  await shot(page, 'after-last-db')
  const home = await text(page, 240)
  console.log('після ОСТАННЬОЇ бази:', home)
  expect.soft(await count(`databases WHERE owner_id=${mine}`)).toBe(0)
  expect.soft(await page.getByRole('button', { name: /Створити/ }).count(), 'є дія «створити» — не тупик').toBeGreaterThan(0)
})

test('10. акаунт: видалення і повторна реєстрація', async ({ page }) => {
  await open(page, OWNER)
  await page.locator('.tabbar [aria-label="Профіль"]').click()
  await page.getByText('Видалити акаунт').click()
  const btn = page.locator('button.mbtn')
  const field = page.getByLabel('Підтвердження видалення')
  await field.fill('видалити')
  console.log('малими літерами → неактивна:', await btn.isDisabled())
  await field.fill('ВИДАЛИТ')
  console.log('неповне слово → неактивна:', await btn.isDisabled())
  expect.soft(await btn.isDisabled()).toBe(true)
  await field.fill('ВИДАЛИТИ')
  await shot(page, 'delete-account')
  await btn.click()
  await page.waitForTimeout(3500)
  await shot(page, 'after-delete-account')
  console.log('після видалення акаунта:', await text(page, 200))
  const left = await db(`SELECT (SELECT count(*)::int FROM users WHERE tg_id=${OWNER.tg_id}) u, (SELECT count(*)::int FROM auth.users WHERE email='${OWNER.tg_id}@telegram.propspace.app') a, (SELECT count(*)::int FROM storage.objects) s`)
  console.log('LEFT:', JSON.stringify(left))
  expect.soft(left).toEqual([{ u: 0, a: 0, s: 0 }])
  const keys = await page.evaluate(() => Object.keys(localStorage))
  console.log('localStorage після:', keys.join(', '))
  expect.soft(keys.filter((k) => /^(ps_user|snap_v1|draft_v1|ps_guest)/.test(k)), 'сесійні ключі стерто').toEqual([])
  // Чи є вихід з екрана після видалення (кнопка входу), а не тупик.
  console.log('дія на екрані після видалення:', await page.getByRole('button').allInnerTexts())
})

test('11. акаунт: той самий Telegram заходить знову — чистий старт', async ({ page }) => {
  await open(page, OWNER)
  await page.waitForTimeout(5000)
  await shot(page, 're-register')
  const scr = await text(page, 200)
  console.log('повторний вхід:', scr)
  expect.soft(scr).toMatch(/Хто ти\?|Увійти/)
  if (await page.getByRole('button', { name: /Увійти/ }).count()) {
    await page.getByRole('button', { name: /Увійти/ }).first().click()
    await page.waitForTimeout(4000)
    console.log('після «Увійти»:', await text(page, 200))
  }
  await expect(page.getByText(/Хто ти\?/i)).toBeVisible({ timeout: 20_000 })
  expect.soft(await count(`databases WHERE owner_id=${mine}`), 'нічого зі старого акаунта').toBe(0)
  await reset(OWNER); await reset(MATE)
})

/**
 * ПРОХІД ЯК КОРИСТУВАЧ на ЖИВІЙ базі (інструмент, у прогін не входить).
 *
 *   bash tests/e2e/live/stand.sh start
 *   SHOTS_DIR=/tmp/shots PERF=1 CI=1 npx playwright test _live --workers=1
 *
 * На відміну від решти набору, тут немає фікстур: кожен екран показує те, що
 * повернула справжня база з усіма міграціями, а кожна дія звіряється ЗАПИТОМ
 * до бази — «тост сказав успіх» доказом не вважається.
 */
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { test, expect, type Page } from '@playwright/test'
import { skipCoachmarks } from './helpers/harness'
import { installLive, db, exec, type LiveLog, type Persona } from './live/live'

const SHOTS = process.env.SHOTS_DIR
let shotN = 0
async function shot(page: Page, name: string) {
  if (!SHOTS) return
  await page.waitForTimeout(350)
  await page.screenshot({ path: `${SHOTS}/${String(++shotN).padStart(3, '0')}-${name}.png` })
}

function report(name: string, log: LiveLog) {
  const noise = /favicon|Download the React DevTools|net::ERR_ABORTED/
  const errs = log.errors.filter((e) => !noise.test(e))
  console.log(`\n── ${name}: ${log.requests.length} запитів, ${log.failed.length} помилок сервера, ${errs.length} помилок консолі`)
  for (const f of log.failed) console.log('  ✗ ' + f)
  for (const e of errs) console.log('  ! ' + e.slice(0, 300))
}

const OWNER: Persona = { tg_id: 700000001, first_name: 'Олена', username: 'olena' }

test.describe.configure({ mode: 'serial', timeout: 240_000 })

let current: LiveLog | null = null
test.afterEach(async ({}, info) => {
  if (current) report(info.title, current)
  current = null
})

async function open(page: Page, persona: Persona, startParam?: string, keepCoach = false) {
  const log = await installLive(page, persona, { startParam })
  current = log
  if (!keepCoach) await skipCoachmarks(page)
  await page.goto('/')
  return log
}

async function back(page: Page) {
  await page.getByText('Назад', { exact: true }).first().click()
}

async function toast(page: Page) {
  const t = page.locator('.toast').last()
  await t.waitFor({ state: 'visible', timeout: 8000 }).catch(() => {})
  return (await t.textContent().catch(() => '')) ?? ''
}

async function reset(p: Persona) {
  await exec(`UPDATE property_views SET viewer_id = NULL WHERE viewer_id IN (SELECT id FROM users WHERE tg_id = ${p.tg_id});
    DELETE FROM users WHERE tg_id = ${p.tg_id};
    DELETE FROM auth.users WHERE email = '${p.tg_id}@telegram.propspace.app';`)
}

test('власник: онбординг, база, обʼєкт', async ({ page }) => {
  await reset(OWNER)
  await open(page, OWNER)
  await expect(page.getByText(/Хто ти\?/i)).toBeVisible({ timeout: 20_000 })
  await shot(page, 'role-select')
  await page.getByText('Власник', { exact: true }).first().click()
  await page.getByRole('button', { name: /Продовжити/i }).click()
  await expect(page.getByText('Контакти', { exact: true })).toBeVisible()
  await shot(page, 'profile-setup')
  await page.getByRole('button', { name: /Почати роботу/i }).click()
  await expect(page.getByText(/Немає жодної бази/i)).toBeVisible({ timeout: 15_000 })
  await shot(page, 'empty-state')

  await page.getByRole('button', { name: /Створити першу базу/i }).click()
  await page.getByPlaceholder('БЦ Олімп').fill('БЦ Живий')
  await page.locator('.type-card', { hasText: 'Бізнес-центр' }).click()
  await shot(page, 'create-db')
  await page.getByRole('button', { name: 'Створити базу' }).click()
  await page.waitForTimeout(1500)
  await shot(page, 'after-create-db')
  const dbs = await db<{ name: string }[]>(`SELECT d.name FROM databases d JOIN users u ON u.id=d.owner_id WHERE u.tg_id=${OWNER.tg_id}`)
  expect.soft(dbs.map((d) => d.name)).toEqual(['БЦ Живий'])
  console.log('SCREEN after db:', (await page.locator('body').innerText()).slice(0, 300).replace(/\n/g, ' | '))
})

async function toDb(page: Page, name = 'БЦ Живий') {
  await expect(page.getByText('Мої бази')).toBeVisible({ timeout: 20_000 })
  await page.getByText(name).first().click()
  await expect(page.getByLabel('Меню бази')).toBeVisible({ timeout: 15_000 })
}

test('власник: обʼєкти — створення, редагування, дублювання, масово', async ({ page }) => {
  await open(page, OWNER)
  await toDb(page)
  await page.getByLabel("Додати обʼєкт").click()
  await expect(page.getByText("Новий обʼєкт")).toBeVisible()
  await page.getByPlaceholder('Офіс 101').fill('Офіс 201')
  await page.getByPlaceholder('47').fill('50')
  await page.getByPlaceholder('52').fill('60')
  await page.getByPlaceholder('18').fill('20')
  await shot(page, 'property-form')
  await page.getByRole('button', { name: "Додати обʼєкт" }).click()
  await page.waitForTimeout(1500)
  await shot(page, 'after-create-property')
  let props = await db<{ name: string; area_useful: number; area_total: number; rent_rate: number; status: string; owner_ok: boolean }[]>(
    `SELECT p.name, p.area_useful, p.area_total, p.rent_rate, p.status, p.owner_id = d.owner_id AS owner_ok FROM properties p JOIN databases d ON d.id=p.db_id ORDER BY p.created_at`)
  console.log('PROPS after create:', JSON.stringify(props))
  expect.soft(props.map((p) => p.name)).toContain('Офіс 201')

  // відкрити й редагувати
  await page.locator('.obj-t', { hasText: 'Офіс 201' }).first().click()
  await page.waitForTimeout(1200)
  await shot(page, 'property-detail')
  console.log('DETAIL:', (await page.locator('body').innerText()).slice(0, 500).replace(/\n/g, ' | '))
  await page.getByLabel(/Редагувати/).first().click().catch(async () => {
    await page.getByText('Редагувати', { exact: true }).first().click()
  })
  await expect(page.getByPlaceholder('Офіс 101')).toHaveValue('Офіс 201', { timeout: 10_000 })
  await page.getByPlaceholder('2').first().fill('3').catch(() => {})
  await page.getByPlaceholder('Офіс 101').fill('Офіс 201А')
  await page.getByRole('button', { name: /Зберегти/ }).click()
  await page.waitForTimeout(1500)
  props = await db(`SELECT name, floor FROM properties ORDER BY created_at`)
  console.log('PROPS after edit:', JSON.stringify(props))
  expect.soft((props as { name: string }[]).map((p) => p.name)).toContain('Офіс 201А')
  await shot(page, 'after-edit')
})

async function openProp(page: Page, name: string) {
  await toDb(page)
  await page.locator('.obj-t', { hasText: name }).first().click()
  await expect(page.getByText('ФІНАНСИ')).toBeVisible({ timeout: 15_000 })
}

async function confirmSheet(page: Page) {
  const dlg = page.getByRole('dialog').last()
  await dlg.waitFor({ state: 'visible', timeout: 5000 })
  await shot(page, 'confirm')
  await dlg.locator('button.modal-btn').filter({ hasNotText: 'Скасувати' }).last().click()
}

test('власник: оренда, звільнення, скасування, архів', async ({ page }) => {
  await open(page, OWNER)
  await openProp(page, 'Офіс 201А')
  await page.getByRole('button', { name: /Здати в оренду/ }).click()
  await page.getByLabel('Орендар').fill('ТОВ Ромашка')
  await page.getByLabel('Договір від').fill('2026-09-01')
  await page.getByLabel('Договір до').fill('2027-08-31')
  await shot(page, 'rent-form')
  await page.locator('button.mbtn').filter({ hasText: /Здати/ }).click()
  await page.waitForTimeout(1500)
  await shot(page, 'after-rent')
  let st = await db(`SELECT p.status, p.tenant_name, p.lease_start_date, (SELECT count(*) FROM tenancies t WHERE t.property_id=p.id) n, (SELECT count(*) FROM tenancies t WHERE t.property_id=p.id AND ended_at IS NULL) open FROM properties p WHERE name='Офіс 201А'`)
  console.log('RENT:', JSON.stringify(st))

  await page.getByRole('button', { name: /Звільнити/ }).click()
  await confirmSheet(page).catch(() => console.log('no confirm dialog'))
  const t1 = await toast(page)
  await shot(page, 'vacate-toast')
  console.log('VACATE toast:', t1)
  st = await db(`SELECT p.status, p.tenant_name, (SELECT count(*) FROM tenancies t WHERE t.property_id=p.id AND ended_at IS NULL) open FROM properties p WHERE name='Офіс 201А'`)
  console.log('VACATE:', JSON.stringify(st))
  await page.locator('.toast').getByText('Скасувати').click().catch((e) => console.log('no undo:', String(e).slice(0, 80)))
  await page.waitForTimeout(1500)
  st = await db(`SELECT p.status, p.tenant_name, (SELECT count(*) FROM tenancies t WHERE t.property_id=p.id) n, (SELECT count(*) FROM tenancies t WHERE t.property_id=p.id AND ended_at IS NULL) open FROM properties p WHERE name='Офіс 201А'`)
  console.log('UNDO:', JSON.stringify(st))
  await shot(page, 'after-undo')
  expect.soft((st as { status: string }[])[0].status).toBe('occupied')
})

test('зонд: рамка на кнопці редагування', async ({ page }) => {
  await open(page, OWNER)
  await openProp(page, 'Офіс 201А')
  await page.waitForTimeout(800)
  const info = await page.evaluate(() => {
    const a = document.activeElement as HTMLElement | null
    const btn = [...document.querySelectorAll('button')].find((b) => /Редагувати/.test(b.getAttribute('aria-label') ?? '')) as HTMLElement | undefined
    const cs = btn ? getComputedStyle(btn) : null
    return {
      active: a ? `${a.tagName}.${a.className} [${a.getAttribute('aria-label')}]` : null,
      focusVisible: btn ? btn.matches(':focus-visible') : null,
      outline: cs ? `${cs.outlineStyle} ${cs.outlineWidth} ${cs.outlineColor}` : null,
      border: cs ? `${cs.borderStyle} ${cs.borderWidth} ${cs.borderColor}` : null,
      cls: btn?.className,
    }
  })
  console.log('PROBE:', JSON.stringify(info))
})

test('власник: платежі — розклад, часткова оплата, доплата', async ({ page }) => {
  await exec(`DELETE FROM rent_payment_records; DELETE FROM rent_payments;`)
  await open(page, OWNER)
  await toDb(page)
  await page.getByLabel('Меню бази').click()
  await page.getByText('Календар платежів').click()
  await page.waitForTimeout(1500)
  await shot(page, 'calendar-empty')
  console.log('CAL:', (await page.locator('body').innerText()).slice(0, 400).replace(/\n/g, ' | '))
  await page.getByRole('button', { name: /Налаштувати/ }).first().click()
  await page.getByLabel('День місяця').fill('5')
  await shot(page, 'schedule-form')
  await page.locator('button.mbtn').first().click()
  await page.waitForTimeout(1500)
  const sch = await db(`SELECT due_day, owner_id = (SELECT owner_id FROM properties WHERE id = property_id) AS owner_ok FROM rent_payments`)
  console.log('SCHEDULE:', JSON.stringify(sch))
  await shot(page, 'calendar-with-schedule')
  console.log('CAL2:', (await page.locator('body').innerText()).slice(0, 600).replace(/\n/g, ' | '))

  // перший неоплачений період → «Отримано»
  await page.getByRole('button', { name: /^Отримано$|Доплата/ }).first().click()
  await page.waitForTimeout(1200)
  await shot(page, 'pay-confirm')
  console.log('CONFIRM:', (await page.locator('body').innerText()).slice(0, 500).replace(/\n/g, ' | '))
  await page.getByLabel('Сума отриманого платежу').fill('500')
  await page.getByLabel('Нотатка до платежу').fill('перша частина')
  await page.locator('button.mbtn').first().click()
  await page.waitForTimeout(1500)
  let rec = await db(`SELECT r.due_date, r.status, r.amount, r.amount_due, (SELECT count(*) FROM rent_payment_parts p WHERE p.record_id = r.id) parts FROM rent_payment_records r ORDER BY due_date`)
  console.log('AFTER 500:', JSON.stringify(rec))
  await shot(page, 'calendar-partial')
  console.log('CAL3:', (await page.locator('body').innerText()).slice(0, 600).replace(/\n/g, ' | '))

  await page.getByRole('button', { name: /^Отримано$|Доплата/ }).first().click()
  await page.waitForTimeout(1200)
  await shot(page, 'pay-confirm-partial')
  console.log('CONFIRM2:', (await page.locator('body').innerText()).slice(0, 600).replace(/\n/g, ' | '))
  const amt = page.getByLabel('Сума отриманого платежу')
  console.log('prefill:', await amt.inputValue())
  await amt.fill('700')
  await page.locator('button.mbtn').first().click()
  await page.waitForTimeout(1500)
  rec = await db(`SELECT r.due_date, r.status, r.amount, r.amount_due, (SELECT count(*) FROM rent_payment_parts p WHERE p.record_id = r.id) parts FROM rent_payment_records r ORDER BY due_date`)
  console.log('AFTER 700:', JSON.stringify(rec))
  const act = await db(`SELECT kind, actor_name, property_name FROM db_activity ORDER BY created_at`)
  console.log('ACTIVITY:', JSON.stringify(act))
  await shot(page, 'calendar-paid')
})

test('власник: фото й документи', async ({ page }) => {
  await open(page, OWNER)
  await openProp(page, 'Офіс 201А')
  const png = readFileSync(join(__dirname, 'fixtures', 'photo.png'))
  await page.locator('input[type="file"][accept^="image"]').first().setInputFiles([
    { name: 'a.png', mimeType: 'image/png', buffer: png },
    { name: 'b.png', mimeType: 'image/png', buffer: png },
  ])
  await page.waitForTimeout(4000)
  await shot(page, 'after-photo-upload')
  console.log('PHOTO SCREEN:', (await page.locator('body').innerText()).slice(0, 300).replace(/\n/g, ' | '))
  let ph = await db(`SELECT pp.sort_order, pp.storage_path, (SELECT count(*) FROM storage.objects o WHERE o.bucket_id='photos' AND o.name = pp.storage_path) AS in_storage FROM property_photos pp ORDER BY sort_order`)
  console.log('PHOTOS:', JSON.stringify(ph))
  // назад на картку
  if (await page.getByText('ФІНАНСИ').count() === 0) await back(page)
  await expect(page.getByText('ФІНАНСИ')).toBeVisible({ timeout: 15_000 })
  await shot(page, 'detail-with-photos')

  const pdf = Buffer.from('%PDF-1.4\n1 0 obj<<>>endobj\ntrailer<<>>\n%%EOF\n')
  await page.locator('input[type="file"][accept*="pdf"]').first().setInputFiles({ name: 'Договір.pdf', mimeType: 'application/pdf', buffer: pdf })
  await page.waitForTimeout(2500)
  const files = await db(`SELECT f.file_name, f.mime_type, (SELECT count(*) FROM storage.objects o WHERE o.bucket_id='property-files' AND o.name = f.storage_path) AS in_storage FROM property_files f`)
  console.log('FILES:', JSON.stringify(files), 'toast:', await toast(page))
  await shot(page, 'detail-with-file')

  // видалити одне фото (смужка фото на картці)
  const del = page.getByRole('button', { name: /Видалити фото/ })
  if (await del.count()) {
    await del.first().click()
    await confirmSheet(page).catch(() => console.log('no confirm dialog'))
    await page.waitForTimeout(1500)
  } else console.log('NO DELETE BUTTON IN GALLERY:', (await page.locator('body').innerText()).slice(0, 200))
  ph = await db(`SELECT pp.sort_order, (SELECT count(*) FROM storage.objects o WHERE o.bucket_id='photos' AND o.name = pp.storage_path) AS in_storage FROM property_photos pp ORDER BY sort_order`)
  const orphans = await db(`SELECT o.name FROM storage.objects o WHERE o.bucket_id='photos' AND NOT EXISTS (SELECT 1 FROM property_photos pp WHERE pp.storage_path=o.name)`)
  console.log('PHOTOS after delete:', JSON.stringify(ph), 'orphans:', JSON.stringify(orphans))
})

async function menu(page: Page, item: string) {
  await page.getByLabel('Меню бази').click()
  await page.getByRole('dialog').getByText(item, { exact: true }).click()
}
const text = async (page: Page, n = 500) => (await page.locator('body').innerText()).slice(0, n).replace(/\n/g, ' | ')

test('власник: папки й пакетні дії', async ({ page }) => {
  await exec(`DELETE FROM property_folders`)
  await open(page, OWNER)
  await toDb(page)
  await menu(page, 'Папки')
  await page.getByLabel('Назва нової папки').fill('Поверх 3')
  await page.getByLabel('Назва нової папки').press('Enter')
  await page.waitForTimeout(1000)
  await page.getByLabel('Назва нової папки').fill('Поверх 4')
  await page.getByLabel('Назва нової папки').press('Enter')
  await page.waitForTimeout(1000)
  await page.getByRole('button', { name: 'Перейменувати' }).first().click()
  await page.getByLabel(/Нова назва папки/).fill('Третій поверх')
  await page.getByRole('button', { name: 'Зберегти' }).click()
  await page.waitForTimeout(800)
  await page.getByRole('button', { name: 'Вниз' }).first().click()
  await page.waitForTimeout(800)
  await shot(page, 'folders')
  console.log('FOLDERS:', JSON.stringify(await db(`SELECT name, sort_order FROM property_folders ORDER BY sort_order`)))
  await back(page)
  await menu(page, 'Виділити обʼєкти')
  await page.locator('.obj-card').first().click()
  await shot(page, 'select-mode')
  await page.getByText('У папку').click()
  await page.waitForTimeout(800)
  await shot(page, 'folder-picker')
  console.log('PICKER:', await text(page, 300))
  await page.getByText('Третій поверх').click()
  await page.waitForTimeout(1500)
  console.log('MOVED:', JSON.stringify(await db(`SELECT p.name, f.name AS folder FROM properties p LEFT JOIN property_folders f ON f.id=p.folder_id`)))
  await shot(page, 'after-move')
  console.log('LIST:', await text(page, 400))
})

const tokens: Record<string, string> = {}

test('власник: шаринг бази, гості, команда', async ({ page }) => {
  await open(page, OWNER)
  await toDb(page)
  await menu(page, 'Аналітика і поширення')
  await page.waitForTimeout(1500)
  await shot(page, 'sharing-analytics')
  console.log('SHARING:', await text(page, 400))
  const shareBtn = page.getByRole('button', { name: /Поділитись|Поділитися|Посилання/ }).first()
  if (await shareBtn.count()) {
    await shareBtn.click()
    await page.waitForTimeout(1200)
    await shot(page, 'share-sheet')
    console.log('SHEET:', (await page.getByRole('dialog').last().innerText().catch(() => '')).replace(/\n/g, ' | ').slice(0, 300))
    await page.keyboard.press('Escape')
  } else console.log('NO SHARE BUTTON')
  tokens.db = (await db<{ t: string }[]>(`SELECT share_token t FROM databases WHERE name='БЦ Живий'`))[0].t
  await back(page)

  await menu(page, 'Управління гостями')
  await page.getByLabel('Запросити гостя').click()
  await page.getByRole('button', { name: /Створити/ }).click()
  await page.waitForTimeout(1200)
  await shot(page, 'guest-created')
  console.log('GUEST LINK:', await text(page, 300))
  tokens.guest = (await db<{ t: string }[]>(`SELECT invite_token t FROM guest_links ORDER BY created_at DESC LIMIT 1`))[0]?.t
  await back(page)
  await back(page)

  await menu(page, 'Команда')
  await page.getByLabel('Запросити в команду').click()
  await page.getByRole('button', { name: /Створити/ }).click()
  await page.waitForTimeout(1200)
  await shot(page, 'team-created')
  tokens.team = (await db<{ t: string }[]>(`SELECT invite_token t FROM db_members ORDER BY created_at DESC LIMIT 1`))[0]?.t
  console.log('TOKENS:', JSON.stringify(tokens))
  expect.soft(tokens.guest).toBeTruthy()
  expect.soft(tokens.team).toBeTruthy()
})

const REALTOR: Persona = { tg_id: 700000002, first_name: 'Роман', username: 'roman' }
const GUEST: Persona = { tg_id: 700000003, first_name: 'Галина', username: 'galyna' }
const EDITOR: Persona = { tg_id: 700000004, first_name: 'Ігор', username: 'ihor' }

test('рієлтор: підписка за посиланням і підбірка', async ({ page }) => {
  test.skip(!tokens.db, 'немає токена бази')
  await reset(REALTOR)
  await open(page, REALTOR, `db_${tokens.db}`)
  await page.waitForTimeout(4000)
  await shot(page, 'realtor-entry')
  console.log('REALTOR ENTRY:', await text(page, 400))
  await page.getByRole('button', { name: /Підключити базу/ }).click()
  await page.waitForTimeout(5000)
  await shot(page, 'realtor-after-connect')
  console.log('REALTOR AFTER:', await text(page, 500))
  if (await page.getByText(/Хто ти\?/).count()) {
    await page.getByText('Ріелтор', { exact: true }).first().click()
    await page.getByRole('button', { name: /Продовжити/i }).click()
    await page.waitForTimeout(1500)
    if (await page.getByRole('button', { name: /Почати роботу/i }).count()) await page.getByRole('button', { name: /Почати роботу/i }).click()
    await page.waitForTimeout(3000)
    await shot(page, 'realtor-after-onboarding')
    console.log('REALTOR ONB:', await text(page, 500))
  }
  console.log('SUBS:', JSON.stringify(await db(`SELECT u.role, (SELECT count(*) FROM realtor_subscriptions s WHERE s.realtor_id=u.id) subs FROM users u WHERE tg_id=${REALTOR.tg_id}`)))
})

test('гість: запрошення', async ({ page }) => {
  test.skip(!tokens.guest, 'немає гостьового токена')
  await reset(GUEST)
  await open(page, GUEST, `guest_${tokens.guest}`)
  await page.waitForTimeout(4000)
  await shot(page, 'guest-entry')
  console.log('GUEST ENTRY:', await text(page, 400))
  await page.getByRole('button', { name: /Прийняти запрошення/ }).click()
  await page.waitForTimeout(5000)
  await shot(page, 'guest-after-accept')
  console.log('GUEST AFTER:', await text(page, 500))
  console.log('GUEST DB:', JSON.stringify(await db(`SELECT u.role, g.status, g.guest_name FROM users u LEFT JOIN guest_links g ON g.guest_user_id=u.id WHERE u.tg_id=${GUEST.tg_id}`)))
})

test('редактор: вступ у команду і запис', async ({ page }) => {
  test.skip(!tokens.team, 'немає токена команди')
  await reset(EDITOR)
  await open(page, EDITOR, `team_${tokens.team}`)
  await page.waitForTimeout(4000)
  await shot(page, 'editor-entry')
  console.log('EDITOR ENTRY:', await text(page, 400))
  // редактор створює обʼєкт — owner_id мусить стати власниці бази
  await page.getByLabel("Додати обʼєкт").click()
  await page.getByPlaceholder('Офіс 101').fill('Склад Ігоря')
  await page.getByPlaceholder('47').fill('30')
  await page.getByRole('button', { name: "Додати обʼєкт" }).click()
  await page.waitForTimeout(2000)
  console.log('EDITOR CREATE:', JSON.stringify(await db(`SELECT p.name, p.owner_id = d.owner_id AS owner_ok FROM properties p JOIN databases d ON d.id=p.db_id WHERE p.name='Склад Ігоря'`)))
  console.log('JOURNAL:', JSON.stringify(await db(`SELECT kind, actor_name, property_name FROM db_activity ORDER BY created_at DESC LIMIT 2`)))
  await shot(page, 'editor-after-create')
  console.log('MEMBER:', JSON.stringify(await db(`SELECT m.status, m.member_name, u.role FROM db_members m JOIN users u ON u.id=m.user_id WHERE u.tg_id=${EDITOR.tg_id}`)))
})

test('рієлтор: дашборд, підбірка, поширення', async ({ page }) => {
  await open(page, REALTOR)
  await page.waitForTimeout(4000)
  await shot(page, 'realtor-dashboard')
  console.log('RDASH:', await text(page, 500))
  await page.locator('.tabbar [aria-label="Підбірки"]').click().catch(() => console.log('no collections tab'))
  await page.waitForTimeout(2000)
  await shot(page, 'collections-empty')
  console.log('COLS:', await text(page, 300))
  await page.getByRole('button', { name: /Створити підбірку/ }).first().click()
  await page.waitForTimeout(2000)
  await shot(page, 'collection-new')
  console.log('COL NEW:', await text(page, 400))
  await page.getByText('Підбірка 1').first().click()
  await page.waitForTimeout(1500)
  await shot(page, 'collection-open')
  console.log('COL OPEN:', await text(page, 400))
  const add = page.getByRole('button', { name: /Додати обʼєкт/ }).first()
  if (await add.count()) {
    await add.click()
    await page.waitForTimeout(1500)
    await shot(page, 'collection-add-sheet')
    await page.getByRole('button', { name: /Додати до підбірки/ }).first().click()
    await page.waitForTimeout(1500)
    await page.keyboard.press('Escape')
  } else console.log('NO ADD BUTTON')
  console.log('COL DB:', JSON.stringify(await db(`SELECT c.name, c.is_draft, (SELECT count(*) FROM collection_properties cp WHERE cp.collection_id=c.id) n, c.share_token FROM collections c`)))
  await shot(page, 'collection-filled')
  const share = page.getByLabel('Поділитись підбіркою').first()
  if (await share.count() && await share.isEnabled()) {
    await share.click()
    await page.waitForTimeout(1500)
    await shot(page, 'collection-share')
    console.log('COL SHARE:', (await page.getByRole('dialog').last().innerText().catch(() => '')).replace(/\n/g, ' | ').slice(0, 300))
  }
  tokens.col = (await db<{ t: string; d: boolean }[]>(`SELECT share_token t, is_draft d FROM collections LIMIT 1`))[0]?.t ?? ''
  console.log('COL after share:', JSON.stringify(await db(`SELECT is_draft FROM collections`)))
})

test('публічна /v: база, обʼєкт, підбірка (анонім)', async ({ page }) => {
  tokens.db = (await db<{ t: string }[]>(`SELECT share_token t FROM databases WHERE name='БЦ Живий'`))[0].t
  tokens.col = (await db<{ t: string }[]>(`SELECT share_token t FROM collections WHERE is_draft = false LIMIT 1`))[0]?.t ?? ''
  const log = await installLive(page, { tg_id: 1, first_name: 'x' })
  current = log
  await page.goto(`/v/?db=${tokens.db}`)
  await page.waitForTimeout(3000)
  await shot(page, 'v-db')
  console.log('V DB:', await text(page, 400))
  const ptok = (await db<{ t: string }[]>(`SELECT share_token t FROM properties WHERE name='Офіс 201А'`))[0].t
  await page.goto(`/v/?prop=${ptok}`)
  await page.waitForTimeout(3000)
  await shot(page, 'v-prop')
  console.log('V PROP:', await text(page, 500))
  if (tokens.col) {
    await page.goto(`/v/?col=${tokens.col}`)
    await page.waitForTimeout(3000)
    await shot(page, 'v-col')
    console.log('V COL:', await text(page, 400))
  }
  console.log('PUBLIC VIEWS:', JSON.stringify(await db(`SELECT viewer_name, (property_id IS NOT NULL) p, (db_id IS NOT NULL) d, (collection_id IS NOT NULL) c FROM property_views WHERE viewer_id IS NULL`)))
})

test('власник: хто переглядав, команда, гості, відкликання', async ({ page }) => {
  await open(page, OWNER)
  await expect(page.getByText('Мої бази')).toBeVisible({ timeout: 20_000 })
  await page.locator('.tabbar [aria-label="Сповіщення"]').click()
  await page.waitForTimeout(2500)
  await shot(page, 'notifications')
  console.log('NOTIF:', await text(page, 600))
  await page.locator('.tabbar [aria-label="Бази"]').click().catch(() => page.goBack())
  await toDb(page)
  await menu(page, 'Команда')
  await page.waitForTimeout(1500)
  await shot(page, 'team-list')
  console.log('TEAM:', await text(page, 400))
  await back(page)
  await menu(page, 'Управління гостями')
  await page.waitForTimeout(1500)
  await shot(page, 'guest-list')
  console.log('GUESTS:', await text(page, 400))
  const revoke = page.getByRole('button', { name: /Відкликати/ }).first()
  if (await revoke.count()) {
    await revoke.click()
    await confirmSheet(page).catch(() => console.log('no confirm dialog'))
    await page.waitForTimeout(1500)
    console.log('REVOKE toast:', await toast(page))
  }
  console.log('GUEST LINKS:', JSON.stringify(await db(`SELECT status FROM guest_links`)))
  await back(page)
  await menu(page, 'Журнал змін')
  await page.waitForTimeout(1500)
  await shot(page, 'journal')
  console.log('JOURNAL UI:', await text(page, 500))
  await back(page)
  await menu(page, 'Архів оренд')
  await page.waitForTimeout(1500)
  await shot(page, 'tenancy-archive')
  console.log('ARCHIVE UI:', await text(page, 500))
})

test('гість після відкликання', async ({ page }) => {
  await open(page, GUEST)
  await page.waitForTimeout(4000)
  await shot(page, 'guest-revoked')
  console.log('GUEST REVOKED:', await text(page, 400))
})

test('власник: експорт CSV → імпорт назад', async ({ page }) => {
  await page.addInitScript(() => {
    const w = window as unknown as { __files: { name: string; text: string; size: number }[] }
    w.__files = []
    Object.defineProperty(navigator, 'canShare', { value: () => true, configurable: true })
    Object.defineProperty(navigator, 'share', {
      configurable: true,
      value: async (data: { files?: File[] }) => {
        for (const f of data.files ?? []) w.__files.push({ name: f.name, text: f.type.includes('csv') ? await f.text() : '', size: f.size })
      },
    })
  })
  await open(page, OWNER)
  await toDb(page)
  await menu(page, 'Експорт')
  await page.waitForTimeout(800)
  await shot(page, 'export')
  for (const [fmt, btn] of [['PDF Документ', /Завантажити PDF/], ['Excel таблиця', /Завантажити Excel/], ['CSV таблиця', /Завантажити CSV/]] as const) {
    await page.getByText(fmt, { exact: true }).click()
    await page.getByRole('button', { name: btn }).click()
    await page.waitForTimeout(2500)
  }
  const files = await page.evaluate(() => (window as unknown as { __files: { name: string; text: string; size: number }[] }).__files)
  console.log('EXPORT files:', files.map((f) => `${f.name} ${f.size}B`).join(', '))
  const csv = files.find((f) => f.name.endsWith('.csv'))?.text ?? ''
  console.log('CSV head:', csv.split('\n').slice(0, 3).join(' ⏎ '))
  expect.soft(files.length).toBe(3)

  await back(page)
  await menu(page, 'Імпорт із CSV')
  await page.waitForTimeout(800)
  const lines = csv.replace(/^﻿/, '').split(/\r?\n/)
  const re = [lines[0], ...lines.slice(1).filter(Boolean).map((l, i) => l.replace(/^([^,]*),([^,]*)/, `$1,Імпорт ${i + 1}`))].join('\n')
  await page.locator('input[type="file"]').setInputFiles({ name: 'back.csv', mimeType: 'text/csv', buffer: Buffer.from(re) })
  await page.waitForTimeout(1000)
  await shot(page, 'import-preview')
  console.log('IMPORT preview:', await text(page, 400))
  await page.getByRole('button', { name: /Імпортувати/ }).click()
  await page.waitForTimeout(2500)
  console.log('IMPORT toast:', await toast(page))
  console.log('IMPORTED:', JSON.stringify(await db(`SELECT name, rent_rate, area_useful, area_basis, status FROM properties WHERE name LIKE 'Імпорт%'`)))
})

test('власник: профіль — мова, валюта, контакти', async ({ page }) => {
  await open(page, OWNER)
  await expect(page.getByText('Мої бази')).toBeVisible({ timeout: 20_000 })
  await page.locator('.tabbar [aria-label="Профіль"]').click()
  await page.waitForTimeout(1500)
  await shot(page, 'profile')
  await page.getByRole('button', { name: 'UAH' }).click()
  await page.waitForTimeout(1200)
  await page.getByRole('button', { name: 'Eng' }).click()
  await page.waitForTimeout(2000)
  await shot(page, 'profile-en')
  console.log('PROFILE EN:', await text(page, 300))
  await page.getByLabel('Phone').fill('abc').catch(() => page.getByLabel('Телефон').fill('abc'))
  await page.getByLabel('Email').click()
  await page.waitForTimeout(800)
  console.log('PHONE bad toast:', await toast(page))
  await page.getByLabel('Phone').fill('+380671234567').catch(() => page.getByLabel('Телефон').fill('+380671234567'))
  await page.getByLabel('Email').fill('not-an-email')
  await page.getByLabel('Phone').click().catch(() => page.getByLabel('Телефон').click())
  await page.waitForTimeout(1500)
  console.log('EMAIL bad toast:', await toast(page), JSON.stringify(await db(`SELECT email FROM users WHERE tg_id=${OWNER.tg_id}`)))
  await page.getByLabel('Email').fill('olena@example.com')
  await page.locator('body').click({ position: { x: 5, y: 5 } })
  await page.waitForTimeout(1500)
  console.log('USER:', JSON.stringify(await db(`SELECT language_code, currency, phone, email FROM users WHERE tg_id=${OWNER.tg_id}`)))
  // назад на українську й долар — решта проходу асертить український текст
  await page.getByRole('button', { name: 'Ukr' }).click()
  await page.waitForTimeout(1500)
  await page.getByRole('button', { name: 'USD' }).click()
  await page.waitForTimeout(1200)
  console.log('USER after:', JSON.stringify(await db(`SELECT language_code, currency FROM users WHERE tg_id=${OWNER.tg_id}`)))
})

test('власник: видалити редактора з команди → редактор без запису', async ({ page }) => {
  await open(page, OWNER)
  await toDb(page)
  await menu(page, 'Команда')
  await page.waitForTimeout(1500)
  const revoke = page.getByRole('button', { name: /Відкликати/ }).first()
  if (await revoke.count()) {
    await revoke.click()
    await confirmSheet(page).catch(() => console.log('no confirm dialog'))
    await page.waitForTimeout(1500)
    console.log('TEAM revoke toast:', await toast(page))
  } else console.log('NO TEAM REVOKE')
  console.log('MEMBERS:', JSON.stringify(await db(`SELECT status, member_name FROM db_members`)))
})

test('редактор після відкликання', async ({ page }) => {
  await open(page, EDITOR)
  await page.waitForTimeout(4000)
  await shot(page, 'editor-revoked')
  console.log('EDITOR REVOKED:', await text(page, 400))
})

test('власник: оновити посилання → рієлтор втрачає доступ', async ({ page }) => {
  await open(page, OWNER)
  await toDb(page)
  await menu(page, 'Аналітика і поширення')
  await page.waitForTimeout(1500)
  await page.getByRole('button', { name: /Поділитись|Поділитися|Посилання/ }).first().click()
  await page.waitForTimeout(1200)
  const rot = page.getByRole('dialog').last().getByRole('button', { name: /Оновити посилання/ }).first()
  console.log('SHARE SHEET:', (await page.getByRole('dialog').last().innerText().catch(() => '')).replace(/\n/g, ' | ').slice(0, 300))
  if (await rot.count()) {
    await rot.click()
    await page.waitForTimeout(600); if (await page.getByRole('dialog').count() > 1) await confirmSheet(page)
    await page.waitForTimeout(1500)
    console.log('ROTATE toast:', await toast(page))
  }
  console.log('SUBS:', JSON.stringify(await db(`SELECT count(*) n FROM realtor_subscriptions`)))
})

test('рієлтор після оновлення посилання', async ({ page }) => {
  await open(page, REALTOR)
  await page.waitForTimeout(4000)
  await shot(page, 'realtor-after-rotate')
  console.log('REALTOR AFTER:', await text(page, 400))
})

test('власник: видалити обʼєкт із фото, видалити базу', async ({ page }) => {
  await open(page, OWNER)
  const before = await db<{ b: string; n: number }[]>(`SELECT bucket_id b, count(*)::int n FROM storage.objects GROUP BY 1`)
  console.log('STORAGE before:', JSON.stringify(before))
  await openProp(page, 'Офіс 201А')
  await page.getByLabel(/Редагувати/).first().click()
  await page.getByRole('button', { name: /Видалити/ }).last().click()
  await confirmSheet(page).catch(() => console.log('no confirm dialog'))
  await page.waitForTimeout(2000)
  console.log('DEL PROP toast:', await toast(page))
  console.log('PROP left:', JSON.stringify(await db(`SELECT count(*) n FROM properties WHERE name='Офіс 201А'`)))
  console.log('STORAGE after prop:', JSON.stringify(await db(`SELECT bucket_id b, count(*)::int n FROM storage.objects GROUP BY 1`)))
  console.log('TENANCY kept:', JSON.stringify(await db(`SELECT property_name, property_id IS NULL detached FROM tenancies`)))
})

test('власник: видалити акаунт', async ({ page }) => {
  await open(page, OWNER)
  await expect(page.getByText('Мої бази')).toBeVisible({ timeout: 20_000 })
  await page.locator('.tabbar [aria-label="Профіль"]').click()
  await page.getByText('Видалити акаунт').click()
  await page.waitForTimeout(800)
  await page.getByPlaceholder('ВИДАЛИТИ').fill('ВИДАЛИТИ')
  await shot(page, 'delete-account')
  await page.locator('button.mbtn').click()
  await page.waitForTimeout(3000)
  await shot(page, 'after-delete-account')
  console.log('AFTER DELETE:', await text(page, 200))
  console.log('LEFT:', JSON.stringify(await db(`SELECT (SELECT count(*) FROM users WHERE tg_id=${OWNER.tg_id}) u, (SELECT count(*) FROM auth.users WHERE email='${OWNER.tg_id}@telegram.propspace.app') a, (SELECT count(*) FROM databases) d, (SELECT count(*) FROM storage.objects) s, (SELECT count(*) FROM property_views WHERE viewer_name='Олена') vn`)))
  const ls = await page.evaluate(() => Object.keys(localStorage))
  console.log('LOCALSTORAGE after:', ls.join(', '))
})

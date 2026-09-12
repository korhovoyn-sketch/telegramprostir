import { test, expect, type Page } from '@playwright/test'
import { deflateSync } from 'node:zlib'
import {
  setupApp, DEFAULT_USER, skipCoachmarks, seedSession, jsonRoute as json,
} from './helpers/harness'

/**
 * РИЗИКОВІ МОМЕНТИ ВВЕДЕННЯ — запит власника: повторне введення, не ті поля,
 * не той формат документа, перевантаження документами.
 *
 * Спільне в усьому класі: помилку робить не код, а ЛЮДИНА, і питання лише в
 * тому, чи скаже їй застосунок. Наявний набір це майже не міряв — він
 * перевіряв ЩАСЛИВІ шляхи (правильний файл, одне натискання, унікальна назва),
 * а всі знайдені тут дефекти живуть рівно поза ними.
 *
 * Кожен тест нижче ПАДАВ до свого фікса; фальсифікації описані в PR.
 */

const USER = { ...DEFAULT_USER, role: 'owner' as const, first_name: 'Микола' }
const DB_ID = '10000000-0000-0000-0000-000000000001'
const PROP_ID = '20000000-0000-0000-0000-000000000001'
const NOW = new Date().toISOString()

const DB = {
  id: DB_ID, owner_id: USER.id, name: 'БЦ Рубін', address: 'вул. Хрещатик, 1',
  type: 'business_center', color: 'pink', share_token: 'aabbccddeeff001122334455',
  share_expires_at: null, created_at: NOW, updated_at: NOW, landlord_name: null,
  properties: [{ status: 'free', rent_rate: 18, area_useful: 100, rent_type: 'per_m2' }],
}

const PROP = {
  id: PROP_ID, db_id: DB_ID, owner_id: USER.id, name: 'Офіс 101', floor: '2',
  status: 'free', area_useful: 100, area_total: 120, area_basis: 'useful',
  rent_type: 'per_m2', rent_rate: 18, utilities_rate: null,
  has_parking: false, parking_spaces: 0, parking_type: null, ev_charger: false,
  utilities: null, description: null, address: null, sale_price: null,
  tenant_name: null, lease_start_date: null, lease_end_date: null,
  folder_id: null, landlord_name: null, sort_order: 100,
  share_token: 'bb00000000000000000000_1', share_expires_at: null,
  created_at: NOW, updated_at: NOW, photos: [],
}

const PNG = Buffer.from(
  'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg==',
  'base64',
)

/**
 * СПРАВЖНІЙ великий PNG, а не буфер випадкових байтів. Перша редакція гарда
 * подавала `Buffer.alloc(11MB)` — і тест падав ЧЕСНО, але не з тієї причини:
 * такий буфер не декодується, `compressImage` fail-open віддає оригінал, і
 * 11 МБ законно відсіюються фінальною межею. Тобто фікстура міряла б не те,
 * заради чого писалась. Шум у пікселях обовʼязковий: рівна заливка стиснеться
 * zlib-ом у кілобайти і потрібного розміру не дасть.
 */
function bigPng(w: number, h: number): Buffer {
  const chunk = (type: string, data: Buffer) => {
    const len = Buffer.alloc(4); len.writeUInt32BE(data.length)
    const body = Buffer.concat([Buffer.from(type, 'ascii'), data])
    const crc = Buffer.alloc(4); crc.writeUInt32BE(crc32(body))
    return Buffer.concat([len, body, crc])
  }
  const raw = Buffer.alloc(h * (1 + w * 3))
  let seed = 1
  for (let y = 0; y < h; y++) {
    const off = y * (1 + w * 3)
    raw[off] = 0
    for (let i = 0; i < w * 3; i++) {
      seed = (seed * 1103515245 + 12345) & 0x7fffffff
      raw[off + 1 + i] = seed & 0xff
    }
  }
  const ihdr = Buffer.alloc(13)
  ihdr.writeUInt32BE(w, 0); ihdr.writeUInt32BE(h, 4)
  ihdr[8] = 8; ihdr[9] = 2
  return Buffer.concat([
    Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]),
    chunk('IHDR', ihdr),
    chunk('IDAT', deflateSync(raw, { level: 0 })),
    chunk('IEND', Buffer.alloc(0)),
  ])
}

const CRC_TABLE = (() => {
  const t = new Int32Array(256)
  for (let n = 0; n < 256; n++) {
    let c = n
    for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1
    t[n] = c
  }
  return t
})()
function crc32(buf: Buffer): number {
  let c = 0xffffffff
  for (let i = 0; i < buf.length; i++) c = CRC_TABLE[(c ^ buf[i]) & 0xff] ^ (c >>> 8)
  return (c ^ 0xffffffff) >>> 0
}

async function ownerFixtures(page: Page) {
  await setupApp(page, { user: USER })
  await seedSession(page, USER as unknown as Record<string, unknown>)
  await skipCoachmarks(page)
  await page.route('**/rest/v1/databases**', (r) =>
    json(r, (r.request().headers()['accept'] ?? '').includes('object') ? DB : [DB]))
  await page.route('**/rest/v1/db_members**', (r) => json(r, []))
  for (const t of ['property_folders', 'property_views', 'notifications',
                   'rent_payments', 'rent_payment_records', 'collections', 'guest_links']) {
    await page.route(`**/rest/v1/${t}**`, (r) => json(r, []))
  }
}

async function atProperty(page: Page) {
  await page.goto('/')
  await expect(page.getByText('Мої бази')).toBeVisible({ timeout: 25_000 })
  await page.getByText('БЦ Рубін').first().click()
  await page.locator('.obj-card .obj-t', { hasText: 'Офіс 101' }).click()
  await expect(page.getByText('Фотографії')).toBeVisible({ timeout: 15_000 })
}

// ─────────────────────────────────────────────────────────────────────────────
// НЕ ТОЙ ФОРМАТ ДОКУМЕНТА
// ─────────────────────────────────────────────────────────────────────────────

test('формат: .docx без MIME від ОС доїжджає до сервера як docx', async ({ page }) => {
  // НАЙДОРОЖЧИЙ із знайдених. `file.type` береться з реєстру ОС, тож для .docx
  // він законно порожній (Windows без Office) — а завантажувач вимагав точний
  // збіг і відхиляв. Заміряно: з пʼяти реальних комбінацій проходила ОДНА.
  // Тобто договір — головний документ продукту — завантажити було НЕМОЖЛИВО.
  test.setTimeout(90_000)
  await ownerFixtures(page)
  const validated: Record<string, unknown>[] = []
  const rows: Record<string, unknown>[] = []
  await page.route('**/rest/v1/properties**', (r) =>
    json(r, (r.request().headers()['accept'] ?? '').includes('object') ? PROP : [PROP]))
  await page.route('**/functions/v1/validate-upload', (r) => {
    validated.push(JSON.parse(r.request().postData() ?? '{}'))
    return json(r, { uploadUrl: 'https://stub.local/put', storagePath: `${PROP_ID}/1_a.docx` })
  })
  await page.route('https://stub.local/put', (r) => r.fulfill({ status: 200, body: '{}' }))
  await page.route('**/rest/v1/property_files**', (r) => {
    if (r.request().method() === 'POST') {
      const b = JSON.parse(r.request().postData() ?? '{}')
      rows.push(b)
      return json(r, [{ id: '90000000-0000-0000-0000-000000000001', created_at: NOW, ...b }], 201)
    }
    return json(r, rows)
  })

  await atProperty(page)
  // `application/octet-stream` — те, що віддають Android і частина файлових
  // менеджерів. ПОРОЖНІЙ тип (Windows без Office) відтворити цим API не можна:
  // заміряно — `setInputFiles({ mimeType: '' })` сам виводить тип із
  // РОЗШИРЕННЯ і подає браузеру ідеальний docx, тобто тест на ньому був би
  // ВАКУУМНИЙ. Спіймано власною фальсифікацією: зі строгою перевіркою,
  // поверненою назад, він проходив.
  await page.locator('input[type="file"][accept=".pdf,.doc,.docx"]').setInputFiles([
    { name: 'Договір оренди.docx', mimeType: 'application/octet-stream', buffer: Buffer.from('PK\x03\x04docx') },
  ])

  await expect.poll(() => validated.length, {
    message: 'файл навіть не дійшов до validate-upload — відсіяв клієнтський фільтр',
    timeout: 20_000,
  }).toBe(1)
  // Значення мусить бути з енуму edge-функції, інакше вона віддасть 400.
  expect(validated[0].mimeType,
    'на сервер поїхав порожній тип — edge-функція відповість 400')
    .toBe('application/vnd.openxmlformats-officedocument.wordprocessingml.document')
  await expect.poll(() => rows.length, { timeout: 20_000 }).toBe(1)
  expect(rows[0].mime_type, 'у колонку ліг порожній тип').not.toBe('')
})

test('формат: чужий файл відхиляється, і причина названа', async ({ page }) => {
  // АНТИВАКУУМ до попереднього: «виводь тип із розширення» не сміє означати
  // «приймай усе». Без цієї половини фікс міг би пропускати .exe під виглядом
  // документа.
  test.setTimeout(90_000)
  await ownerFixtures(page)
  let validateCalls = 0
  await page.route('**/rest/v1/properties**', (r) =>
    json(r, (r.request().headers()['accept'] ?? '').includes('object') ? PROP : [PROP]))
  await page.route('**/functions/v1/validate-upload', (r) => {
    validateCalls++
    return json(r, { uploadUrl: 'https://stub.local/put', storagePath: 'x' })
  })
  await page.route('**/rest/v1/property_files**', (r) => json(r, []))

  await atProperty(page)
  await page.locator('input[type="file"][accept=".pdf,.doc,.docx"]').setInputFiles([
    { name: 'таблиця.xlsx', mimeType: 'application/vnd.ms-excel', buffer: Buffer.from('x') },
  ])

  await expect(page.getByText(/формат не підтримується/i)).toBeVisible({ timeout: 15_000 })
  expect(validateCalls, 'чужий файл усе одно поїхав на сервер').toBe(0)
})

// ─────────────────────────────────────────────────────────────────────────────
// ПЕРЕВАНТАЖЕННЯ ДОКУМЕНТАМИ
// ─────────────────────────────────────────────────────────────────────────────

test('перевантаження: межа фото рахується НА ОБʼЄКТ, а не на партію', async ({ page }) => {
  // MAX_PHOTOS=20 обмежував рівно один захід, а лічильник наявних читався лише
  // заради нумерації — тобто 20 + 20 + 20 клалось без жодного слова. Документи
  // цю дисципліну мали з самого початку (MAX_FILES звіряється з БД), фото — ні.
  test.setTimeout(90_000)
  await ownerFixtures(page)
  const posts: string[] = []
  await page.route('**/rest/v1/properties**', (r) =>
    json(r, (r.request().headers()['accept'] ?? '').includes('object') ? PROP : [PROP]))
  // Обʼєкт УЖЕ має 20 фото — рівно межа.
  await page.route('**/rest/v1/property_photos**', (r) => {
    if (r.request().method() === 'POST') { posts.push('x'); return json(r, [{ id: 'p' }], 201) }
    // count=exact, head:true → лічильник живе в Content-Range, не в тілі.
    return r.fulfill({
      status: 200, contentType: 'application/json',
      headers: { 'content-range': '0-19/20', 'access-control-expose-headers': 'content-range' },
      body: '[]',
    })
  })
  await page.route('**/storage/v1/object/photos/**', (r) => json(r, { Key: 'photos/x' }))

  await atProperty(page)
  await page.locator('input[type="file"][accept="image/*"]').setInputFiles([
    { name: 'a.png', mimeType: 'image/png', buffer: PNG },
  ])

  await expect(page.getByText(/Максимум 20 фото на обʼєкт/)).toBeVisible({ timeout: 20_000 })
  // Головне: у storage НЕ поїхало нічого.
  await page.waitForTimeout(1500)
  expect(posts.length, '21-ше фото все одно записалось').toBe(0)
})

test('перевантаження: ЧАСТКОВИЙ відсів не мовчить, а великий кадр ПРОХОДИТЬ', async ({ page }) => {
  // Дві половини одного правила, і друга важливіша за першу.
  //
  // (1) Тост про відсів існував лише для «відсіялись УСІ» і для «>20». Обравши
  //     три знімки і отримавши один, користувач бачив «1 фото завантажено» —
  //     цифру, що не збігається з вибором, і жодного пояснення.
  // (2) Фільтр екрана відкидав усе понад 10 МБ ДО стиснення — хоч конвеєр
  //     навмисно стискає кадр саме для того, щоб 12-мегабайтний знімок пройшов
  //     (це прямо написано в `photoUpload.ts`). Тобто звичайне фото з сучасного
  //     телефона не завантажувалось узагалі.
  test.setTimeout(90_000)
  await ownerFixtures(page)
  const posts: string[] = []
  await page.route('**/rest/v1/properties**', (r) =>
    json(r, (r.request().headers()['accept'] ?? '').includes('object') ? PROP : [PROP]))
  await page.route('**/rest/v1/property_photos**', (r) =>
    r.request().method() === 'POST'
      ? (posts.push('x'), json(r, [{ id: `p${posts.length}` }], 201))
      : r.fulfill({ status: 200, contentType: 'application/json',
          headers: { 'content-range': '*/0' }, body: '[]' }))
  await page.route('**/storage/v1/object/photos/**', (r) => json(r, { Key: 'photos/x' }))

  await atProperty(page)
  // Великий «кадр із камери» (11 МБ) + не-зображення. Перший мусить ПРОЙТИ,
  // другий — бути названим.
  await page.locator('input[type="file"][accept="image/*"]').setInputFiles([
    { name: 'IMG_0042.png', mimeType: 'image/png', buffer: bigPng(1900, 1900) },
    { name: 'нотатки.txt', mimeType: 'text/plain', buffer: Buffer.from('не фото') },
  ])

  // Міряється ПЕРСИСТЕНТНИЙ рядок екрана, а не тост: стор тримає рівно один
  // тост, тож підсумок завантаження затирав би попередження — і в тесті, і в
  // користувача. Перша редакція гарда саме на цьому й «флейкнула», показавши
  // справжній дефект, а не власну нестабільність.
  await expect(page.locator('.fr-note').filter({ hasText: /Не зображення: 1/ }))
    .toBeVisible({ timeout: 20_000 })

  // АНТИВАКУУМ і водночас головне: 11-мегабайтний знімок НЕ відсіявся.
  await expect.poll(() => posts.length, {
    message: 'великий кадр із камери відсіявся ДО стиснення — конвеєр позбавлено сенсу',
    timeout: 30_000,
  }).toBe(1)
})

test('перевантаження: зріз ПАРТІЇ не мовчить, і підпис називає ВСІ причини', async ({ page }) => {
  // Два боки ОДНІЄЇ помилки обліку, обидва — моя ж регресія попереднього раунду.
  //
  // (1) `files = validFiles.slice(0, MAX_PHOTOS)` різав партію ДО перевірки
  //     місткості, тож на ПОРОЖНЬОМУ обʼєкті пізніша умова рахувала `20 > 20`
  //     — хибу. 22 обраних фото ставали 20 без тоста і без напису.
  // (2) `skipReason` був ТЕРНАРНИМ вибором ОДНІЄЇ причини, тоді як `skipped`
  //     рахував суму: «не зображення» ховало «понад межу», і підпис
  //     суперечив би цифрі, якби цифру десь показали.
  test.setTimeout(120_000)
  await ownerFixtures(page)
  await page.route('**/rest/v1/properties**', (r) =>
    json(r, (r.request().headers()['accept'] ?? '').includes('object') ? PROP : [PROP]))
  // Обʼєкт ПОРОЖНІЙ — саме той випадок, де зріз партії був німим.
  await page.route('**/rest/v1/property_photos**', (r) =>
    r.request().method() === 'POST'
      ? json(r, [{ id: 'p' }], 201)
      : r.fulfill({ status: 200, contentType: 'application/json',
          headers: { 'content-range': '*/0' }, body: '[]' }))
  await page.route('**/storage/v1/object/photos/**', (r) => json(r, { Key: 'photos/x' }))

  await atProperty(page)
  // 22 придатні + одне не-зображення: межа партії (20) зрізає ДВА, фільтр — ОДНЕ.
  const picked = Array.from({ length: 22 }, (_, i) => ({
    name: `IMG_${i}.png`, mimeType: 'image/png', buffer: PNG,
  }))
  picked.push({ name: 'нотатки.txt', mimeType: 'text/plain', buffer: Buffer.from('не фото') })
  await page.locator('input[type="file"][accept="image/*"]').setInputFiles(picked)

  // Персистентний рядок, а не тост: стор тримає рівно ОДИН тост (див. сусідній
  // гард). Обидві причини мусять бути НАЗВАНІ — саме це й ламав тернарний вибір.
  const note = page.locator('.fr-note')
  await expect(note).toBeVisible({ timeout: 25_000 })
  await expect(note, 'підпис не назвав відсіяне не-зображення').toContainText(/Не зображення: 1/)
  await expect(note, 'зріз партії лишився німим — 22 фото мовчки стали 20')
    .toContainText(/Понад межу 20 фото: 2/)
})

test('перевантаження: непридатний файл на ПОВНОМУ обʼєкті чує про ФОРМАТ', async ({ page }) => {
  // Перевірка місткості стояла ПЕРЕД перевіркою формату, тож на межі .txt
  // діставав «Максимум 10 файлів на обʼєкт» — підказку, яка веде НЕ ТУДИ
  // (видалити зайве замість узяти інший файл). Друга половина: кожна причина
  // йшла окремим `onError`, а стор тримає ОДИН тост, тож останній викликач
  // затирав попередніх — із трьох відхилених користувач читав лише одну
  // причину і вважав решту завантаженою.
  test.setTimeout(90_000)
  await ownerFixtures(page)
  await page.route('**/rest/v1/properties**', (r) =>
    json(r, (r.request().headers()['accept'] ?? '').includes('object') ? PROP : [PROP]))
  let validateCalls = 0
  await page.route('**/functions/v1/validate-upload', (r) => {
    validateCalls++
    return json(r, { uploadUrl: 'https://stub.local/put', storagePath: 'x' })
  })
  // Обʼєкт УЖЕ повний: 10 із 10.
  await page.route('**/rest/v1/property_files**', (r) => r.fulfill({
    status: 200, contentType: 'application/json',
    headers: { 'content-range': '0-9/10', 'access-control-expose-headers': 'content-range' },
    body: '[]',
  }))

  await atProperty(page)
  await page.locator('input[type="file"][accept=".pdf,.doc,.docx"]').setInputFiles([
    { name: 'нотатки.txt', mimeType: 'text/plain', buffer: Buffer.from('не документ') },
  ])

  await expect(page.locator('.toast'), 'причиною названо кількість, а не формат')
    .toContainText(/формат не підтримується/i, { timeout: 20_000 })
  // АНТИВАКУУМ: файл справді не поїхав на сервер — тобто фікс не «пропустив
  // усе», а лише виправив ДІАГНОЗ.
  await page.waitForTimeout(800)
  expect(validateCalls, 'непридатний файл усе одно поїхав на сервер').toBe(0)
})

test('конвеєр документів: ОДИН тост на партію, і він називає ОБИДВІ причини', async ({ page }) => {
  // Стор тримає рівно ОДИН тост — це властивість архітектури, тож поки
  // `onError` кличеться з кожної гілки шляху, ОСТАННЄ ЗА ЧАСОМ виграє
  // незалежно від важливості. Передперевірка формату це вже визнавала й
  // агрегувала причини, а цикл завантаження її скасовував шістьма власними
  // викликами: партія «непридатний + той, що впаде» показувала лише збій
  // завантаження, і про відхилений ФОРМАТ користувач не дізнавався НІКОЛИ.
  test.setTimeout(90_000)
  await ownerFixtures(page)
  await page.route('**/rest/v1/properties**', (r) =>
    json(r, (r.request().headers()['accept'] ?? '').includes('object') ? PROP : [PROP]))
  await page.route('**/rest/v1/property_files**', (r) => json(r, []))
  await page.route('**/functions/v1/validate-upload', (r) =>
    json(r, { uploadUrl: 'https://stub.local/put', storagePath: `${PROP_ID}/1_a.pdf` }))
  // PUT падає — саме та гілка, що затирала повідомлення про формат.
  await page.route('https://stub.local/put', (r) => r.fulfill({ status: 500, body: '' }))

  await atProperty(page)
  await page.locator('input[type="file"][accept=".pdf,.doc,.docx"]').setInputFiles([
    { name: 'нотатки.txt', mimeType: 'text/plain', buffer: Buffer.from('не документ') },
    { name: 'Договір.pdf', mimeType: 'application/pdf', buffer: Buffer.from('%PDF-1.4') },
  ])

  const toast = page.locator('.toast')
  await expect(toast).toBeVisible({ timeout: 20_000 })
  // Обидві причини в ОДНОМУ повідомленні. До фікса тут лишалась тільки друга.
  await expect(toast, 'формат відхиленого файлу затерло повідомлення про збій завантаження')
    .toContainText(/формат не підтримується/i)
  await expect(toast, 'збій завантаження не названий').toContainText(/Договір\.pdf/)
})

test('конвеєр документів: збій INSERT прибирає файл, а не лишає сироту', async ({ page }) => {
  // Передперевірка власності обіцяла в коментарі, що осиротілих не буде — але
  // це був лише ПЕРЕДчек: усе, що падало ПІСЛЯ аплоуду, лишало файл у сховищі
  // назавжди. Сусідній конвеєр фото (`photoUpload.ts`) прибирання мав; цей ні.
  test.setTimeout(90_000)
  await ownerFixtures(page)
  const removed: string[] = []
  await page.route('**/rest/v1/properties**', (r) =>
    json(r, (r.request().headers()['accept'] ?? '').includes('object') ? PROP : [PROP]))
  await page.route('**/functions/v1/validate-upload', (r) =>
    json(r, { uploadUrl: 'https://stub.local/put', storagePath: `${PROP_ID}/1_dogovir.pdf` }))
  await page.route('https://stub.local/put', (r) => r.fulfill({ status: 200, body: '{}' }))
  // INSERT відмовляє — рядок не зʼявився, отже файл у сховищі нічим не адресований.
  await page.route('**/rest/v1/property_files**', (r) =>
    r.request().method() === 'POST'
      ? r.fulfill({ status: 403, contentType: 'application/json',
          body: JSON.stringify({ message: 'new row violates row-level security policy for table "property_files"' }) })
      : json(r, []))
  await page.route('**/storage/v1/object/property-files**', (r) => {
    if (r.request().method() === 'DELETE') {
      removed.push(r.request().postData() ?? '')
      return json(r, [{ name: `${PROP_ID}/1_dogovir.pdf` }])
    }
    return json(r, {})
  })

  await atProperty(page)
  await page.locator('input[type="file"][accept=".pdf,.doc,.docx"]').setInputFiles([
    { name: 'Договір.pdf', mimeType: 'application/pdf', buffer: Buffer.from('%PDF-1.4') },
  ])

  await expect.poll(() => removed.length, {
    message: 'файл лишився у сховищі без рядка — осиротів назавжди',
    timeout: 20_000,
  }).toBe(1)
  expect(removed[0], 'прибрано не той шлях').toContain('1_dogovir.pdf')

  // ДРУГА ПОЛОВИНА: сира `message` від PostgREST несе назву таблиці й текст
  // політики — вона не сміє доїхати в тост (правило 1 Security rules).
  const toast = page.locator('.toast')
  await expect(toast).toBeVisible()
  await expect(toast, 'у тост протекла внутрішня деталь БД')
    .not.toContainText(/row-level security|property_files/i)
})

// ─────────────────────────────────────────────────────────────────────────────
// ПОВТОРНЕ ВВЕДЕННЯ
// ─────────────────────────────────────────────────────────────────────────────

test('повторне: два швидкі тапи «Створити підбірку» дають ОДНУ', async ({ page }) => {
  // Гарда не було взагалі, а назва бралась із `collections.length + 1` — тобто
  // обидва виклики читали ту саму довжину і створювали ДВІ підбірки з
  // ОДНАКОВОЮ назвою. Найгірша форма дубля: їх не відрізнити очима.
  test.setTimeout(90_000)
  const REALTOR = { ...DEFAULT_USER, role: 'realtor' as const, first_name: 'Олена' }
  await setupApp(page, { user: REALTOR })
  await seedSession(page, REALTOR as unknown as Record<string, unknown>)
  await skipCoachmarks(page)
  await page.route('**/rest/v1/realtor_subscriptions**', (r) => json(r, []))
  await page.route('**/rest/v1/databases**', (r) => json(r, []))
  await page.route('**/rest/v1/db_members**', (r) => json(r, []))
  for (const t of ['property_views', 'notifications', 'collection_properties']) {
    await page.route(`**/rest/v1/${t}**`, (r) => json(r, []))
  }

  const posts: Record<string, unknown>[] = []
  await page.route('**/rest/v1/collections**', async (r) => {
    if (r.request().method() === 'POST') {
      posts.push(JSON.parse(r.request().postData() ?? '{}'))
      // Повільна відповідь — саме вікно, у яке проскакував другий тап. З
      // миттєвою мок-відповіддю тест був би зелений і БЕЗ гарда.
      await new Promise((res) => setTimeout(res, 900))
      return json(r, [{
        id: `70000000-0000-0000-0000-00000000000${posts.length}`,
        realtor_id: REALTOR.id, name: `Підбірка ${posts.length}`, is_draft: true,
        share_token: 'ff00112233445566778899aa', share_expires_at: null,
        created_at: NOW, updated_at: NOW,
      }], 201)
    }
    return json(r, [])
  })

  await page.goto('/')
  await expect(page.getByText('Робочі бази')).toBeVisible({ timeout: 25_000 })
  await page.locator('.tabbar [aria-label="Підбірки"]').click()

  const cta = page.getByRole('button', { name: 'Створити підбірку' }).first()
  await expect(cta).toBeVisible({ timeout: 15_000 })

  // ДВА СИНХРОННІ кліки по ТОМУ САМОМУ вузлу — це і є подвійний тап, і саме
  // найгірший його випадок: `disabled` зʼявиться лише НАСТУПНИМ рендером, тож
  // тут перевіряється рівно синхронний ref-гард, а не візуальна неактивність.
  //
  // Два окремі `cta.click()` для цього не годяться з двох причин: між ними є
  // затримка, за яку React устигає перемалювати, і сам локатор чіпляється за
  // плаваючу кнопку, яку перекриває таббар (заміряно — 170 повторів
  // «intercepts pointer events» до таймауту). Тобто попередня редакція гарда
  // падала на ГЕОМЕТРІЇ, а не на коді.
  await cta.evaluate((el: HTMLElement) => { el.click(); el.click() })

  await page.waitForTimeout(2500)
  expect(posts.length, `створено ${posts.length} підбірок замість однієї`).toBe(1)
})

test('повторне: дублікат назви обʼєкта попереджає ДО збереження', async ({ page }) => {
  // Імпорт із CSV дублікати пропускає і перелічує поіменно, а ручне введення
  // мовчки клало другий такий самий рядок — той самий застосунок відповідав на
  // те саме питання двома різними способами.
  test.setTimeout(90_000)
  await ownerFixtures(page)
  await page.route('**/rest/v1/properties**', (r) =>
    json(r, (r.request().headers()['accept'] ?? '').includes('object') ? PROP : [PROP]))

  await page.goto('/')
  await expect(page.getByText('Мої бази')).toBeVisible({ timeout: 25_000 })
  await page.getByText('БЦ Рубін').first().click()
  await expect(page.locator('.obj-card .obj-t').first()).toBeVisible({ timeout: 15_000 })
  await page.getByRole('button', { name: /Додати обʼєкт/ }).first().click()

  const nameField = page.getByLabel('Назва обʼєкта')
  await expect(nameField).toBeVisible({ timeout: 15_000 })

  // Унікальна назва — тиша.
  await nameField.fill('Офіс 202')
  await expect(page.getByText('Обʼєкт із такою назвою вже є в базі')).toHaveCount(0)

  // Та сама назва в іншому регістрі й із пробілами — для людини це дубль.
  await nameField.fill('  офіс 101 ')
  await expect(page.getByText('Обʼєкт із такою назвою вже є в базі'))
    .toBeVisible({ timeout: 5_000 })

  // ПОПЕРЕДЖЕННЯ, А НЕ ЗАБОРОНА: два «Комора» бувають законно, тож кнопка
  // збереження мусить лишатись активною.
  await expect(page.locator('.mbtn').first()).toBeEnabled()
})

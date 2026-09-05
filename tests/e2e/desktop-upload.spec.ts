import { test, expect, type Page, type Browser } from '@playwright/test'
import { setupApp, DEFAULT_USER, skipCoachmarks, jsonRoute as json } from './helpers/harness'

/**
 * ДОДАВАННЯ ФАЙЛІВ І ФОТО З КОМПʼЮТЕРА.
 *
 * На телефоні аплоуд покритий (`deep-lifecycle`), але рівно на 375 і рівно
 * для ФОТО. Тут закриваються дві інші прогалини, і обидві реальні:
 *
 * 1. ДЕСКТОПНА ШИРИНА. Кнопки додавання живуть у колонці читання, яку цей
 *    раунд і завів; якщо колонка їх сховає, обріже або винесе за рамку —
 *    «аплоуд працює» на API-рівні нічого не варте. Тому гард спершу МІРЯЄ
 *    афорданс (видимий, у межах рамки, ≥44px), і лише потім жене файли.
 * 2. ДОКУМЕНТИ. Ланцюг `validate-upload` → підписаний PUT → `property_files`
 *    не мав ЖОДНОГО e2e (греп по tests/ давав лише джерельний
 *    `edge-invariants`). Тобто найдовший конвеєр застосунку перевірявся
 *    читанням коду.
 *
 * Мультивибір перевіряється навмисно: з компʼютера беруть кілька файлів
 * одразу, і `multiple` на інпуті без гарда легко зникає при рефакторингу.
 */

const USER = { ...DEFAULT_USER, role: 'owner' as const, first_name: 'Микола' }
const DB_ID = '10000000-0000-0000-0000-000000000001'
const NOW = new Date().toISOString()

const DB = {
  id: DB_ID, owner_id: USER.id, name: 'БЦ Рубін', address: 'вул. Хрещатик, 1',
  type: 'business_center', color: 'pink', share_token: 'aabbccddeeff001122334455',
  share_expires_at: null, created_at: NOW, updated_at: NOW,
  properties: [{ status: 'free', rent_rate: 18, area_useful: 100, rent_type: 'per_m2' }],
}

const PROP = {
  id: '20000000-0000-0000-0000-000000000001',
  db_id: DB_ID, owner_id: USER.id, name: 'Офіс 101', floor: '2',
  status: 'free', area_useful: 100, area_total: 120, area_basis: 'useful',
  rent_type: 'per_m2', rent_rate: 18, utilities_rate: null,
  has_parking: false, parking_spaces: 0, parking_type: null, ev_charger: false,
  utilities: null, description: null, address: null, sale_price: null,
  tenant_name: null, lease_start_date: null, lease_end_date: null,
  folder_id: null, landlord_name: null,
  sort_order: 100, share_token: 'bb00000000000000000000_1', share_expires_at: null,
  created_at: NOW, updated_at: NOW, photos: [],
}

// 1×1 PNG. Компресор fail-open: якщо canvas не впорається, поїде оригінал.
const PNG = Buffer.from(
  'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg==',
  'base64',
)
const PDF = Buffer.from('%PDF-1.4\n1 0 obj\n<<>>\nendobj\ntrailer\n<<>>\n%%EOF\n')

async function fixtures(page: Page) {
  await setupApp(page, { user: USER })
  // Без цього коачмарк-оверлей перехоплює перший клік по картці бази, і тест
  // висить на db-list до таймауту — заміряно (120с на екрані «Мої бази»).
  await skipCoachmarks(page)
  await page.route('**/rest/v1/databases**', (r) => {
    const accept = r.request().headers()['accept'] ?? ''
    return json(r, accept.includes('object') ? DB : [DB])
  })
  await page.route('**/rest/v1/properties**', (r) => {
    const accept = r.request().headers()['accept'] ?? ''
    return json(r, accept.includes('object') ? PROP : [PROP])
  })
  await page.route('**/rest/v1/db_members**', (r) => json(r, []))
  for (const t of ['property_folders', 'property_views', 'notifications',
                   'rent_payments', 'rent_payment_records', 'collections', 'guest_links']) {
    await page.route(`**/rest/v1/${t}**`, (r) => json(r, []))
  }
}

/** Ноутбучне вікно без тачу — саме так Telegram Desktop показує Mini App. */
async function desktop(browser: Browser) {
  const ctx = await browser.newContext({ viewport: { width: 1280, height: 800 }, deviceScaleFactor: 1 })
  return { ctx, page: await ctx.newPage() }
}

async function openProperty(page: Page) {
  await page.goto('/')
  await expect(page.getByText('Мої бази')).toBeVisible({ timeout: 25_000 })
  await page.getByText('БЦ Рубін').first().click()
  await page.locator('.obj-card .obj-t', { hasText: 'Офіс 101' }).click()
  await expect(page.getByText('Фотографії')).toBeVisible({ timeout: 15_000 })
}

test('десктоп · фото з компʼютера: мультивибір доходить до storage і в базу', async ({ browser }) => {
  // Три екрани плюс черга аплоуду — дефолтних 30с не вистачає навіть на
  // ненавантаженому раннері, а тут ще й компресія фото через canvas.
  test.setTimeout(120_000)
  const { ctx, page } = await desktop(browser)
  try {
    await fixtures(page)
    const posts: string[] = []
    const rows: Record<string, unknown>[] = []
    await page.route('**/storage/v1/object/photos/**', (r) => {
      if (r.request().method() === 'POST') posts.push(new URL(r.request().url()).pathname)
      return json(r, { Key: 'photos/x' })
    })
    await page.route('**/rest/v1/property_photos**', (r) => {
      if (r.request().method() === 'POST') {
        const body = JSON.parse(r.request().postData() ?? '{}')
        rows.push(body)
        return json(r, [{ id: `80000000-0000-0000-0000-00000000000${rows.length}`, ...body }], 201)
      }
      return json(r, rows)
    })

    await openProperty(page)

    // АФОРДАНС ПЕРШИМ: інпут прихований за задумом, тож міряється плитка «+»,
    // яка його клікає. Без цього гард доводив би лише те, що API приймає файли.
    // `getByRole('button')` тут ще й тримає інваріант: плитка мусить лишатись
    // `<button>`. Доти це був клікабельний `<div>` — на компʼютері недосяжний
    // з клавіатури й безіменний для читалки.
    const addBtn = page.getByRole('button', { name: 'Додати фото' }).first()
    await expect(addBtn, 'кнопку додавання фото не видно на десктопі').toBeVisible()
    const geo = await addBtn.evaluate((el) => {
      const b = el.getBoundingClientRect()
      const root = document.getElementById('app-root')!.getBoundingClientRect()
      return { w: b.width, h: b.height, inFrame: b.left >= root.left - 1 && b.right <= root.right + 1 }
    })
    expect(geo.h, 'зона дотику кнопки нижча за 44px').toBeGreaterThanOrEqual(44)
    expect(geo.inFrame, 'кнопка вилазить за рамку застосунку').toBe(true)

    // ДВА файли одразу — саме так беруть із компʼютера.
    await page.locator('input[type="file"][accept="image/*"]').setInputFiles([
      { name: 'a.png', mimeType: 'image/png', buffer: PNG },
      { name: 'b.png', mimeType: 'image/png', buffer: PNG },
    ])

    await expect(page.getByText('Завантажено!')).toBeVisible({ timeout: 20_000 })
    expect(posts.length, `у storage поїхало ${posts.length} файлів замість 2`).toBe(2)
    expect(rows.length, 'у property_photos лягло не два рядки').toBe(2)
    // Шлях без user-controlled сегментів: {propertyId}/{timestamp}_{rand}.{ext}
    for (const p of posts) expect(p).toMatch(new RegExp(`/photos/${PROP.id}/\\d+_[a-z0-9]+\\.png$`))
    // sort_order послідовний — інакше друге фото стало б другою обкладинкою.
    expect(rows.map((r) => r.sort_order)).toEqual([0, 1])
  } finally {
    await ctx.close()
  }
})

test('десктоп · документ з компʼютера: validate-upload → PUT → property_files', async ({ browser }) => {
  test.setTimeout(120_000)
  const { ctx, page } = await desktop(browser)
  try {
    await fixtures(page)
    const validated: Record<string, unknown>[] = []
    let putBody = 0
    const fileRows: Record<string, unknown>[] = []

    await page.route('**/functions/v1/validate-upload', (r) => {
      validated.push(JSON.parse(r.request().postData() ?? '{}'))
      return json(r, {
        uploadUrl: 'https://stub.local/signed/put',
        storagePath: `${PROP.id}/1700000000_abc.pdf`,
      })
    })
    await page.route('https://stub.local/signed/put', (r) => {
      if (r.request().method() === 'PUT') putBody++
      return r.fulfill({ status: 200, body: '{}' })
    })
    await page.route('**/rest/v1/property_files**', (r) => {
      if (r.request().method() === 'POST') {
        const body = JSON.parse(r.request().postData() ?? '{}')
        fileRows.push(body)
        return json(r, [{ id: '90000000-0000-0000-0000-000000000001', created_at: NOW, ...body }], 201)
      }
      return json(r, fileRows)
    })

    await openProperty(page)

    // Порожній стан пропонує «Завантажити файл»; коли файли вже є, та сама дія
    // живе в шапці секції як «Додати».
    const addDoc = page.getByRole('button', { name: /Завантажити файл|Додати/ }).first()
    await expect(addDoc, 'кнопку додавання документа не видно на десктопі').toBeVisible()
    const docInFrame = await addDoc.evaluate((el) => {
      const b = el.getBoundingClientRect()
      const root = document.getElementById('app-root')!.getBoundingClientRect()
      return b.left >= root.left - 1 && b.right <= root.right + 1
    })
    expect(docInFrame, 'кнопка документів вилазить за рамку застосунку').toBe(true)

    await page.locator('input[type="file"][accept*=".pdf"]').setInputFiles(
      [{ name: 'dogovir.pdf', mimeType: 'application/pdf', buffer: PDF }],
    )

    await expect.poll(() => fileRows.length, { timeout: 20_000 }).toBe(1)
    // Кожна ланка ланцюга мусить бути ПРОЙДЕНОЮ, а не просто «щось зберегли»:
    // edge-функція отримала параметри, підписаний PUT відбувся, рядок ліг.
    expect(validated[0]).toMatchObject({
      propertyId: PROP.id, fileName: 'dogovir.pdf', mimeType: 'application/pdf',
    })
    expect(putBody, 'підписаний PUT не відбувся').toBe(1)
    expect(fileRows[0]).toMatchObject({
      property_id: PROP.id, owner_id: USER.id, file_name: 'dogovir.pdf',
    })
    // Шлях приходить від edge-функції, тож клієнт не сміє його переписувати.
    expect((fileRows[0] as { storage_path: string }).storage_path).toBe(`${PROP.id}/1700000000_abc.pdf`)
  } finally {
    await ctx.close()
  }
})

/**
 * Перетягування у вікно — те, чим на компʼютері додають файли за
 * замовчуванням. Дроп симулюється справжнім `DragEvent` з `DataTransfer`:
 * `bubbles: true` обовʼязково, бо React слухає на корені, а не на елементі.
 */
async function dropFile(page: Page, selector: string, name: string, type: string, bytes: number[]) {
  return page.evaluate(({ selector, name, type, bytes }) => {
    const dt = new DataTransfer()
    dt.items.add(new File([new Uint8Array(bytes)], name, { type }))
    const el = document.querySelector(selector)
    if (!el) return false
    el.dispatchEvent(new DragEvent('dragenter', { dataTransfer: dt, bubbles: true }))
    el.dispatchEvent(new DragEvent('dragover', { dataTransfer: dt, bubbles: true }))
    el.dispatchEvent(new DragEvent('drop', { dataTransfer: dt, bubbles: true }))
    return true
  }, { selector, name, type, bytes })
}

const PNG_BYTES = Array.from(PNG)

test('десктоп · фото ПЕРЕТЯГУВАННЯМ у смугу доходить до storage', async ({ browser }) => {
  test.setTimeout(120_000)
  const { ctx, page } = await desktop(browser)
  try {
    await fixtures(page)
    const posts: string[] = []
    await page.route('**/storage/v1/object/photos/**', (r) => {
      if (r.request().method() === 'POST') posts.push(new URL(r.request().url()).pathname)
      return json(r, { Key: 'photos/x' })
    })
    await page.route('**/rest/v1/property_photos**', (r) => {
      if (r.request().method() === 'POST') {
        const body = JSON.parse(r.request().postData() ?? '{}')
        return json(r, [{ id: '80000000-0000-0000-0000-000000000001', ...body }], 201)
      }
      return json(r, [])
    })

    await openProperty(page)
    expect(await dropFile(page, '.photos-strip', 'drag.png', 'image/png', PNG_BYTES)).toBe(true)

    await expect(page.getByText('Завантажено!')).toBeVisible({ timeout: 20_000 })
    expect(posts.length, 'перетягнуте фото не поїхало в storage').toBe(1)
  } finally {
    await ctx.close()
  }
})

test('десктоп · документ ПЕРЕТЯГУВАННЯМ проходить той самий ланцюг', async ({ browser }) => {
  test.setTimeout(120_000)
  const { ctx, page } = await desktop(browser)
  try {
    await fixtures(page)
    const fileRows: Record<string, unknown>[] = []
    await page.route('**/functions/v1/validate-upload', (r) => json(r, {
      uploadUrl: 'https://stub.local/signed/put',
      storagePath: `${PROP.id}/1700000000_abc.pdf`,
    }))
    await page.route('https://stub.local/signed/put', (r) => r.fulfill({ status: 200, body: '{}' }))
    await page.route('**/rest/v1/property_files**', (r) => {
      if (r.request().method() === 'POST') {
        const body = JSON.parse(r.request().postData() ?? '{}')
        fileRows.push(body)
        return json(r, [{ id: '90000000-0000-0000-0000-000000000001', created_at: NOW, ...body }], 201)
      }
      return json(r, fileRows)
    })

    await openProperty(page)
    // Секція файлів монтується ПІСЛЯ свого запиту, тож без очікування дроп
    // летить у ще неіснуючу зону (заміряно: `dropFile` вертав false).
    await page.waitForSelector('.drop-zone', { timeout: 15_000 })
    expect(await dropFile(page, '.drop-zone', 'dogovir.pdf', 'application/pdf', [37, 80, 68, 70])).toBe(true)

    await expect.poll(() => fileRows.length, { timeout: 20_000 }).toBe(1)
    expect(fileRows[0]).toMatchObject({ property_id: PROP.id, file_name: 'dogovir.pdf' })
  } finally {
    await ctx.close()
  }
})

test('десктоп · чужий формат у зону фото — відмова, а не мовчазний перехід', async ({ browser }) => {
  test.setTimeout(120_000)
  const { ctx, page } = await desktop(browser)
  try {
    await fixtures(page)
    let storageTouched = false
    await page.route('**/storage/v1/object/photos/**', (r) => { storageTouched = true; return json(r, {}) })

    await openProperty(page)
    await dropFile(page, '.photos-strip', 'notes.txt', 'text/plain', [104, 105])

    // Фільтр мусить СКАЗАТИ про відмову, а не проковтнути дроп: мовчазне
    // «нічого не сталось» користувач читає як зламане перетягування.
    await expect(page.getByText('Це не зображення')).toBeVisible({ timeout: 10_000 })
    await expect(page.getByText('Завантажено!')).toHaveCount(0)
    expect(storageTouched, 'у storage поїхав нефайл зображення').toBe(false)
  } finally {
    await ctx.close()
  }
})

test('десктоп · дроп ПОВЗ зону не відкриває файл замість застосунку', async ({ browser }) => {
  test.setTimeout(120_000)
  const { ctx, page } = await desktop(browser)
  try {
    await fixtures(page)
    await page.goto('/')
    await expect(page.getByText('Мої бази')).toBeVisible({ timeout: 25_000 })

    // Без глобального глушника браузер НАВІГУЄ на кинутий файл — тобто
    // застосунок зникає разом із незбереженим станом. Перевіряється саме
    // `defaultPrevented`: це і є та властивість, яка навігацію скасовує.
    const prevented = await page.evaluate(() => {
      const dt = new DataTransfer()
      dt.items.add(new File([new Uint8Array([1, 2, 3])], 'stray.pdf', { type: 'application/pdf' }))
      const over = new DragEvent('dragover', { dataTransfer: dt, bubbles: true, cancelable: true })
      const drop = new DragEvent('drop', { dataTransfer: dt, bubbles: true, cancelable: true })
      document.body.dispatchEvent(over)
      document.body.dispatchEvent(drop)
      return { over: over.defaultPrevented, drop: drop.defaultPrevented }
    })
    expect(prevented.over, 'dragover не скасовано — вікно не стає ціллю дропу').toBe(true)
    expect(prevented.drop, 'drop повз зону не скасовано — браузер відкриє файл').toBe(true)
  } finally {
    await ctx.close()
  }
})

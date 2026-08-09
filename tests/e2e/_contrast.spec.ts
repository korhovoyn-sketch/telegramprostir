import { test, type Page, type Route } from '@playwright/test'
import { setupApp, DEFAULT_USER, seedSession } from './helpers/harness'
import { measureContrast, belowAA, smallTargets } from './helpers/contrast'

/**
 * ПРИНТЕР найгірших місць читабельності й досяжності — інструмент, не гард.
 *
 * Гард живе в `contrast.spec.ts` (заморожена база + allowlist). Тут навмисно
 * лишається друк таблиці: коли борг треба РОЗБИРАТИ, потрібні самі числа й
 * порядок, а не факт «щось нове». Замірний код спільний — `helpers/contrast.ts`.
 *
 * Запуск: PERF=1 npx playwright test _contrast --workers=1
 */

const USER = { ...DEFAULT_USER, role: 'owner' as const, first_name: 'Микола' }
const DB_ID = '10000000-0000-0000-0000-000000000001'
const NOW = new Date().toISOString()

const DB = {
  id: DB_ID, owner_id: USER.id, name: 'БЦ Рубін', address: 'вул. Хрещатик, 1',
  type: 'business_center', color: 'pink', share_token: 'aabbccddeeff001122334455',
  share_expires_at: null, created_at: NOW, updated_at: NOW,
}
const PROP = {
  id: '20000000-0000-0000-0000-000000000001', db_id: DB_ID, owner_id: USER.id,
  name: 'Офіс 10 поверху ( мале крило )', floor: '10', status: 'occupied',
  area_useful: 175.8, area_total: 195.13, area_basis: 'total', rent_type: 'per_m2',
  rent_rate: 12.8, utilities_rate: 2.5, has_parking: false, parking_spaces: 0,
  parking_type: null, ev_charger: false, folder_id: null,
  utilities: ['electricity', 'water', 'heating', 'gas'], description: 'Світлий офіс.',
  address: 'Дегтярівська 27-Т', sale_price: null, tenant_name: 'Фоп Плотко',
  lease_start_date: '2025-08-15', lease_end_date: '2026-08-31',
  sort_order: 1, share_token: 'bb00000000000000000011', share_expires_at: null,
  created_at: NOW, updated_at: NOW, photos: [], _view_count: 3,
}

async function setup(page: Page) {
  await setupApp(page, { user: USER })
  await seedSession(page, USER as unknown as Record<string, unknown>)
  const json = (r: Route, body: unknown) =>
    r.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(body) })
  await page.route('**/rest/v1/databases**', (r) =>
    json(r, (r.request().headers()['accept'] ?? '').includes('object') ? DB : [DB]))
  await page.route('**/rest/v1/properties**', (r) =>
    json(r, (r.request().headers()['accept'] ?? '').includes('object') ? PROP : [PROP]))
  await page.route('**/rest/v1/users**', (r) =>
    json(r, (r.request().headers()['accept'] ?? '').includes('object') ? USER : [USER]))
  for (const t of ['property_folders', 'property_files', 'property_photos', 'rent_payments', 'rent_payment_records', 'property_views', 'db_members', 'notifications']) {
    await page.route(`**/rest/v1/${t}**`, (r) => json(r, []))
  }
}

async function audit(page: Page, label: string) {
  const rows = await measureContrast(page)
  const bad = belowAA(rows)
  console.log(`\n─── ${label}: ${rows.length} текстових блоків, нижче AA — ${bad.length} ───`)
  for (const x of bad.slice(0, 12)) {
    console.log(`  ${String(x.ratio).padStart(5)}:1  (треба ${x.need})  ${String(x.size).padStart(2)}px/${x.weight}  «${x.text}»  .${x.cls}  [${x.key}]`)
  }
}

test('контраст: екрани власника', async ({ page }) => {
  test.setTimeout(120_000)
  await setup(page)

  await page.goto('/')
  await page.getByText('Мої бази').waitFor({ timeout: 20_000 })
  await page.waitForTimeout(700)
  await audit(page, 'db-list')

  await page.goto('/')
  await page.getByText('БЦ Рубін').first().waitFor({ timeout: 20_000 })
  await page.getByText('БЦ Рубін').first().click()
  await page.getByText('Всі (1)').waitFor({ timeout: 15_000 })
  await page.waitForTimeout(700)
  await audit(page, 'db-objects')

  await page.goto('/')
  await page.getByText('БЦ Рубін').first().waitFor({ timeout: 20_000 })
  await page.getByText('БЦ Рубін').first().click()
  await page.locator('.obj-card').first().locator('.obj-t').click()
  await page.getByRole('button', { name: /Звільнити/ }).waitFor({ timeout: 15_000 })
  await page.waitForTimeout(700)
  await audit(page, 'property-detail')

  await page.goto('/')
  await page.getByText('Мої бази').waitFor({ timeout: 20_000 })
  await page.locator('.tabbar [aria-label="Профіль"]').click()
  await page.getByText('Налаштування').waitFor({ timeout: 15_000 })
  await page.waitForTimeout(700)
  await audit(page, 'profile')
})

test('тап-таргети проти Apple HIG 44×44', async ({ page }) => {
  test.setTimeout(120_000)
  await setup(page)
  const steps: [string, () => Promise<void>][] = [
    ['db-list', async () => {
      await page.goto('/'); await page.getByText('Мої бази').waitFor({ timeout: 20_000 })
    }],
    ['db-objects', async () => {
      await page.getByText('БЦ Рубін').first().click(); await page.getByText('Всі (1)').waitFor({ timeout: 15_000 })
    }],
    ['property-detail', async () => {
      await page.locator('.obj-card').first().locator('.obj-t').click()
      await page.getByRole('button', { name: /Звільнити/ }).waitFor({ timeout: 15_000 })
    }],
    ['profile', async () => {
      await page.goto('/'); await page.getByText('Мої бази').waitFor({ timeout: 20_000 })
      await page.locator('.tabbar [aria-label="Профіль"]').click()
      await page.getByText('Налаштування').waitFor({ timeout: 15_000 })
    }],
    ['notifications', async () => {
      await page.locator('.tabbar [aria-label="Сповіщення"]').click()
      await page.getByText('Сповіщення').first().waitFor({ timeout: 15_000 })
    }],
  ]
  for (const [label, go] of steps) {
    await go()
    await page.waitForTimeout(500)
    const bad = await smallTargets(page, 44)
    console.log(`\n─── ${label}: менших за 44×44 — ${bad.length} ───`)
    const uniq = new Map<string, { cls: string; label: string; w: number; h: number }>()
    for (const b of bad) uniq.set(`${b.cls}|${b.w}x${b.h}`, b)
    for (const b of [...uniq.values()].slice(0, 10)) {
      console.log(`  ${String(b.w).padStart(3)}×${String(b.h).padStart(3)}  «${b.label}»  .${b.cls}`)
    }
  }
})

test('дії останньої картки не під таббаром', async ({ page }) => {
  await setup(page)
  await page.goto('/')
  await page.getByText('БЦ Рубін').first().waitFor({ timeout: 20_000 })
  await page.getByText('БЦ Рубін').first().click()
  await page.getByText('Всі (1)').waitFor({ timeout: 15_000 })
  // Прокручуємо в самий низ — саме там дії останньої картки зустрічаються з таббаром.
  await page.evaluate(() => { const b = document.querySelector('.body') as HTMLElement; b.scrollTop = b.scrollHeight })
  await page.waitForTimeout(600)

  const res = await page.evaluate(() => {
    const bar = document.querySelector('.tabbar') as HTMLElement
    const barTop = bar.getBoundingClientRect().top
    const acts = [...document.querySelectorAll('.obj-act-btn')] as HTMLElement[]
    const last = acts[acts.length - 1]
    const r = last?.getBoundingClientRect()
    // Чи справді таббар перехоплює тап у центрі кнопки?
    const cx = r ? Math.round(r.left + r.width / 2) : 0
    const cy = r ? Math.round(r.top + r.height / 2) : 0
    const hit = r ? document.elementFromPoint(cx, cy) : null
    return {
      barTop: Math.round(barTop),
      lastBottom: r ? Math.round(r.bottom) : -1,
      overlap: r ? Math.round(r.bottom - barTop) : -1,
      hitClass: hit ? (hit.className?.toString().slice(0, 30) || hit.tagName) : 'нічого',
      hitIsAction: !!hit?.closest('.obj-act-btn'),
    }
  })
  console.log('\n─── ДІЇ КАРТКИ vs ТАББАР ───')
  console.log(`верх таббару:        ${res.barTop}px`)
  console.log(`низ останньої дії:   ${res.lastBottom}px`)
  console.log(`перекриття:          ${res.overlap}px ${res.overlap > 0 ? '⚠' : '✓'}`)
  console.log(`тап у центр влучає:  ${res.hitClass} → ${res.hitIsAction ? 'у кнопку ✓' : 'НЕ в кнопку ⚠'}`)
})

test('розширена зона дотику нікому не краде тапи', async ({ page }) => {
  test.setTimeout(120_000)
  await setup(page)
  const steps: [string, () => Promise<void>][] = [
    ['db-objects', async () => {
      await page.goto('/'); await page.getByText('БЦ Рубін').first().waitFor({ timeout: 20_000 })
      await page.getByText('БЦ Рубін').first().click(); await page.getByText('Всі (1)').waitFor({ timeout: 15_000 })
    }],
    ['profile', async () => {
      await page.goto('/'); await page.getByText('Мої бази').waitFor({ timeout: 20_000 })
      await page.locator('.tabbar [aria-label="Профіль"]').click()
      await page.getByText('Налаштування').waitFor({ timeout: 15_000 })
    }],
    ['notifications', async () => {
      await page.locator('.tabbar [aria-label="Сповіщення"]').click()
      await page.getByText('Сповіщення').first().waitFor({ timeout: 15_000 })
    }],
  ]
  for (const [label, go] of steps) {
    await go()
    await page.waitForTimeout(500)
    const res = await page.evaluate(() => {
      const bad: string[] = []
      const bar = document.querySelector('.tabbar') as HTMLElement | null
      const fold = bar ? bar.getBoundingClientRect().top : window.innerHeight
      const targets = [...document.querySelectorAll('.seg-b,.view-seg-b,.fr-seg-b,.notif-tab,.hdr-back')] as HTMLElement[]
      for (const t of targets) {
        const r = t.getBoundingClientRect()
        // Нижче таббару — це не «вкрадений тап», а просто нижче фолду.
        if (r.width < 4 || r.top < 0 || r.bottom > fold) continue
        // Центр і КРАЇ розширеної зони мусять влучати в сам контрол.
        for (const dy of [-20, 0, 20]) {
          const x = Math.round(r.left + r.width / 2)
          const y = Math.round(r.top + r.height / 2 + dy)
          if (y < 1 || y > fold - 1) continue
          const hit = document.elementFromPoint(x, y)
          if (!hit) continue
          // Влучили або в себе, або в НЕінтерактивне — крадіжки немає.
          const ownTarget = hit === t || t.contains(hit) || hit.contains(t)
          const other = (hit as HTMLElement).closest('button,[role="button"],a,.sheet-row,.obj-card,.row,.notif-row')
          if (!ownTarget && other && !t.contains(other)) {
            bad.push(`${(t.className || '').toString().slice(0, 18)} @${dy > 0 ? '+' : ''}${dy} → ${(other.className || other.tagName).toString().slice(0, 24)}`)
          }
        }
      }
      return bad
    })
    console.log(`\n─── ${label}: конфліктів зони дотику — ${res.length} ───`)
    for (const b of [...new Set(res)].slice(0, 8)) console.log('  ' + b)
  }
})

test('діагностика: сегменти Профілю vs таббар', async ({ page }) => {
  await setup(page)
  await page.goto('/')
  await page.getByText('Мої бази').waitFor({ timeout: 20_000 })
  await page.locator('.tabbar [aria-label="Профіль"]').click()
  await page.getByText('Налаштування').waitFor({ timeout: 15_000 })
  await page.waitForTimeout(500)
  const res = await page.evaluate(() => {
    const bar = document.querySelector('.tabbar') as HTMLElement
    const bt = bar.getBoundingClientRect()
    const body = document.querySelector('.body') as HTMLElement
    const segs = [...document.querySelectorAll('.fr-seg-b')] as HTMLElement[]
    return {
      barTop: Math.round(bt.top), barH: Math.round(bt.height),
      bodyPadBottom: getComputedStyle(body).paddingBottom,
      bodyClass: body.className,
      scrollable: body.scrollHeight > body.clientHeight,
      segs: segs.map((e) => {
        const r = e.getBoundingClientRect()
        return { t: Math.round(r.top), b: Math.round(r.bottom), label: (e.textContent || '').trim().slice(0, 6) }
      }),
    }
  })
  console.log('\n─── ПРОФІЛЬ: сегменти vs таббар ───')
  console.log(`таббар: top=${res.barTop} height=${res.barH}`)
  console.log(`.body: ${res.bodyClass} / padding-bottom=${res.bodyPadBottom} / прокрутний=${res.scrollable}`)
  for (const s of res.segs) console.log(`  «${s.label}» ${s.t}…${s.b}  ${s.b > res.barTop ? '⚠ ПІД таббаром' : '✓'}`)
})

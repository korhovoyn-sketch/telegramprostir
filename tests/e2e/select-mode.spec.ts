import { test, expect, type Page } from '@playwright/test'
import { setupApp, DEFAULT_USER, jsonRoute } from './helpers/harness'
const USER={...DEFAULT_USER,role:'owner' as const}
const DB_ID='10000000-0000-0000-0000-000000000001'; const NOW=new Date().toISOString()
const DB={id:DB_ID,owner_id:USER.id,name:'Міком Палац',address:'a',type:'business_center',color:'pink',share_token:'aabbccddeeff001122334455',share_expires_at:null,created_at:NOW,updated_at:NOW,properties:[]}
function prop(n:number){return{id:`20000000-0000-0000-0000-0000000000${String(n).padStart(2,'0')}`,db_id:DB_ID,owner_id:USER.id,name:`Офіс ${n} поверху ( мале крило )`,floor:String(n),status:'occupied',area_useful:175.8,area_total:195.13,area_basis:'total',rent_type:'per_m2',rent_rate:13,utilities_rate:2.5,has_parking:false,parking_spaces:0,parking_type:null,ev_charger:false,folder_id:null,utilities:null,description:null,address:null,sale_price:null,tenant_name:'Фоп плотко',lease_start_date:'2025-08-15',lease_end_date:'2026-08-31',sort_order:n,share_token:`bb0000000000000000${String(n).padStart(6,'0')}`,share_expires_at:null,created_at:NOW,updated_at:NOW,photos:[]}}
const PROPERTIES=Array.from({length:5},(_,i)=>prop(i+1))
async function setup(page:Page){
  await setupApp(page,{user:USER})
  await page.route('**/rest/v1/databases**',(r)=>jsonRoute(r,(r.request().headers()['accept']??'').includes('object')?DB:[DB]))
  await page.route('**/rest/v1/properties**',(r)=>jsonRoute(r,PROPERTIES))
  await page.route('**/rest/v1/property_folders**',(r)=>jsonRoute(r,[]))
  await page.route('**/rest/v1/db_members**',(r)=>jsonRoute(r,[]))
  await page.addInitScript(()=>localStorage.setItem('ob_v1',JSON.stringify(['owner-fab','obj-fab','realtor-qr','col-fab'])))
}
// Регресії режиму вибору:
//  • .hdr-a мав фіксовану ширину під ІКОНКУ (32/44px) — текстова «Скасувати»
//    вилазила за екран і обрізалась;
//  • картку виділяв outline, який малюється ЗА межами border-box, тож
//    contain:paint на .obj-card зрізав його по боках (виглядало як обрізані
//    картки). Тепер inset-ring, який фізично не може вийти за межі.
test('режим вибору: нічого не обрізано по краях', async ({ page }, ti) => {
  await setup(page); await page.goto('/')
  await expect(page.getByText('Мої бази')).toBeVisible({timeout:20000})
  await page.getByText('Міком Палац').first().click()
  await expect(page.getByText('Всі (5)')).toBeVisible()
  await page.getByLabel('Меню бази').click()
  await page.getByText("Виділити обʼєкти").click()
  await expect(page.getByText("Оберіть обʼєкти для дії")).toBeVisible()
  await page.locator('.obj-card').first().click()
  await page.waitForTimeout(400)

  const r = await page.evaluate(() => {
    const vw = window.innerWidth
    const btn = [...document.querySelectorAll('.hdr-a')].find(b => (b.textContent||'').includes('Скасувати')) as HTMLElement
    const br = btn.getBoundingClientRect()
    const cards = [...document.querySelectorAll('.obj-card')].map(c => {
      const cr = c.getBoundingClientRect(); return { left: Math.round(cr.left), right: Math.round(cr.right) }
    })
    return { vw, btnLeft: Math.round(br.left), btnRight: Math.round(br.right),
             btnText: (btn.textContent||'').trim(), btnScrollW: btn.scrollWidth, btnClientW: btn.clientWidth,
             worstRight: Math.max(...cards.map(c=>c.right)), worstLeft: Math.min(...cards.map(c=>c.left)) }
  })
  await page.screenshot({path: ti.outputPath('select.png')})
  expect(r.btnRight, 'кнопка «Скасувати» в межах екрана').toBeLessThanOrEqual(r.vw)
  expect(r.btnScrollW, 'текст кнопки не обрізаний').toBeLessThanOrEqual(r.btnClientW + 1)
  expect(r.worstRight, 'картки не вилазять праворуч').toBeLessThanOrEqual(r.vw)
  expect(r.worstLeft, 'картки не вилазять ліворуч').toBeGreaterThanOrEqual(0)
})

// Панель дій над обраними: скляна плитка, а не «мертва» плашка. Раніше в неї
// стояв неоголошений var(--bg2) — фон не малювався взагалі.
test('панель обраних: напівпрозоре скло, скрим і закріплене «Видалити»', async ({ page }) => {
  await setup(page); await page.goto('/')
  await expect(page.getByText('Мої бази')).toBeVisible({ timeout: 20000 })
  await page.getByText('Міком Палац').first().click()
  await expect(page.getByText('Всі (5)')).toBeVisible()
  await page.getByLabel('Меню бази').click()
  await page.getByText("Виділити обʼєкти").click()
  await page.locator('.obj-card').first().locator('.obj-t').click()
  await expect(page.locator('.batchbar')).toBeVisible()
  await page.waitForTimeout(450)

  const geo = await page.evaluate(() => {
    const bar = document.querySelector('.batchbar') as HTMLElement
    const cs = getComputedStyle(bar)
    const b = bar.getBoundingClientRect()
    const tab = document.querySelector('.tabbar')!.getBoundingClientRect()
    const scrim = document.querySelector('.batchbar-scrim')
    const del = document.querySelector('.batch-pill.err')!.getBoundingClientRect()
    const scroll = document.querySelector('.batch-scroll')!.getBoundingClientRect()
    return {
      bg: cs.backgroundColor, radius: cs.borderTopLeftRadius,
      left: Math.round(b.left), right: Math.round(b.right), vw: window.innerWidth,
      barBottom: Math.round(b.bottom), tabTop: Math.round(tab.top),
      hasScrim: !!scrim,
      delOutsideScroll: del.left >= scroll.right - 1,
      delW: Math.round(del.width), delH: Math.round(del.height),
    }
  })

  // Фон саме напівпрозорий (≈50%), а не суцільний і не відсутній
  const alpha = Number(geo.bg.match(/rgba?\([^)]*?,\s*([\d.]+)\)/)?.[1] ?? '1')
  expect(alpha, 'панель напівпрозора').toBeGreaterThan(0.3)
  expect(alpha, 'панель не суцільна').toBeLessThan(0.8)
  expect(parseFloat(geo.radius), 'скруглена як шит').toBeGreaterThanOrEqual(16)
  // Плаваюча плитка з відступами, а не смуга на всю ширину
  expect(geo.left).toBeGreaterThan(4)
  expect(geo.right).toBeLessThan(geo.vw - 4)
  // Над таббаром, не поверх нього
  expect(geo.barBottom, 'панель не налазить на таббар').toBeLessThanOrEqual(geo.tabTop)
  expect(geo.hasScrim, 'скрим під панеллю').toBe(true)
  // Небезпечна дія завжди на видноті — поза прокруткою пілюль
  expect(geo.delOutsideScroll, '«Видалити» закріплене праворуч').toBe(true)
  expect(geo.delH, 'тач-таргет не менше 36px').toBeGreaterThanOrEqual(36)
  await expect(page.getByLabel(/Видалити 1 об/)).toBeVisible()
})

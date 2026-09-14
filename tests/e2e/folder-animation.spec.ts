import { test, expect, type Page } from '@playwright/test'
import { setupApp, DEFAULT_USER, jsonRoute } from './helpers/harness'
const USER = { ...DEFAULT_USER, role: 'owner' as const }
const DB_ID='10000000-0000-0000-0000-000000000001'; const A='40000000-0000-0000-0000-0000000000a1'
const NOW=new Date().toISOString()
const DB={id:DB_ID,owner_id:USER.id,name:'Міком Палац',address:'a',type:'business_center',color:'pink',share_token:'aabbccddeeff001122334455',share_expires_at:null,created_at:NOW,updated_at:NOW,properties:[]}
function prop(n:number){return{id:`20000000-0000-0000-0000-0000000000${String(n).padStart(2,'0')}`,db_id:DB_ID,owner_id:USER.id,name:`Офіс ${100+n}`,floor:String(n),status:'occupied',area_useful:292,area_total:324,area_basis:'total',rent_type:'per_m2',rent_rate:18,utilities_rate:2.5,has_parking:false,parking_spaces:0,parking_type:null,ev_charger:false,folder_id:A,utilities:null,description:null,address:null,sale_price:null,tenant_name:'ФОП Бригинець',lease_start_date:'2025-07-01',lease_end_date:'2027-06-30',sort_order:n,share_token:`bb00000000000000000${String(n).padStart(5,'0')}`,share_expires_at:null,created_at:NOW,updated_at:NOW,photos:[]}}
const PROPERTIES=Array.from({length:8},(_,i)=>prop(i+1))
const FOLDERS=[{id:A,db_id:DB_ID,owner_id:USER.id,name:'Орендарі 2',sort_order:100,created_at:NOW,updated_at:NOW}]
async function setup(page:Page){
  await setupApp(page,{user:USER})
  await page.route('**/rest/v1/databases**',(r)=>jsonRoute(r,(r.request().headers()['accept']??'').includes('object')?DB:[DB]))
  await page.route('**/rest/v1/properties**',(r)=>jsonRoute(r,PROPERTIES))
  await page.route('**/rest/v1/property_folders**',(r)=>jsonRoute(r,FOLDERS))
  await page.route('**/rest/v1/db_members**',(r)=>jsonRoute(r,[]))
  await page.addInitScript(()=>localStorage.setItem('ob_v1',JSON.stringify(['owner-fab','obj-fab','realtor-qr','col-fab'])))
}
// Регресія: розгортання/згортання папки МУСИТЬ проходити через проміжні висоти.
// Раніше React батчив дві поспіль зміни height, браузер бачив лише кінцеве
// значення і секція «стрибала» — на відео це виглядало як рвана анімація.
test('акордеон папки анімує висоту, а не стрибає', async ({ page }) => {
  await setup(page); await page.goto('/')
  await expect(page.getByText('Мої бази')).toBeVisible({timeout:20000})
  await page.getByText('Міком Палац').first().click()
  await expect(page.getByText('Всі (8)')).toBeVisible()
  await page.waitForTimeout(700)

  // sample the wrapper height across the collapse; читаємо блюр НА ПЕРШОМУ кадрі,
  // в тому самому evaluate — окремий page.evaluate() ПІСЛЯ 14-кадрового циклу це
  // гонка: під навантаженням повного прогону (паралельні воркери) rAF рідшає, і
  // 300мс-анімація встигає завершитись (fold-anim знято) до другого виклику.
  const { samples, blurOff, fades } = await page.evaluate(async () => {
    const hd = document.querySelector('.fold-hd') as HTMLElement
    const wrap = document.querySelector('.fold-wrap') as HTMLElement
    const out:number[] = []
    const alpha:number[] = []
    hd.click()
    let blur = 'no-anim-class'
    for (let i=0;i<14;i++){
      await new Promise(r=>requestAnimationFrame(()=>r(null)))
      out.push(Math.round(wrap.getBoundingClientRect().height))
      alpha.push(parseFloat(getComputedStyle(wrap).opacity))
      if (i === 0) {
        const c = document.querySelector('.fold-wrap.fold-anim .glass-s') as HTMLElement | null
        blur = c ? getComputedStyle(c).backdropFilter : 'no-anim-class'
      }
    }
    return { samples: out, blurOff: blur, fades: alpha }
  })
  const distinct = new Set(samples).size
  // A real animation passes through several intermediate heights; a snap gives 1-2.
  expect(distinct, `очікуємо плавні проміжні висоти, отримали ${JSON.stringify(samples)}`).toBeGreaterThan(3)
  // і блюр вимкнено на час руху (інакше 24 скляні шари щокадру = дропнуті кадри)
  expect(blurOff, 'блюр вимкнено на час анімації').toBe('none')
  // Прозорість НЕ анімується разом із висотою: `opacity < 1` на обгортці
  // змушує браузер щокадру складати все піддерево папки в офскрін-буфер і
  // композитувати з альфою — та сама зайва робота, що й блюр вище, лише
  // непомітна в коді. Фейд усе одно схований `overflow:hidden`.
  const faded = fades.filter((o) => o < 1)
  expect(faded, `обгортка не має фейдитись під час руху, отримали ${JSON.stringify(fades)}`).toEqual([])
})

/**
 * ПЕРЕРИВАННЯ — клас, якого гард вище не бачить ЗА ПОБУДОВОЮ: він міряє ОДНЕ,
 * неперерване згортання, а дефект живе рівно там, де рух скасовують на льоту.
 *
 * Заміряно ДО фікса (8 карток, розгорнута папка 1452px): згорнути, перервати
 * на 5-му кадрі (видимі 456px) і розгорнути назад давало 1452 на ПЕРШОМУ ж
 * кадрі і шість поспіль по 1452 — тобто зворотний хід не анімувався ВЗАГАЛІ, а
 * на екрані був стрибок 456→1452, 68% висоти обгортки за один кадр.
 *
 * Причина — у ПРИБИРАННІ ефекту: React виконує його ПЕРЕД тілом наступного,
 * тож `anim.cancel()` знімав `fill:forwards` і висота поверталась на
 * інлайновий стиль (початок перерваного руху) ще до того, як тіло встигало її
 * прочитати. Тому фікс мусить бути саме в прибиранні, а не в тілі.
 */
test('перерване згортання продовжується з ВИДИМОЇ висоти, а не стрибає', async ({ page }) => {
  await setup(page); await page.goto('/')
  await expect(page.getByText('Мої бази')).toBeVisible({timeout:20000})
  await page.getByText('Міком Палац').first().click()
  await expect(page.getByText('Всі (8)')).toBeVisible()
  await page.waitForTimeout(700)

  const { open: openH, mid, after } = await page.evaluate(async () => {
    const hd = document.querySelector('.fold-hd') as HTMLElement
    const wrap = document.querySelector('.fold-wrap') as HTMLElement
    const frame = () => new Promise((r) => requestAnimationFrame(() => r(null)))
    const H = () => Math.round(wrap.getBoundingClientRect().height)
    const openH = H()
    hd.click()                                  // згортаємо
    for (let i = 0; i < 5; i++) await frame()   // ...і перериваємо на льоту
    const mid = H()
    hd.click()
    const after: number[] = []
    for (let i = 0; i < 6; i++) { await frame(); after.push(H()) }
    return { open: openH, mid, after }
  })

  // Антивакуум: переривання мусить статись ПОСЕРЕД руху. Якщо `mid` дорівнює
  // відкритій висоті, згортання ще не почалось — і тест нижче збігався б ні на
  // чому, бо продовжувати не було б звідки.
  expect(mid, `перервали не посеред руху: open=${openH}, mid=${mid}`).toBeLessThan(openH * 0.8)
  expect(mid).toBeGreaterThan(0)

  // Зворотний хід СТАРТУЄ близько до видимої висоти, а не з кінцевої.
  expect(after[0], `стрибок: видимі ${mid}px → ${after[0]}px за один кадр (кінцева ${openH})`)
    .toBeLessThan(mid + (openH - mid) * 0.5)
  // ...і справді РУХАЄТЬСЯ через проміжні значення, а не стоїть.
  expect(new Set(after).size, `очікуємо рух, отримали ${JSON.stringify(after)}`).toBeGreaterThan(3)
})

/**
 * Індикатор і тіло — ОДИН рецепт. Було .2s `--ease` проти 300мс `--ease-out`:
 * стрілка ставала в кінцеве положення на 100мс раніше, ніж секція дорухалась,
 * ще й іншою кривою. Читається як «готово» посеред руху.
 */
test('стрілка їде тим самим рецептом, що й тіло', async ({ page }) => {
  await setup(page); await page.goto('/')
  await expect(page.getByText('Мої бази')).toBeVisible({timeout:20000})
  await page.getByText('Міком Палац').first().click()
  await expect(page.getByText('Всі (8)')).toBeVisible()

  const { dur, ease, easeOut } = await page.evaluate(() => {
    const chev = document.querySelector('.fold-hd-chev') as HTMLElement
    const t = getComputedStyle(chev).transition
    return {
      dur: /(\d*\.?\d+)s/.exec(t)?.[1] ?? '',
      ease: /cubic-bezier\([^)]+\)/.exec(t)?.[0] ?? '',
      easeOut: getComputedStyle(document.documentElement).getPropertyValue('--ease-out').trim(),
    }
  })
  // 300мс — та сама тривалість, що жене `Collapsible.tsx` (і що вже несе виїзд шита).
  expect(dur, 'тривалість стрілки мусить збігатися з тілом (0.3s)').toBe('0.3')
  // Криву звіряємо з ТОКЕНОМ, а не з літералом: інакше гард закріпив би копію.
  const norm = (c: string) => c.replace(/\s/g, '').replace(/0\./g, '.')
  expect(norm(ease), 'крива стрілки мусить бути --ease-out').toBe(norm(easeOut))
})

/**
 * Заголовок — ЄДИНИЙ орган керування акордеоном. Як `<div>` він був недосяжний
 * з клавіатури і читалка не оголошувала ні роль, ні стан секції.
 */
test('заголовок папки — кнопка зі станом, досяжна з клавіатури', async ({ page }) => {
  await setup(page); await page.goto('/')
  await expect(page.getByText('Мої бази')).toBeVisible({timeout:20000})
  await page.getByText('Міком Палац').first().click()
  await expect(page.getByText('Всі (8)')).toBeVisible()
  await page.waitForTimeout(700)

  const hd = page.locator('.fold-hd').first()
  await expect(hd).toHaveJSProperty('tagName', 'BUTTON')
  await expect(hd).toHaveAttribute('aria-expanded', 'true')
  // `aria-controls` мусить вказувати на РЕАЛЬНЕ тіло, а не в порожнечу.
  const controls = await hd.getAttribute('aria-controls')
  await expect(page.locator(`#${controls}`)).toHaveClass(/fold-wrap/)

  // Клавіатура справді перемикає стан.
  await hd.focus()
  await page.keyboard.press('Enter')
  await expect(hd).toHaveAttribute('aria-expanded', 'false')
})

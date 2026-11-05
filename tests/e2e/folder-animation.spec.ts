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

/**
 * ВЕЛИКА ПАПКА: рухається ВИДИМЕ, а не вся висота.
 *
 * Тривалість і крива однакові для папки на 1 картку і на 24, тож доти рух
 * велико́ї майже весь відбувався ЗА краєм екрана. Заміряно (8 карток, 1452px,
 * під заголовком видно 254px): розгортання заповнювало ВСЮ видиму частину за
 * ОДИН кадр, решта 280мс руху — невидимі; згортання ~70мс стояло (висота
 * падала лише в невидимій частині), а потім повзло хвостом кривої. Для папки
 * на 24 картки мертвий старт — ~135мс.
 *
 * Тому анімується лише те, що можна побачити: розгортання — до низу
 * скролера, згортання — від нього (невидима частина знімається відразу і
 * непомітно). Ключові кадри перевіряються НАПРЯМУ: від цього не залежить
 * темп кадрів під навантаженням.
 */
async function openWith(page: Page, collapsed: string[], props: { folder_id: string | null }[] = PROPERTIES) {
  await setup(page)
  await page.route('**/rest/v1/properties**', (r) => jsonRoute(r, props))
  await page.addInitScript(([k, v]) => {
    if (!sessionStorage.getItem('__seeded')) { localStorage.setItem(k, v); sessionStorage.setItem('__seeded', '1') }
  }, [`ps:foldCollapse:${USER.id}:${DB_ID}`, JSON.stringify(collapsed)])
  await page.goto('/')
  await expect(page.getByText('Мої бази')).toBeVisible({ timeout: 20000 })
  await page.getByText('Міком Палац').first().click()
  await expect(page.getByText(`Всі (${props.length})`)).toBeVisible()
  await expect(page.locator('.fold-hd')).toHaveCount(props.some((p) => !p.folder_id) ? 2 : 1)
  await page.waitForTimeout(700)
}

/** Тапає заголовок і пише покадрово висоту, видиму частину, верх заголовка і ключові кадри руху. */
function tapAndSample(page: Page, frames = 24, nth = 0) {
  return page.evaluate(async ({ frames, nth }) => {
    const hd = document.querySelectorAll('.fold-hd')[nth] as HTMLElement
    const wrap = document.getElementById(hd.getAttribute('aria-controls')!) as HTMLElement
    const sc = document.querySelector('.body') as HTMLElement
    const sr = sc.getBoundingClientRect()
    const room = Math.round(sr.top + sc.clientHeight - wrap.getBoundingClientRect().top)
    const vis = () => { const r = wrap.getBoundingClientRect(); return Math.round(Math.max(0, Math.min(r.bottom, sr.top + sc.clientHeight) - Math.max(r.top, sr.top))) }
    const full = Math.round((wrap.firstElementChild as HTMLElement).getBoundingClientRect().height)
    const out: { h: number; vis: number; top: number }[] = []
    const snap = () => out.push({ h: Math.round(wrap.getBoundingClientRect().height), vis: vis(), top: Math.round(hd.getBoundingClientRect().top) })
    snap()
    hd.click()
    // Ефект, що запускає рух, біжить після коміту — ключові кадри беремо з
    // першого кадру, на якому анімація вже є.
    let kf: number[] = []
    for (let i = 0; i < frames; i++) {
      await new Promise((r) => requestAnimationFrame(() => r(null)))
      const a = wrap.getAnimations()[0]
      if (!kf.length && a) kf = (a.effect as KeyframeEffect).getKeyframes().map((k) => parseFloat(String(k.height)))
      snap()
    }
    return { room, full, kf, frames: out }
  }, { frames, nth })
}

test('велика папка: анімується лише ВИДИМА частина', async ({ page }) => {
  await openWith(page, [A])

  const ex = await tapAndSample(page)
  // антивакуум: папка справді вища за видиму частину, інакше обмежувати нічого
  expect(ex.full, `папка мусить бути вищою за видиму частину: ${ex.full} vs ${ex.room}`).toBeGreaterThan(ex.room * 2)
  expect(ex.kf.length, 'розгортання не запустило анімацію').toBe(2)
  expect(ex.kf[1], `розгортання жене висоту ДАЛІ видимого (${ex.kf[1]} > ${ex.room})`).toBeLessThanOrEqual(ex.room + 1)
  const seen = new Set(ex.frames.map((f) => f.vis))
  expect(seen.size, `видима частина мусить РУХАТИСЬ, а не зʼявитись кадром: ${JSON.stringify(ex.frames.map((f) => f.vis))}`).toBeGreaterThan(3)
  expect(ex.frames[ex.frames.length - 1].h, 'після руху папка розкрита повністю').toBe(ex.full)

  await page.waitForTimeout(300)
  const co = await tapAndSample(page)
  expect(co.kf[0], `згортання стартує з НЕВИДИМОЇ висоти (${co.kf[0]} > ${co.room})`).toBeLessThanOrEqual(co.room + 1)
  // Видиме мусить почати рухатись на першому ж кадрі руху, а не після паузи.
  const firstMove = co.frames.findIndex((f) => f.vis < co.frames[0].vis)
  expect(firstMove, `згортання стоїть ${firstMove} кадрів: ${JSON.stringify(co.frames.map((f) => f.vis))}`).toBeLessThanOrEqual(3)
  // ...і заголовок не стрибає: зняття невидимої частини не сміє зачепити прокрутку
  expect(new Set([...ex.frames, ...co.frames].map((f) => f.top)).size, 'заголовок зрушив під час руху').toBe(1)
})

/**
 * Прокрутку змінює ЛИШЕ рух, а не його кінець. Chromium (Android) якорить
 * прокрутку, і після згортання з упором у низ сторінки наступне розгортання
 * тягнуло сторінку за собою; з обмеженим рухом це дало б стрибок на ~190px у
 * мить, коли висота відпускається в `auto`. Тому на час руху якоріння знято.
 */
test('розгортання після згортання внизу сторінки: заголовок не стрибає', async ({ page }) => {
  // Остання секція («Без папки», 2 картки) — під великою папкою, тобто внизу.
  const loose = [9, 10].map((n) => ({ ...prop(n), folder_id: null }))
  await openWith(page, [], [...PROPERTIES, ...loose])
  await page.evaluate(() => { const b = document.querySelector('.body') as HTMLElement; b.scrollTop = b.scrollHeight })
  await page.waitForTimeout(300)
  // Згортання з упором у низ: прокрутка законно сповзає разом із висотою.
  const co = await tapAndSample(page, 24, 1)
  // антивакуум: заголовок видно і сторінка справді впирається в низ
  expect(co.frames[0].top).toBeGreaterThan(0)
  const coSteps = co.frames.slice(1).map((f, i) => Math.abs(f.top - co.frames[i].top))
  expect(Math.max(...coSteps), `згортання: заголовок стрибнув ${JSON.stringify(co.frames.map((f) => f.top))}`).toBeLessThan(co.room * 0.6)
  await page.waitForTimeout(300)
  const ex = await tapAndSample(page, 30, 1)
  // Кінець руху — найнебезпечніший кадр: там висота йде в `auto`.
  const steps = ex.frames.slice(1).map((f, i) => Math.abs(f.top - ex.frames[i].top))
  expect(Math.max(...steps), `розгортання: заголовок стрибнув ${JSON.stringify(ex.frames.map((f) => f.top))}`).toBeLessThan(40)
  // антивакуум: розгортання справді відбулось і щось показало
  expect(ex.frames[ex.frames.length - 1].vis).toBeGreaterThan(50)
})

/**
 * ПОШУК розгортає всі секції примусово — і тап по заголовку там був МЕРТВИМ:
 * стрілка не рухалась, секція лишалась відкритою, вібро відгукувалось. Гірше —
 * тап тихо змінював ЗБЕРЕЖЕНИЙ стан, тож після очищення пошуку папка, згорнута
 * до нього, поверталась розгорнутою (заміряно: `[a1,b1]` → `[b1]`).
 */
test('під час пошуку заголовок працює, а збережений вибір не чіпає', async ({ page }) => {
  const key = `ps:foldCollapse:${USER.id}:${DB_ID}`
  await openWith(page, [A])
  const hd = page.locator('.fold-hd')
  await expect(hd).toHaveAttribute('aria-expanded', 'false')

  await page.getByPlaceholder('Пошук обʼєкту...').fill('Офіс')
  await expect(hd, 'пошук розгортає секцію').toHaveAttribute('aria-expanded', 'true')
  await hd.click()
  await expect(hd, 'тап під час пошуку мусить згорнути секцію').toHaveAttribute('aria-expanded', 'false')
  await hd.click()
  await expect(hd).toHaveAttribute('aria-expanded', 'true')
  await hd.click()
  await expect(hd).toHaveAttribute('aria-expanded', 'false')
  expect(await page.evaluate((k) => localStorage.getItem(k), key), 'тап під час пошуку переписав збережений стан').toBe(JSON.stringify([A]))

  // Новий запит — нові знахідки: секції знову відкриті.
  await page.getByPlaceholder('Пошук обʼєкту...').fill('Офіс 1')
  await expect(hd).toHaveAttribute('aria-expanded', 'true')

  await page.getByPlaceholder('Пошук обʼєкту...').fill('')
  await expect(hd, 'після пошуку — збережений вибір').toHaveAttribute('aria-expanded', 'false')
})

/**
 * ПОРОЖНЯ папка розгорталась у смужку 10px — заголовок перемикав НІЩО. Тепер
 * у тілі пояснення, як її наповнити.
 */
test('порожня папка каже, що вона порожня і як її наповнити', async ({ page }) => {
  const E = '40000000-0000-0000-0000-0000000000e1'
  await setup(page)
  await page.route('**/rest/v1/property_folders**', (r) => jsonRoute(r, [...FOLDERS, { ...FOLDERS[0], id: E, name: 'Нова папка', sort_order: 200 }]))
  await page.goto('/')
  await expect(page.getByText('Мої бази')).toBeVisible({ timeout: 20000 })
  await page.getByText('Міком Палац').first().click()
  await expect(page.locator('.fold-hd')).toHaveCount(2)

  const body = page.locator(`#fold-body-${E}`)
  await expect(body.locator('.fold-empty')).toBeVisible()
  await expect(body).toContainText('Порожня папка')
  await expect(body, 'підказка мусить називати шлях').toContainText('У папку')
  // антивакуум: папка з обʼєктами підказки не має
  await expect(page.locator(`#fold-body-${A} .fold-empty`)).toHaveCount(0)
})

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
  const { samples, blurOff } = await page.evaluate(async () => {
    const hd = document.querySelector('.fold-hd') as HTMLElement
    const wrap = document.querySelector('.fold-wrap') as HTMLElement
    const out:number[] = []
    hd.click()
    let blur = 'no-anim-class'
    for (let i=0;i<14;i++){
      await new Promise(r=>requestAnimationFrame(()=>r(null)))
      out.push(Math.round(wrap.getBoundingClientRect().height))
      if (i === 0) {
        const c = document.querySelector('.fold-wrap.fold-anim .glass-s') as HTMLElement | null
        blur = c ? getComputedStyle(c).backdropFilter : 'no-anim-class'
      }
    }
    return { samples: out, blurOff: blur }
  })
  const distinct = new Set(samples).size
  // A real animation passes through several intermediate heights; a snap gives 1-2.
  expect(distinct, `очікуємо плавні проміжні висоти, отримали ${JSON.stringify(samples)}`).toBeGreaterThan(3)
  // і блюр вимкнено на час руху (інакше 24 скляні шари щокадру = дропнуті кадри)
  expect(blurOff, 'блюр вимкнено на час анімації').toBe('none')
})

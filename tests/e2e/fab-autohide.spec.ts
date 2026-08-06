import { test, expect, type Page } from '@playwright/test'
import { setupApp, DEFAULT_USER, jsonRoute } from './helpers/harness'
const USER={...DEFAULT_USER,role:'owner' as const}
const DB_ID='10000000-0000-0000-0000-000000000001'; const NOW=new Date().toISOString()
const DB={id:DB_ID,owner_id:USER.id,name:'Міком Палац',address:'a',type:'business_center',color:'pink',share_token:'aabbccddeeff001122334455',share_expires_at:null,created_at:NOW,updated_at:NOW,properties:[]}
function prop(n:number){return{id:`20000000-0000-0000-0000-0000000000${String(n).padStart(2,'0')}`,db_id:DB_ID,owner_id:USER.id,name:`Офіс ${n}`,floor:String(n),status:'occupied',area_useful:175,area_total:195,area_basis:'total',rent_type:'per_m2',rent_rate:13,utilities_rate:2.5,has_parking:false,parking_spaces:0,parking_type:null,ev_charger:false,folder_id:null,utilities:null,description:null,address:null,sale_price:null,tenant_name:'ТОВ Тест',lease_start_date:'2025-08-15',lease_end_date:'2027-08-31',sort_order:n,share_token:`bb000000000000000${String(n).padStart(7,'0')}`,share_expires_at:null,created_at:NOW,updated_at:NOW,photos:[]}}
const PROPERTIES=Array.from({length:10},(_,i)=>prop(i+1))
async function setup(page:Page){
  await setupApp(page,{user:USER})
  await page.route('**/rest/v1/databases**',(r)=>jsonRoute(r,(r.request().headers()['accept']??'').includes('object')?DB:[DB]))
  await page.route('**/rest/v1/properties**',(r)=>jsonRoute(r,PROPERTIES))
  await page.route('**/rest/v1/property_folders**',(r)=>jsonRoute(r,[]))
  await page.route('**/rest/v1/db_members**',(r)=>jsonRoute(r,[]))
  await page.addInitScript(()=>localStorage.setItem('ob_v1',JSON.stringify(['owner-fab','obj-fab','realtor-qr','col-fab'])))
}
// FAB і статус-бейдж картки обидва притиснуті до правого краю, тож кнопка
// постійно накривала бейдж. Тепер вона ховається на гортанні вниз (користувач
// читає список) і повертається на гортанні вгору / біля верху.
test('FAB ховається на гортанні вниз і повертається вгору', async ({ page }) => {
  await setup(page); await page.goto('/')
  await expect(page.getByText('Мої бази')).toBeVisible({timeout:20000})
  await page.getByText('Міком Палац').first().click()
  await expect(page.getByText('Всі (10)')).toBeVisible()
  await page.waitForTimeout(900) // fabPop settles
  const fab = page.locator('.fab')
  await expect(fab).not.toHaveClass(/fab-off/)

  await page.locator('.body').evaluate(el=>{el.scrollTop=600}); await page.waitForTimeout(400)
  await expect(fab, 'схована при гортанні вниз').toHaveClass(/fab-off/)
  const offY = await fab.evaluate(el=>el.getBoundingClientRect().top)

  await page.locator('.body').evaluate(el=>{el.scrollTop=300}); await page.waitForTimeout(500)
  await expect(fab, 'повернулась при гортанні вгору').not.toHaveClass(/fab-off/)
  const onY = await fab.evaluate(el=>el.getBoundingClientRect().top)
  expect(offY, 'схована кнопка справді зʼїхала нижче').toBeGreaterThan(onY)

  await page.locator('.body').evaluate(el=>{el.scrollTop=0}); await page.waitForTimeout(400)
  await expect(fab, 'біля верху завжди видима').not.toHaveClass(/fab-off/)
})

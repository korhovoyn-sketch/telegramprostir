import { test, expect } from '@playwright/test'
import { setupApp, DEFAULT_USER, seedSession, seedSupabaseSession } from './helpers/harness'

// Що НЕ вантажиться на старті — по ФАКТИЧНО завантажених скриптах, а не по
// джерелу. Статичний імпорт глибоко в графі модулів джерельний гард не
// побачить: zod потрапляв у початковий бандл через `useAuth`, який сам живе на
// критичному шляху, хоч схема там потрібна рівно одній дії — видаленню акаунта.
// Заміряно: 14.4 КБ gz у КОЖНОМУ старті.
//
// Межа — увесь старт, включно з idle-префетчем (2с таймаут
// `requestIdleCallback`): він тягне лише сім базових екранів, тож бібліотеки
// експорту чи схем не мають туди потрапити й опосередковано.
//
// Маркери — рядки, що живуть лише в самих бібліотеках (перевірено по `out/`):
// `ZodError` — zod, `addFileToVFS` — jsPDF і екран, що його кличе, `SheetJS` —
// xlsx. Антивакуум: клієнт Supabase мусить знайтись, інакше «нічого
// зайвого» означало б «тіла скриптів не прочитались».

test('старт власника не вантажить zod, jsPDF і xlsx', async ({ page }) => {
  const user = { ...DEFAULT_USER, role: 'owner' as const }
  await setupApp(page, { user })
  await seedSession(page, { ...user })
  await seedSupabaseSession(page, { ...user })
  await page.addInitScript(() =>
    localStorage.setItem('ob_v1', JSON.stringify(['owner-fab', 'obj-fab', 'realtor-qr', 'col-fab'])))

  const bodies: Promise<{ url: string; text: string }>[] = []
  page.on('response', (r) => {
    const url = r.url()
    if (!/\/_next\/static\/chunks\/.+\.js$/.test(url)) return
    bodies.push(r.text().then((text) => ({ url, text }), () => ({ url, text: '' })))
  })

  await page.goto('/')
  await expect(page.locator('.tabbar')).toBeVisible({ timeout: 20_000 })
  await page.waitForTimeout(2600)

  const loaded = await Promise.all(bodies)
  expect(loaded.some((s) => s.text.includes('GoTrueClient'))).toBe(true)
  const name = (u: string) => u.replace(/^.*\/chunks\//, '')
  for (const marker of ['ZodError', 'addFileToVFS', 'SheetJS']) {
    expect(loaded.filter((s) => s.text.includes(marker)).map((s) => name(s.url)), marker).toEqual([])
  }
})

import { test, type Page } from '@playwright/test'
import { expect } from '@playwright/test'
import { ALL_GROUPS, OWNER_SCREENS, OWNER, ownerFixtures, atDbObjects, viaDbMenu, type ScreenStep } from './helpers/screens'
import { jsonRoute } from './helpers/harness'

/**
 * ІНСТРУМЕНТ, не гард (`_`-префікс → у прогін не входить):
 *   CI=1 PERF=1 npx playwright test _input-audit --workers=1
 *
 * Проходить УСІ кроки `helpers/screens.ts` і в кожне видиме поле вводить
 * текст СПРАВЖНЬОЮ клавіатурою (не `fill`: `fill` ставить значення одним
 * присвоєнням і не проходить шлях, яким іде палець — санітайзер, каретка,
 * `maxLength`, перехоплення клавіш). Друкує рядок `INPUT_AUDIT` на поле і
 * `INPUT_FLAG` на кожну аномалію:
 *   - не очищається / не набирається / набране спотворене;
 *   - вставка посередині лягає не туди або каретка тікає в кінець;
 *   - виділене не замінюється;
 *   - вставка з буфера (insertText) не доходить;
 *   - значення зникає після виходу з поля (blur);
 *   - поле перекрите іншим елементом; шрифт < 16px.
 */

/** Стани, які обхід не відкриває: поля зʼявляються лише ДІЄЮ на екрані. */
const newForm = async (page: Page) => {
  await atDbObjects(page)
  await page.getByLabel('Додати обʼєкт').click()
  await expect(page.getByText('Новий обʼєкт')).toBeVisible({ timeout: 15_000 })
}
const EXTRA: ScreenStep[] = [
  { label: 'form-sale', go: async (page) => { await newForm(page); await page.locator('.fr-seg-b', { hasText: 'Продаж' }).click() } },
  { label: 'form-occupied', go: async (page) => { await newForm(page); await page.locator('.fr-seg-b', { hasText: 'Зайнято' }).click() } },
  { label: 'form-bulk', go: async (page) => {
    await newForm(page)
    await page.getByLabel('Назва обʼєкта', { exact: true }).fill('Офіс 1')
    await page.getByLabel('Більше обʼєктів').click(); await page.getByLabel('Більше обʼєктів').click()
    await expect(page.getByLabel('Назва обʼєкта 2')).toBeVisible()
  } },
  { label: 'form-folder', go: async (page) => {
    await newForm(page)
    await page.locator('button.fr-tap', { hasText: 'Папка' }).click()
    await expect(page.getByLabel('Назва нової папки')).toBeVisible()
  } },
  { label: 'folder-rename', go: async (page) => {
    await viaDbMenu(page, 'Папки', /Групуйте|Додати папку/)
    await page.getByLabel('Перейменувати').first().click()
  } },
  { label: 'team-invite', go: async (page) => {
    await viaDbMenu(page, 'Команда', /Команда|Запросити/)
    await page.getByLabel('Запросити в команду').click()
    await expect(page.getByRole('button', { name: 'Створити' })).toBeVisible({ timeout: 15_000 })
  } },
  { label: 'parking-form', go: async (page) => {
    const db = { id: '10000000-0000-0000-0000-000000000001', owner_id: OWNER.id, name: 'Паркінг', address: 'a',
      type: 'parking', color: 'purple', share_token: 'aabbccddeeff001122334455', share_expires_at: null,
      created_at: '2025-09-01T09:00:00.000Z', updated_at: '2025-09-01T09:00:00.000Z', properties: [] }
    await page.route('**/rest/v1/databases**', (r) =>
      jsonRoute(r, (r.request().headers()['accept'] ?? '').includes('object') ? db : [db]))
    await newForm(page)
  } },
]

type Probe = {
  i: number; tag: string; type: string; mode: string; name: string; ph: string
  max: number; fs: number; ro: boolean; dis: boolean; before: string
}

const TEXT = 'Офіс №5 «Ґанок» пʼятий'

async function sample(page: Page, sel: string) {
  return page.locator(sel).evaluate((el) => {
    const i = el as HTMLInputElement
    let s: number | null = null
    try { s = i.selectionStart } catch { /* date */ }
    return { v: i.value, s }
  })
}

test.skip(!process.env.PERF, 'інструмент: PERF=1')

const GROUPS = [...ALL_GROUPS, { role: 'owner-extra', fixtures: ownerFixtures, screens: EXTRA }]
void OWNER_SCREENS

for (const group of GROUPS) {
  test(`введення: ${group.role}`, async ({ page }) => {
    test.setTimeout(600_000)
    page.setDefaultTimeout(15_000)
    await group.fixtures(page)
    for (const s of group.screens) {
      try { await s.go(page) } catch (e) { console.log(`INPUT_FLAG ${s.label} :: крок не дійшов: ${(e as Error).message.split('\n')[0]}`); continue }
      await page.waitForTimeout(700)
      const fields: Probe[] = await page.evaluate(() => {
        const els = [...document.querySelectorAll('input, textarea')] as HTMLInputElement[]
        const out: Probe[] = []
        let i = 0
        for (const el of els) {
          if (['file', 'checkbox', 'radio', 'hidden', 'range'].includes(el.type)) continue
          const r = el.getBoundingClientRect()
          const cs = getComputedStyle(el)
          if (r.width < 2 || r.height < 2 || cs.visibility === 'hidden' || cs.display === 'none') continue
          el.setAttribute('data-ia', String(i))
          out.push({
            i, tag: el.tagName.toLowerCase(), type: el.type, mode: el.inputMode,
            name: el.getAttribute('aria-label') ?? '', ph: el.placeholder, max: el.maxLength,
            fs: parseFloat(cs.fontSize), ro: el.readOnly, dis: el.disabled, before: el.value,
          })
          i++
        }
        return out
      })
      if (!fields.length) { console.log(`INPUT_AUDIT ${s.label} :: полів немає`); continue }
      // З КІНЦЯ: очищення ранніх полів (назва) законно перемальовує пізні
      // (рядки масового створення існують лише за непорожньої назви).
      for (const f of [...fields].reverse()) {
        const sel = `[data-ia="${f.i}"]`
        const id = `${s.label} #${f.i} ${f.tag}[${f.type}${f.mode ? '/' + f.mode : ''}] «${f.name || f.ph}»`
        const flags: string[] = []
        if (f.fs < 16) flags.push(`шрифт ${f.fs}px`)
        if (!f.name) flags.push('без aria-label')
        if (f.ro || f.dis) { console.log(`INPUT_AUDIT ${id} :: ${f.ro ? 'readonly' : 'disabled'}`); continue }
        const loc = page.locator(sel)
        if (!(await loc.count())) { console.log(`INPUT_FLAG ${id} :: зникло до заміру`); continue }
        await loc.evaluate((e) => e.scrollIntoView({ block: 'center' }))
        await page.waitForTimeout(150)
        const covered = await loc.evaluate((el) => {
          const r = el.getBoundingClientRect()
          const hit = document.elementFromPoint(r.left + r.width / 2, r.top + r.height / 2)
          return hit && hit !== el && !el.contains(hit) ? (hit as HTMLElement).className || hit.tagName : null
        })
        if (covered) flags.push(`центр перекриває «${covered}»`)
        if (f.type === 'date') {
          await loc.fill('2026-03-15')
          const v = (await sample(page, sel)).v
          if (v !== '2026-03-15') flags.push(`дата: «${v}»`)
          console.log(`INPUT_AUDIT ${id} :: дата → «${v}»`)
          if (flags.length) console.log(`INPUT_FLAG ${id} :: ${flags.join('; ')}`)
          continue
        }
        try { await loc.click({ timeout: 3000 }) } catch { await loc.focus(); flags.push('клік не дійшов (focus напряму)') }
        const focused = await loc.evaluate((el) => document.activeElement === el)
        if (!focused) flags.push('після кліку фокус не в полі')
        await page.keyboard.press('ControlOrMeta+a')
        await page.keyboard.press('Backspace')
        const cleared = (await sample(page, sel)).v
        if (cleared !== '') flags.push(`не очищається: «${cleared}»`)

        const numeric = f.mode === 'decimal' || f.mode === 'numeric' || f.mode === 'tel'
        const typed = f.mode === 'decimal' ? '1234,5' : f.mode === 'numeric' ? '1234' : f.mode === 'tel' ? '+380671234567'
          : f.type === 'email' || f.mode === 'email' ? 'a.b@example.com' : TEXT
        await page.keyboard.type(typed, { delay: 15 })
        const a = await sample(page, sel)
        const okTyped = numeric
          ? a.v.replace(/[^\d]/g, '') === typed.replace(/[^\d]/g, '').slice(0, f.max > 0 ? f.max : undefined)
          : a.v === typed.slice(0, f.max > 0 ? f.max : undefined)
        if (!okTyped) flags.push(`набрано «${typed}» → «${a.v}»`)
        if (a.s !== null && a.s !== a.v.length) flags.push(`каретка після набору ${a.s}/${a.v.length}`)

        // Вставка посередині: три кроки вліво і один символ.
        if (a.v.length >= 4) {
          for (let k = 0; k < 3; k++) await page.keyboard.press('ArrowLeft')
          const ins = numeric ? '7' : 'Ї'
          await page.keyboard.type(ins)
          const b = await sample(page, sel)
          const at = a.v.length - 3
          const want = a.v.slice(0, at) + ins + a.v.slice(at)
          if (b.v !== want && !(numeric && b.v.replace(/\D/g, '') === want.replace(/\D/g, ''))) flags.push(`вставка посередині: «${b.v}», чекали «${want}»`)
          if (b.s !== null && b.s !== at + 1 && b.v === want) flags.push(`каретка після вставки ${b.s}, чекали ${at + 1}`)
          // Backspace посередині.
          await page.keyboard.press('Backspace')
          const c = await sample(page, sel)
          if (c.v !== a.v && !(numeric && c.v.replace(/\D/g, '') === a.v.replace(/\D/g, ''))) flags.push(`backspace посередині: «${c.v}», чекали «${a.v}»`)
        }
        // Заміна виділеного й «вставка» з буфера.
        await page.keyboard.press('ControlOrMeta+a')
        const paste = numeric ? (f.mode === 'tel' ? '+380 67 000 11 22' : '2 500') : f.type === 'email' ? 'x@y.ua' : 'Склад Б'
        await page.keyboard.insertText(paste)
        const d = await sample(page, sel)
        const okPaste = numeric ? d.v.replace(/\D/g, '') === paste.replace(/\D/g, '') : d.v === paste
        if (!okPaste) flags.push(`вставка з буфера «${paste}» → «${d.v}»`)
        // Вихід із поля: значення мусить лишитись (або відкотитись ОСМИСЛЕНО).
        await page.keyboard.press('Tab')
        await page.waitForTimeout(250)
        const still = await page.locator(sel).count()
        if (still) {
          const e = await sample(page, sel)
          if (e.v !== d.v) flags.push(`після blur «${d.v}» → «${e.v}»`)
        }
        console.log(`INPUT_AUDIT ${id} :: набрано «${a.v}» вставлено «${d.v}» max=${f.max} fs=${f.fs}`)
        if (flags.length) console.log(`INPUT_FLAG ${id} :: ${flags.join('; ')}`)
      }
    }
  })
}

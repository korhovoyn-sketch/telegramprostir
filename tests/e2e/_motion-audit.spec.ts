import { test, expect, type Page } from '@playwright/test'
import * as fs from 'node:fs'
import * as path from 'node:path'
import { ALL_GROUPS, OWNER_SCREENS, ownerFixtures } from './helpers/screens'

/**
 * ІНСТРУМЕНТ (не гард): аудит каретки й руху.
 *   PERF=1 SHOTS_DIR=/tmp/x npx playwright test _motion-audit --workers=1
 *
 * Що міряє і чому саме так — див. шапки тестів. Знімки каретки пишуться в
 * SHOTS_DIR для огляду очима: колір і положення каретки скріншот-порівняння
 * не бачать узагалі (конфіг знімає з `caret: 'hide'`).
 */

const SHOTS = process.env.SHOTS_DIR ?? ''
const TEXT_FIELDS = 'input:not([type=date]):not([type=checkbox]):not([type=radio]):not([type=file]):not([type=hidden]):not([type=range]),textarea'

test.use({ contextOptions: { reducedMotion: 'no-preference' } })

test.describe('каретка в усіх полях', () => {
  for (const group of ALL_GROUPS) {
    test(`${group.role}: колір, шар, видимість фокусованого поля`, async ({ page }) => {
      test.setTimeout(600_000)
      const rows: string[] = []
      for (const step of group.screens) {
        await group.fixtures(page)
        try { await step.go(page) } catch (e) { rows.push(`${step.label}: не дійшли (${String(e).slice(0, 60)})`); continue }
        await page.waitForTimeout(500)
        const n = await page.locator(TEXT_FIELDS).count()
        for (let i = 0; i < Math.min(n, 8); i++) {
          const f = page.locator(TEXT_FIELDS).nth(i)
          if (!(await f.isVisible())) continue
          await f.scrollIntoViewIfNeeded().catch(() => {})
          await f.focus()
          await page.waitForTimeout(80)
          const m = await f.evaluate((el: HTMLInputElement) => {
            const cs = getComputedStyle(el)
            const r = el.getBoundingClientRect()
            const cx = r.left + r.width / 2, cy = r.top + r.height / 2
            const hit = document.elementFromPoint(cx, cy)
            return {
              label: el.getAttribute('aria-label') ?? el.getAttribute('placeholder') ?? el.name ?? '?',
              caret: cs.caretColor, color: cs.color, fill: cs.getPropertyValue('-webkit-text-fill-color'),
              align: cs.textAlign, pr: cs.paddingRight, pl: cs.paddingLeft, fs: cs.fontSize,
              transform: cs.transform, focused: document.activeElement === el,
              covered: !!hit && hit !== el && !el.contains(hit),
              w: Math.round(r.width), h: Math.round(r.height),
            }
          })
          rows.push(`${step.label} | ${m.label} | caret=${m.caret} color=${m.color} fill=${m.fill} | align=${m.align} pl=${m.pl} pr=${m.pr} fs=${m.fs} | tf=${m.transform === 'none' ? 'NONE' : 'layer'} | focused=${m.focused} covered=${m.covered} ${m.w}x${m.h}`)
          if (SHOTS) {
            const box = await f.boundingBox()
            if (box) {
              const clip = { x: Math.max(0, box.x - 16), y: Math.max(0, box.y - 10), width: Math.min(375 - Math.max(0, box.x - 16), box.width + 32), height: box.height + 20 }
              // Каретка блимає (~500мс): два кадри з паузою, щоб хоч один
              // зловив її видимою.
              for (const k of [0, 1]) {
                await page.screenshot({ path: path.join(SHOTS, `caret-${group.role}-${step.label}-${i}-${k}.png`), clip, caret: 'initial' })
                await page.waitForTimeout(530)
              }
            }
          }
          await f.blur()
        }
      }
      console.log(`\n═══ ${group.role} ═══\n` + rows.join('\n'))
    })
  }
})

/**
 * Куди стає каретка, коли санітайзер ЗМІНЮЄ введене. Контрольований інпут:
 * якщо після onChange значення в стані не збігається з тим, що в DOM, React
 * записує своє — і браузер ставить каретку в кінець. Тобто відкинутий символ
 * або кома, переписана на крапку, посеред числа викидають курсор у кінець.
 */
test('каретка після санітайзера посеред числа', async ({ page }) => {
  await ownerFixtures(page)
  await OWNER_SCREENS.find((s) => s.label === 'property-form-new')!.go(page)
  const field = page.getByLabel('Орендна ставка за м²')
  await field.scrollIntoViewIfNeeded()
  const out: string[] = []
  for (const [initial, pos, key] of [
    ['1800', 2, 'a'],   // відкинутий символ
    ['1800', 2, ','],   // кома → крапка
    ['1800', 2, '5'],   // звичайна цифра — контроль
    ['18.5', 1, '.'],   // друга крапка
  ] as const) {
    await field.fill(initial)
    await field.evaluate((el: HTMLInputElement, p) => { el.focus(); el.setSelectionRange(p, p) }, pos)
    await page.keyboard.type(key)
    const r = await field.evaluate((el: HTMLInputElement) => ({ v: el.value, s: el.selectionStart }))
    out.push(`«${initial}» курсор ${pos} + «${key}» → «${r.v}», курсор ${r.s}`)
  }
  console.log('\n═══ санітайзер ═══\n' + out.join('\n'))
  expect(out.length).toBe(4)
})

if (SHOTS) fs.mkdirSync(SHOTS, { recursive: true })

export type { Page }

/**
 * ПОКАДРОВИЙ ПРОФІЛЬ РУХУ. Headless Chromium не скаже, чи плавно на iOS, але
 * ГЕОМЕТРІЯ руху від рушія не залежить: стрибок (елемент долетів за один кадр),
 * розворот (поїхав назад), подвійний рух (і X, і Y там, де мав бути один),
 * мерехтіння прозорості — це видно в будь-якому браузері.
 */
async function installSampler(page: Page) {
  await page.evaluate(() => {
    const w = window as unknown as { __prof: (sel: string, ms: number) => Promise<unknown[]> }
    w.__prof = (sel, ms) => new Promise((res) => {
      const out: unknown[] = []
      const t0 = performance.now()
      let lastEl: Element | null = null
      const step = () => {
        const el = document.querySelector(sel)
        if (el) {
          const r = el.getBoundingClientRect()
          let o = 1
          for (let n: Element | null = el; n; n = n.parentElement) o *= parseFloat(getComputedStyle(n).opacity) || 0
          out.push({ t: Math.round(performance.now() - t0), x: Math.round(r.left * 10) / 10, y: Math.round(r.top * 10) / 10,
            o: Math.round(o * 100) / 100, swap: el !== lastEl })
          lastEl = el
        } else out.push({ t: Math.round(performance.now() - t0), none: true })
        if (performance.now() - t0 < ms) requestAnimationFrame(step); else res(out)
      }
      requestAnimationFrame(step)
    })
  })
}

type Sample = { t: number; x?: number; y?: number; o?: number; swap?: boolean; none?: boolean }
function analyse(name: string, s: Sample[]): string {
  const live = s.filter((f) => !f.none)
  if (live.length < 2) return `${name}: елемента немає (${s.length} кадрів)`
  const from = live.findIndex((f, i) => i > 0 && (f.x !== live[i - 1].x || f.y !== live[i - 1].y || f.o !== live[i - 1].o || f.swap))
  const seg = from > 0 ? live.slice(from - 1) : live
  const dx = seg.map((f, i) => i ? Math.abs(f.x! - seg[i - 1].x!) : 0)
  const dy = seg.map((f, i) => i ? Math.abs(f.y! - seg[i - 1].y!) : 0)
  const totX = Math.abs(seg[seg.length - 1].x! - seg[0].x!), totY = Math.abs(seg[seg.length - 1].y! - seg[0].y!)
  const movingX = dx.filter((d) => d > 0.05).length, movingY = dy.filter((d) => d > 0.05).length
  let revY = 0, revX = 0
  for (let i = 2; i < seg.length; i++) {
    const a = seg[i - 1].y! - seg[i - 2].y!, b = seg[i].y! - seg[i - 1].y!
    if (a * b < -0.01) revY++
    const c = seg[i - 1].x! - seg[i - 2].x!, d = seg[i].x! - seg[i - 1].x!
    if (c * d < -0.01) revX++
  }
  const ops = seg.map((f) => f.o!)
  let revO = 0
  for (let i = 2; i < ops.length; i++) if ((ops[i - 1] - ops[i - 2]) * (ops[i] - ops[i - 1]) < -0.0001) revO++
  const maxDy = Math.max(...dy), maxDx = Math.max(...dx)
  const path = seg.slice(0, 14).map((f) => `${f.t}:${f.x},${f.y}/${f.o}${f.swap ? '*' : ''}`).join(' ')
  return `${name}: X ${totX.toFixed(1)}px за ${movingX} кадр. (макс крок ${maxDx.toFixed(1)}), ` +
    `Y ${totY.toFixed(1)}px за ${movingY} кадр. (макс крок ${maxDy.toFixed(1)}), ` +
    `розвороти X/Y/opacity ${revX}/${revY}/${revO}, opacity ${ops[0]}→${ops[ops.length - 1]}\n    ${path}`
}

test('профілі руху ключових жестів', async ({ page }) => {
  test.setTimeout(240_000)
  const out: string[] = []
  const go = (label: string) => OWNER_SCREENS.find((s) => s.label === label)!.go(page)
  const prof = (sel: string, ms: number) =>
    page.evaluate(([s, m]) => (window as unknown as { __prof: (a: string, b: number) => Promise<Sample[]> }).__prof(s, m), [sel, ms] as const)

  // 1. Перехід уперед: список баз → база
  await ownerFixtures(page)
  // Стаб BackButton у харнесі обробник не зберігає — «Назад» інакше не натиснути.
  await page.addInitScript(() => {
    const w = window as unknown as { Telegram: { WebApp: { BackButton: { onClick: (cb: () => void) => void } } }; __tgBack?: () => void }
    w.Telegram.WebApp.BackButton.onClick = (cb) => { w.__tgBack = cb }
  })
  await go('db-list')
  await installSampler(page)
  let p = prof('.scr', 700)
  await page.getByText('БЦ Рубін').first().click()
  out.push(analyse('перехід уперед (.scr)', await p))

  // 2. Шит меню бази: відкриття
  await page.waitForTimeout(500)
  await installSampler(page)
  p = prof('.modal', 700)
  await page.getByLabel('Меню бази').click()
  out.push(analyse('шит: відкриття (.modal)', await p))
  await page.waitForTimeout(300)

  // 3. Шит: закриття бекдропом
  p = prof('.modal', 600)
  await page.mouse.click(187, 60)
  out.push(analyse('шит: закриття (.modal)', await p))

  // 4. Назад: база → список
  await page.waitForTimeout(500)
  p = prof('.scr', 700)
  await page.evaluate(() => (window as unknown as { __tgBack: () => void }).__tgBack())
  out.push(analyse('назад (.scr)', await p))

  // 5. Вкладка таббару
  await page.waitForTimeout(500)
  p = prof('.scr', 700)
  await page.locator('.tabbar [aria-label="Профіль"]').click()
  out.push(analyse('вкладка → Профіль (.scr)', await p))

  // 6. Сегмент: Картки / Компактно на екрані бази
  await go('db-objects')
  await installSampler(page)
  await page.waitForTimeout(400)
  p = prof('.view-seg-b.on', 500)
  await page.getByLabel('Компактно').click()
  out.push(analyse('сегмент вигляду (.view-seg-b.on)', await p))

  console.log('\n═══ профілі руху ═══\n' + out.join('\n'))
  expect(out.length).toBeGreaterThan(4)
})

/**
 * Свайп-закриття: що робить шит ПІСЛЯ відпускання пальця. Підозра: inline-
 * перехід до 100% перебиває анімація класу `closing`, яка стартує з
 * translateY(0) — тобто шит стрибає назад угору.
 */
test('свайп-закриття: кадри після відпускання', async ({ page }) => {
  await ownerFixtures(page)
  await OWNER_SCREENS.find((s) => s.label === 'db-objects')!.go(page)
  await page.waitForTimeout(500)
  await page.getByLabel('Меню бази').click()
  await page.waitForTimeout(600)
  const frames = await page.locator('.modal-head').evaluate(async (el) => {
    const modal = document.querySelector('.modal') as HTMLElement
    const top0 = modal.getBoundingClientRect().top
    const r = el.getBoundingClientRect()
    const x = r.x + r.width / 2, y0 = r.y + 8
    const fire = (type: string, cy: number, ended = false) => {
      const t = new Touch({ identifier: 1, target: el as Element, clientX: x, clientY: cy })
      el.dispatchEvent(new TouchEvent(type, { touches: ended ? [] : [t], changedTouches: [t], bubbles: true, cancelable: true }))
    }
    const raf = () => new Promise((res) => requestAnimationFrame(res))
    const out: string[] = []
    fire('touchstart', y0)
    for (let i = 1; i <= 4; i++) {
      await raf()
      fire('touchmove', y0 + i * 30)
      out.push(`move ${i * 30}: top=${(modal.getBoundingClientRect().top - top0).toFixed(1)}`)
    }
    fire('touchend', y0 + 120, true)
    const t0 = performance.now()
    for (let i = 0; i < 22; i++) {
      await raf()
      const m = document.querySelector('.modal') as HTMLElement | null
      out.push(`+${Math.round(performance.now() - t0)}ms: ${m ? (m.getBoundingClientRect().top - top0).toFixed(1) + (m.classList.contains('closing') ? ' closing' : '') + ' anim=' + getComputedStyle(m).animationName : 'gone'}`)
    }
    return out
  })
  console.log('\n═══ свайп-закриття ═══\n' + frames.join('\n'))
  expect(frames.length).toBeGreaterThan(10)
})

/**
 * Відгук натиску на елементах із каскадом входу (`animation … both`): чи
 * `:active{transform}` узагалі доходить до рендера.
 */
test('натиск на елементах із каскадом входу', async ({ page }) => {
  await ownerFixtures(page)
  const out: string[] = []
  const probe = async (label: string, sel: string) => {
    await page.waitForTimeout(900)
    const el = page.locator(sel).first()
    if (!(await el.count())) { out.push(`${label}: ${sel} — немає`); return }
    const box = (await el.boundingBox())!
    await page.mouse.move(box.x + box.width / 2, box.y + box.height / 2)
    await page.mouse.down()
    await page.waitForTimeout(250)
    const r = await el.evaluate((e) => ({ tf: getComputedStyle(e).transform, active: e.matches(':active'), anim: getComputedStyle(e).animationName, fill: getComputedStyle(e).animationFillMode }))
    await page.mouse.up()
    out.push(`${label}: ${sel} active=${r.active} transform=${r.tf} anim=${r.anim}/${r.fill}`)
  }
  await OWNER_SCREENS.find((s) => s.label === 'db-list')!.go(page)
  await probe('db-list', '.list .row')
  await OWNER_SCREENS.find((s) => s.label === 'db-objects')!.go(page)
  await probe('db-objects', '.list > .obj-card')
  await OWNER_SCREENS.find((s) => s.label === 'profile')!.go(page)
  await probe('profile', '.profile-stats .pstat')
  console.log('\n═══ натиск ═══\n' + out.join('\n'))
  expect(out.length).toBe(3)
})

import { test, expect, type Page } from '@playwright/test'
import { ownerFixtures, OWNER_SCREENS } from './helpers/screens'

/**
 * СВАЙП ШИТА — ГЕОМЕТРІЯ, А НЕ ЛОГІКА.
 *
 * `modal-a11y` перевіряє, що свайп ЗАКРИВАЄ і що snap-back не лишає inline-
 * стилів, — тобто логіку. Що шит при цьому РУХАЄТЬСЯ, не перевіряв ніхто, і він
 * не рухався: `.modal{animation: modalSlideUp … both}` тримав `translateY(0)`
 * заповненням `forwards`, а анімація в каскаді бʼє inline-стиль жесту. Заміряно:
 * палець пройшов 120px, шит — 0px; затемнення теж не відгукувалось. А після
 * відпускання `modalSlideDown{from{translateY(0)}}` вертав би шит до нуля, щойно
 * жест став видимим.
 */

test.use({ contextOptions: { reducedMotion: 'no-preference' } })

async function openMenu(page: Page) {
  await ownerFixtures(page)
  await OWNER_SCREENS.find((s) => s.label === 'db-objects')!.go(page)
  await page.waitForTimeout(500)
  await page.getByLabel('Меню бази').click()
  // Чекаємо кінця виїзду: під час `modalSlideUp` анімація ЗАКОННО веде шит.
  await page.waitForFunction(() => {
    const m = document.querySelector('.modal')
    return !!m && m.getAnimations().every((a) => a.playState === 'finished')
  })
}

type Drag = { during: { dy: number; top: number; ov: number }[]; after: { t: number; top: number | null; tf: string | null }[] }

/** Тягне хедер шита кроками по кадру і пише, де шит під пальцем і після. */
function swipe(page: Page, steps: number[], release: boolean): Promise<Drag> {
  return page.locator('.modal-head').evaluate(async (el, { steps, release }) => {
    const modal = document.querySelector('.modal') as HTMLElement
    const overlay = document.querySelector('.modal-overlay') as HTMLElement
    const top0 = modal.getBoundingClientRect().top
    const r = el.getBoundingClientRect()
    const x = r.x + r.width / 2, y0 = r.y + 8
    const fire = (type: string, cy: number, ended = false) => {
      const t = new Touch({ identifier: 1, target: el as Element, clientX: x, clientY: cy })
      el.dispatchEvent(new TouchEvent(type, { touches: ended ? [] : [t], changedTouches: [t], bubbles: true, cancelable: true }))
    }
    const raf = () => new Promise((res) => requestAnimationFrame(res))
    const out: Drag = { during: [], after: [] }
    fire('touchstart', y0)
    for (const dy of steps) {
      await raf()
      fire('touchmove', y0 + dy)
      await raf()
      out.during.push({ dy, top: modal.getBoundingClientRect().top - top0, ov: parseFloat(getComputedStyle(overlay).opacity) })
    }
    if (!release) return out
    fire('touchend', y0 + steps[steps.length - 1], true)
    const t0 = performance.now()
    while (performance.now() - t0 < 500) {
      await raf()
      const m = document.querySelector('.modal') as HTMLElement | null
      out.after.push({
        t: performance.now() - t0,
        top: m ? m.getBoundingClientRect().top - top0 : null,
        tf: m?.classList.contains('closing') ? getComputedStyle(m).animationTimingFunction : null,
      })
    }
    return out
  }, { steps, release })
}

test('шит іде за пальцем, а виїзд стартує з точки відпускання', async ({ page }) => {
  await openMenu(page)
  const d = await swipe(page, [30, 60, 90, 120], true)

  for (const s of d.during) {
    expect(Math.abs(s.top - s.dy), `палець ${s.dy}px — шит на ${s.top.toFixed(1)}px`).toBeLessThan(1.5)
  }
  expect(d.during[d.during.length - 1].ov, 'затемнення відгукується на жест').toBeLessThan(0.9)

  const moving = d.after.filter((f) => f.top !== null) as { t: number; top: number; tf: string | null }[]
  // антивакуум: шит справді виїхав, а не лишився на місці
  expect(moving.length, 'кадри виїзду').toBeGreaterThan(3)
  expect(d.after[d.after.length - 1].top, 'шит зник після виїзду').toBeNull()
  const lowest = Math.min(...moving.map((f) => f.top))
  expect(lowest, 'шит стрибнув назад угору перед виїздом').toBeGreaterThan(118)
  // після флiку крива виїзду — різкий старт: шит уже має швидкість жесту
  const tf = moving.find((f) => f.tf)?.tf
  expect(tf, 'крива виїзду після свайпу').toBe('cubic-bezier(0.16, 1, 0.3, 1)')
})

test('свайп нижче порога вертає шит видимо, тап по фону виїжджає мʼяко', async ({ page }) => {
  await openMenu(page)
  const top0 = await page.evaluate(() => document.querySelector('.modal')!.getBoundingClientRect().top)
  const d = await swipe(page, [20, 40], false)
  expect(d.during[1].top, 'шит під пальцем до відпускання').toBeGreaterThan(38)

  // Повільне відпускання: останній рух без зміщення гасить швидкість, інакше
  // 20px за два кадри — це вже флік (поріг 0.5px/мс) і шит закрився б.
  await page.locator('.modal-head').evaluate(async (el) => {
    const r = el.getBoundingClientRect()
    const t = new Touch({ identifier: 1, target: el, clientX: r.x + r.width / 2, clientY: r.y + 8 })
    await new Promise((res) => setTimeout(res, 120))
    el.dispatchEvent(new TouchEvent('touchmove', { touches: [t], changedTouches: [t], bubbles: true, cancelable: true }))
    el.dispatchEvent(new TouchEvent('touchend', { touches: [], changedTouches: [t], bubbles: true, cancelable: true }))
  })
  await page.waitForTimeout(450)
  await expect(page.locator('.modal')).toBeVisible()
  const back = await page.evaluate(() => document.querySelector('.modal')!.getBoundingClientRect().top)
  expect(Math.abs(back - top0), 'шит повернувся на місце').toBeLessThan(1)

  // Тап по фону: крива виїзду — мʼякий старт, а не експо (`--ease-out`
  // проходила ~75% шляху за три кадри).
  const tf = page.evaluate(() => new Promise<string>((res) => {
    const m = document.querySelector('.modal')!
    new MutationObserver((_, mo) => {
      if (m.classList.contains('closing')) { mo.disconnect(); res(getComputedStyle(m).animationTimingFunction) }
    }).observe(m, { attributes: true, attributeFilter: ['class'] })
  }))
  await page.mouse.click(187, 40)
  expect(await tf, 'крива виїзду від тапу').toBe('cubic-bezier(0.4, 0, 0.2, 1)')
})

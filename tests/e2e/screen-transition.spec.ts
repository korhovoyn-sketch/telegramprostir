import { test, expect, type Page } from '@playwright/test'
import { ownerFixtures, OWNER_SCREENS } from './helpers/screens'

/**
 * ПЕРЕХІД МІЖ ЕКРАНАМИ — ОДИН РУХ.
 *
 * Доти обгортка `.nav-wrap` їхала по X, а `.scr` усередині неї — ще й по Y.
 * Покадровий замір показав, що «Назад» вів екран ПО ДІАГОНАЛІ (48px X + 22px Y
 * одночасно), а «Вперед» на першому вході — двома входами поспіль: обгортка
 * доїжджала з фіолетовою заглушкою, поки вантажився чанк, і справжній екран
 * потім входив удруге, сам. Тобто вигляд переходу залежав від кешу.
 *
 * Міряється ГЕОМЕТРІЯ кореня екрана покадрово (rAF), а не CSS-текст: правило
 * могло б стояти, а перебивати його — специфічність чи вкладена анімація.
 */

test.use({ contextOptions: { reducedMotion: 'no-preference' } })

type Frame = { t: number; x: number; y: number; id: number }

/** Стаб BackButton у харнесі обробник не зберігає — інакше «Назад» не натиснути. */
async function captureBack(page: Page) {
  await page.addInitScript(() => {
    const w = window as unknown as { Telegram: { WebApp: { BackButton: { onClick: (cb: () => void) => void } } }; __tgBack?: () => void }
    w.Telegram.WebApp.BackButton.onClick = (cb) => { w.__tgBack = cb }
  })
}

/** Кадри кореня НОВОГО екрана (не заглушки) протягом `ms`. */
function sampleRoot(page: Page, ms: number): Promise<Frame[]> {
  return page.evaluate((dur) => new Promise<Frame[]>((res) => {
    const out: Frame[] = []
    const ids = new WeakMap<Element, number>()
    let next = 0
    const t0 = performance.now()
    const step = () => {
      const el = document.querySelector('.nav-wrap > :not(.scr-wait)')
      if (el) {
        if (!ids.has(el)) ids.set(el, next++)
        const r = el.getBoundingClientRect()
        out.push({ t: performance.now() - t0, x: r.left, y: r.top, id: ids.get(el)! })
      }
      if (performance.now() - t0 < dur) requestAnimationFrame(step); else res(out)
    }
    requestAnimationFrame(step)
  }), ms)
}

/** Хід нового екрана: усі кадри останнього кореня. */
function travel(frames: Frame[]) {
  const last = frames.length ? frames[frames.length - 1].id : -1
  const own = frames.filter((f) => f.id === last)
  const xs = own.map((f) => f.x), ys = own.map((f) => f.y)
  return {
    frames: own.length,
    dx: own.length ? Math.max(...xs) - Math.min(...xs) : 0,
    dy: own.length ? Math.max(...ys) - Math.min(...ys) : 0,
  }
}

test('«Вперед», «Назад» і вкладка: екран рухається ОДНІЄЮ віссю', async ({ page }) => {
  await ownerFixtures(page)
  await captureBack(page)
  await OWNER_SCREENS.find((s) => s.label === 'db-objects')!.go(page)
  await page.waitForTimeout(600)

  // Перший вхід у картку — чанк уже в кеші після цього; тут міряємо лише кеш.
  await page.locator('.obj-t').first().click()
  await expect(page.locator('.nav-wrap > .scr:not(.scr-wait)')).toHaveCount(1)
  await page.waitForTimeout(700)

  const back = sampleRoot(page, 600)
  await page.evaluate(() => (window as unknown as { __tgBack: () => void }).__tgBack())
  const b = travel(await back)
  // антивакуум: перехід справді відбувся і справді рухався
  expect(b.frames, 'назад: кадрів нового екрана').toBeGreaterThan(5)
  expect(b.dx, 'назад: екран мусить їхати по X').toBeGreaterThan(30)
  expect(b.dy, 'назад: і НЕ рухатись по Y (діагональ = дві вкладені анімації)').toBeLessThan(0.5)

  await page.waitForTimeout(500)
  const fwd = sampleRoot(page, 600)
  await page.locator('.obj-t').first().click()
  const f = travel(await fwd)
  expect(f.dx, 'вперед: екран мусить їхати по X').toBeGreaterThan(30)
  expect(f.dy, 'вперед: і НЕ рухатись по Y').toBeLessThan(0.5)

  // Вкладка — навігація «root»: підйом без руху вбік. Таббар є на списку,
  // не на картці — тож спершу назад.
  await page.waitForTimeout(500)
  await page.evaluate(() => (window as unknown as { __tgBack: () => void }).__tgBack())
  await expect(page.locator('.tabbar')).toBeVisible()
  await page.waitForTimeout(500)
  const tab = sampleRoot(page, 600)
  await page.locator('.tabbar [aria-label="Профіль"]').click()
  const t = travel(await tab)
  expect(t.dy, 'вкладка: екран піднімається').toBeGreaterThan(10)
  expect(t.dx, 'вкладка: і НЕ їде вбік').toBeLessThan(0.5)
})

test('ледачий екран: заглушка нейтральна і не входить сама, екран входить ОДИН раз', async ({ page }) => {
  await ownerFixtures(page)
  await OWNER_SCREENS.find((s) => s.label === 'db-objects')!.go(page)
  await page.waitForTimeout(600)

  // Картку обʼєкта сплеш заздалегідь не тягне — тож її чанк піде мережею, і
  // затримка робить заглушку гарантовано видимою.
  await page.route(/\/_next\/static\/chunks\/.+\.js/, async (r) => {
    await new Promise((res) => setTimeout(res, 700))
    await r.continue()
  })
  await page.evaluate(() => {
    const w = window as unknown as { __seen: Record<string, unknown>[] }
    w.__seen = []
    const wrap = () => document.querySelector('.nav-wrap')
    // Стиль знімається В МИТЬ вставки: потім анімація добіжить і нічого не покаже.
    const mo = new MutationObserver(() => {
      const root = wrap()?.firstElementChild
      if (!root || w.__seen.some((s) => s.node === root)) return
      const cs = getComputedStyle(root)
      const loader = root.querySelector('.loader')
      w.__seen.push({
        node: root,
        wait: root.classList.contains('scr-wait'),
        anim: cs.animationName,
        bg: cs.backgroundImage,
        wrapAnim: getComputedStyle(wrap()!).animationName,
        loaderOpacity: loader ? parseFloat(getComputedStyle(loader).opacity) : null,
      })
    })
    mo.observe(document.body, { childList: true, subtree: true })
  })
  await page.locator('.obj-t').first().click()
  await expect(page.locator('.nav-wrap > .scr:not(.scr-wait)')).toHaveCount(1, { timeout: 10_000 })

  const seen = await page.evaluate(() =>
    (window as unknown as { __seen: Record<string, unknown>[] }).__seen.map(({ node: _n, ...rest }) => rest))
  const wait = seen.find((s) => s.wait)
  // антивакуум: без видимої заглушки тест не перевіряв би нічого
  expect(wait, `заглушка мусила зʼявитись: ${JSON.stringify(seen)}`).toBeTruthy()
  expect(wait!.anim, 'заглушка не входить сама — інакше екран входить удруге').toBe('none')
  expect(wait!.bg, 'заглушка без власного фону — фіолетова читалась як чужий екран').toBe('none')
  expect(wait!.loaderOpacity as number, 'спінер не блимає на швидкому завантаженні').toBeLessThan(0.05)

  const real = seen.filter((s) => !s.wait).pop()
  expect(real, 'справжній екран мусив зʼявитись').toBeTruthy()
  expect(real!.anim, 'справжній екран входить сам, напрямком').toBe('navRight')
  expect(real!.wrapAnim, 'обгортка не рухається разом з екраном').toBe('none')

  // Нижня смуга Telegram бере колір НИЗУ градієнта ЕКРАНА. Доти вона брала його
  // з першого `.scr` з фоном — тобто з фіолетової заглушки, і синій екран
  // діставав фіолетову смугу; а без кольору заглушки 12 кадрів очікування не
  // вистачало повільному чанку, і смуга лишалась чорною.
  const bar = () => page.evaluate(() => {
    const w = window as unknown as Record<string, string | undefined>
    const el = document.querySelector('#app-root .scr[class*="bg-"]:not(.scr-wait)')
    return {
      bottom: (w.__tgBottomBarColor ?? '').toLowerCase(),
      end: el ? getComputedStyle(el).getPropertyValue('--bg-end').trim().toLowerCase() : '',
    }
  })
  expect((await bar()).end, 'екран без --bg-end — перевірка стала б порожньою').toMatch(/^#[0-9a-f]{6}$/)
  await expect.poll(async () => { const b = await bar(); return b.bottom === b.end }, {
    message: 'нижня смуга не взяла колір екрана, що вантажився ліниво',
  }).toBe(true)
})

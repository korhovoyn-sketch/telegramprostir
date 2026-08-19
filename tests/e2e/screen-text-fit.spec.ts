import { test, expect, type Page } from '@playwright/test'
import { ALL_GROUPS } from './helpers/screens'

/**
 * ТЕКСТ, ЯКИЙ НЕ ВМІЩАЄТЬСЯ — на ЕКРАНАХ, а не в шитах.
 *
 * `modal-sweep.spec.ts` уже має цю перевірку, але лише для інстансів `<Modal>`:
 * обрізаний підпис поля («Експлуатаційні, $/м²» з'їдав саму ОДИНИЦЮ) і підпис
 * кнопки, що вилазить за половинну кнопку. Заголовків ЕКРАНІВ і полів поза
 * модалками не міряв НІХТО — і саме через цю прогалину переїзд шитів на
 * повноекранні маршрути (фази 2-3) привіз два дефекти одразу, обидва видимі на
 * скріншоті й обидва непомічені 294 тестами:
 *
 *   • `payment-confirm` заголовок «Підтвердити отримання» — 204px проти 202px
 *     доступних, тобто «…отриман…»: у шиті заголовок мав усю ширину, а в хедері
 *     екрана з ним конкурує кнопка «Назад»;
 *   • плейсхолдер нотатки — 287px потрібно проти 116px доступних, тобто
 *     «Готівка, пере». Шит стояв на `.fld` (підпис НАД полем) саме тому, а
 *     переведення на `.fr` у фазі 2 цього не врахувало.
 *
 * Обидва — з класу, який CLAUDE.md уже описує для InviteSheet. Тобто клас був
 * відомий, бракувало саме гарда на екранах.
 */

/** Заголовок хедера з `ellipsis` — обрізання видно лише по scrollWidth. */
async function truncatedTitle(page: Page): Promise<string | null> {
  return page.evaluate(() => {
    const t = document.querySelector('.hdr-t') as HTMLElement | null
    if (!t) return null
    // Підзаголовок — окремий вузол усередині; він має власну ширину й до
    // обрізання самого заголовка не стосується.
    const own = Array.from(t.childNodes)
      .filter((n) => n.nodeType === Node.TEXT_NODE)
      .map((n) => (n.textContent ?? '').trim())
      .join('')
    const over = t.scrollWidth - t.clientWidth
    if (over <= 0) return null
    return `заголовок «${own}» обрізано на ${over}px (${t.scrollWidth} проти ${t.clientWidth})`
  })
}

/**
 * Плейсхолдер, що не вміщається у видиму ширину поля.
 *
 * Міряється ПРОБНИМ вузлом із тим самим шрифтом, а не `scrollWidth` інпута:
 * інпут скролиться, тож його `scrollWidth` дорівнює `clientWidth`, поки в полі
 * немає значення — плейсхолдер у прокрутку не входить, і обрізання невидиме.
 */
async function clippedPlaceholders(page: Page): Promise<string[]> {
  return page.evaluate(() => {
    const bad: string[] = []
    document.querySelectorAll('input').forEach((el) => {
      const i = el as HTMLInputElement
      const ph = i.getAttribute('placeholder') ?? ''
      if (!ph || i.type === 'hidden' || i.type === 'file') return
      if (i.getBoundingClientRect().height === 0) return
      const cs = getComputedStyle(i)
      const probe = document.createElement('span')
      probe.style.cssText = `position:absolute;visibility:hidden;white-space:pre;font:${cs.font}`
      probe.textContent = ph
      document.body.appendChild(probe)
      const need = probe.getBoundingClientRect().width
      probe.remove()
      const avail = i.clientWidth - parseFloat(cs.paddingLeft || '0') - parseFloat(cs.paddingRight || '0')
      // 1px — антиаліасинг вимірювання, не запас.
      if (need > avail + 1) bad.push(`«${ph}»: потрібно ${Math.round(need)}px, доступно ${Math.round(avail)}px`)
    })
    return bad
  })
}

/**
 * Заморожений борг. Порожньо — і має лишатись порожнім: обидва знайдені дефекти
 * ВИПРАВЛЕНІ, а не заморожені. Якщо тут щось з'являється, у записі мусить бути
 * причина, чому текст скорочувати нікуди.
 */
const FIT_DEBT: Record<string, string[]> = {}

for (const group of ALL_GROUPS) {
  test(`текст вміщується: ${group.role}`, async ({ page }) => {
    test.setTimeout(180_000)
    await group.fixtures(page)

    const problems: string[] = []
    const visited: string[] = []
    for (const step of group.screens) {
      await step.go(page)
      visited.push(step.label)
      const allowed = FIT_DEBT[step.label] ?? []

      const title = await truncatedTitle(page)
      if (title && !allowed.includes(title)) problems.push(`${step.label}: ${title}`)

      for (const ph of await clippedPlaceholders(page)) {
        if (!allowed.includes(ph)) problems.push(`${step.label}: плейсхолдер ${ph}`)
      }
    }

    // Антивакуумність: обхід мусить дійти до кожного кроку, інакше «дефектів не
    // знайдено» означало б «маршрут обірвався на першому».
    expect(visited, `${group.role}: обхід не дійшов до всіх екранів`)
      .toEqual(group.screens.map((s) => s.label))
    expect(problems, 'текст обрізано — скороти підпис або дай полю повну ширину (`.fld`)')
      .toEqual([])
  })
}

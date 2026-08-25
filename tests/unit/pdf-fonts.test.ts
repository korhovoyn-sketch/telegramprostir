import { describe, it, expect } from 'vitest'
import { readFileSync, existsSync, statSync } from 'node:fs'
import { resolve } from 'node:path'

/**
 * ШРИФТ ДЛЯ PDF — НАЙДОРОЖЧА МОВЧАЗНА ПОМИЛКА ЦЬОГО ЕКРАНА.
 *
 * `jsPDF` не має кирилиці у вбудованих шрифтах, тож `ExportScreen` довантажує
 * Roboto з `public/fonts/`. Теки `public/` у репозиторії НЕ БУЛО ЖОДНОГО РАЗУ
 * за всю історію — тобто `fetch` віддавав 404, а `fetch` на 404 НЕ КИДАЄ: він
 * повертає `ok:false` і тіло сторінки помилки. Помилка ковталась, і експорт у
 * PDF не працював у проді ніколи, при цьому виглядав робочим.
 *
 * Гард джерельний, а не рантаймовий, свідомо: e2e ганяються проти статичної
 * збірки, де `public/` уже скопійовано в `out/`, тож зникнення файлу з репо
 * вони б побачили лише як падіння того самого експорту — без натяку на причину.
 */
describe('шрифт PDF', () => {
  const FONTS = ['Roboto-Regular.ttf', 'Roboto-Bold.ttf']

  it.each(FONTS)('%s лежить у public/fonts і не є заглушкою', (name) => {
    const path = resolve(process.cwd(), 'public/fonts', name)
    expect(existsSync(path), `${name} немає — експорт PDF мовчки віддасть 404`).toBe(true)
    // Порожній файл або HTML-сторінка помилки, збережена замість шрифту, дали б
    // рівно ту саму мовчазну поразку, що й відсутній файл.
    expect(statSync(path).size, `${name} завеликий/замалий для TTF`).toBeGreaterThan(100_000)
    expect(readFileSync(path).subarray(0, 4).toString('hex'), `${name}: не TTF`)
      .toBe('00010000')
  })

  it.each(FONTS)('%s покриває українську кирилицю', (name) => {
    const buf = readFileSync(resolve(process.cwd(), 'public/fonts', name))

    // Мінімальний розбір `cmap` (формат 4) — досить, щоб довести, що потрібні
    // кодпойнти в шрифті Є. Без цієї перевірки підміна на будь-який валідний
    // латинський TTF пройшла б попередній тест і зламала документ.
    const numTables = buf.readUInt16BE(4)
    let cmapOff = 0
    for (let i = 0; i < numTables; i++) {
      const rec = 12 + i * 16
      if (buf.subarray(rec, rec + 4).toString('latin1') === 'cmap') cmapOff = buf.readUInt32BE(rec + 8)
    }
    expect(cmapOff, `${name}: немає таблиці cmap`).toBeGreaterThan(0)

    let subOff = 0
    const nSub = buf.readUInt16BE(cmapOff + 2)
    for (let i = 0; i < nSub; i++) {
      const rec = cmapOff + 4 + i * 8
      const platform = buf.readUInt16BE(rec)
      const encoding = buf.readUInt16BE(rec + 2)
      const off = cmapOff + buf.readUInt32BE(rec + 4)
      if (buf.readUInt16BE(off) === 4 && (platform === 3 && (encoding === 1 || encoding === 10))) subOff = off
    }
    expect(subOff, `${name}: немає підтаблиці Windows Unicode`).toBeGreaterThan(0)

    const segX2 = buf.readUInt16BE(subOff + 6)
    const endBase = subOff + 14
    const startBase = endBase + segX2 + 2
    const has = (cp: number) => {
      for (let s = 0; s < segX2 / 2; s++) {
        if (buf.readUInt16BE(endBase + s * 2) >= cp && buf.readUInt16BE(startBase + s * 2) <= cp) return true
      }
      return false
    }

    // Ґ/ґ/Є/є/І/і/Ї/ї — саме те, чого немає в базовій латиниці й у більшості
    // «російських» субсетів; «м²» і «—» ходять у підписах ставок і порожніх
    // значень на кожній сторінці.
    for (const ch of 'ҐґЄєІіЇїАЯаяБЦРубін№м²—·–') {
      expect(has(ch.codePointAt(0)!), `${name}: немає гліфа «${ch}»`).toBe(true)
    }
  })
})

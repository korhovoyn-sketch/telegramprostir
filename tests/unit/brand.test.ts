import { describe, it, expect } from 'vitest'
import { readdirSync, readFileSync } from 'node:fs'
import { join } from 'node:path'

/**
 * ЄДИНЕ ІМʼЯ ПРОДУКТУ — «prostir» (рішення власника, листопад 2026).
 *
 * Застосунок, сторінки політики, імʼя бота й short name Mini App казали
 * «prostir», а повідомлення бота (`/start`, `/help`, `/privacy`), тексти
 * нагадувань про платежі, шапка КОЖНОЇ сторінки PDF-експорту й підпис на
 * десктопі — «PropSpace». Для людини це два різні продукти: орендар отримує
 * від власника PDF з одним імʼям, а потім бачить інше в Telegram.
 *
 * Гард джерельний: рендером не закрити — тексти бота й нагадувань живуть в
 * edge-функціях, а шапка PDF — це гліфи субсету шрифту, не текст у DOM.
 *
 * НЕ ЧІПАЄТЬСЯ І НЕ ПОВИННО: `@telegram.propspace.app` — якір ідентичності
 * (email, з якого резолвери виводять tg_id), він з малої літери і сюди не
 * потрапляє. Регістр тут суттєвий: шукаємо саме ЗАПИСАНЕ ім'я бренду.
 */
const OLD_BRAND = /PropSpace|PROPSPACE/

function walk(dir: string, exts: string[], out: string[] = []): string[] {
  for (const e of readdirSync(dir, { withFileTypes: true })) {
    const full = join(dir, e.name)
    if (e.isDirectory()) walk(full, exts, out)
    else if (exts.some((x) => full.endsWith(x))) out.push(full)
  }
  return out
}

describe('єдине імʼя продукту', () => {
  const files = [
    ...walk('src', ['.ts', '.tsx', '.css']),
    ...walk(join('supabase', 'functions'), ['.ts']),
  ]

  it('обхід справді бачить застосунок і edge-функції', () => {
    // Антивакуум: порожній обхід дав би «старого імені немає» на будь-якому коді.
    expect(files.length).toBeGreaterThan(80)
    expect(files.some((f) => f.endsWith('telegram-bot/index.ts'))).toBe(true)
    expect(files.some((f) => f.endsWith('send-reminders/index.ts'))).toBe(true)
    expect(files.some((f) => f.endsWith('ExportScreen.tsx'))).toBe(true)
  })

  it('старе імʼя не лишилось ні в застосунку, ні в повідомленнях бота й нагадувань', () => {
    const offenders: string[] = []
    for (const f of files) {
      const lines = readFileSync(f, 'utf8').split('\n')
      lines.forEach((line, i) => { if (OLD_BRAND.test(line)) offenders.push(`${f}:${i + 1}: ${line.trim().slice(0, 90)}`) })
    }
    expect(offenders, 'залишилось старе імʼя продукту').toEqual([])
  })

  it('якір ідентичності на місці: без нього вхід не знайде жодного користувача', () => {
    // Дзеркальна половина: масова заміна «propspace» → «prostir» зламала б вхід
    // для УСІХ, і цей гард мусить упасти раніше, ніж така заміна дійде до проду.
    const auth = readFileSync(join('supabase', 'functions', 'telegram-auth', 'index.ts'), 'utf8')
    expect(auth).toContain('@telegram.propspace.app')
  })
})

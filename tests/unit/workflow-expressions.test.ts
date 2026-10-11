import { describe, it, expect } from 'vitest'
import { readFileSync, readdirSync } from 'node:fs'
import { join } from 'node:path'

/**
 * GitHub обчислює вирази `${{ … }}` у ВСЬОМУ тексті значення, а не лише там,
 * де вони щось означають: shell-коментар усередині `run: |` для нього такий
 * самий рядок, як і команда. Порожній чи незакритий вираз робить невалідним
 * УВЕСЬ файл — і воркфлоу перестає запускатись узагалі, а на кожен пуш GitHub
 * створює «провалений» прогін, названий шляхом до файлу.
 *
 * Саме так `set-supabase-secrets.yml` пролежав зламаним від `f535c17`:
 * коментар, що ПОЯСНЮВАВ безпековий фікс, містив буквальне `${{ }}`. Тобто
 * крок, який чекліст називає обовʼязковою дією власника (покласти
 * CRON_SECRET), не стартував би взагалі. YAML при цьому валідний —
 * жоден парсер YAML цього не бачить, тільки GitHub.
 */
const DIR = join(process.cwd(), '.github/workflows')
const files = readdirSync(DIR).filter(f => /\.ya?ml$/.test(f))
const OPEN = '$' + '{{'

describe('вирази GitHub у воркфлоу', () => {
  it('антивакуум: воркфлоу знайдені й вирази в них є', () => {
    expect(files.length).toBeGreaterThanOrEqual(5)
    const total = files.reduce((n, f) => n + readFileSync(join(DIR, f), 'utf8').split(OPEN).length - 1, 0)
    expect(total).toBeGreaterThan(20)
  })

  for (const f of files) {
    const lines = readFileSync(join(DIR, f), 'utf8').split('\n')

    it(`${f}: кожен вираз непорожній і закритий у тому ж рядку`, () => {
      const bad: string[] = []
      lines.forEach((l, i) => {
        let at = l.indexOf(OPEN)
        while (at !== -1) {
          const end = l.indexOf('}}', at + 3)
          const body = end === -1 ? null : l.slice(at + 3, end).trim()
          if (body === null || body === '') bad.push(`${i + 1}: ${l.trim()}`)
          at = l.indexOf(OPEN, at + 3)
        }
      })
      expect(bad).toEqual([])
    })

    it(`${f}: у коментарях немає виразів (у run їх теж обчислюють)`, () => {
      const bad = lines
        .map((l, i) => [i + 1, l] as const)
        .filter(([, l]) => /^\s*#/.test(l) && l.includes(OPEN))
        .map(([n, l]) => `${n}: ${l.trim()}`)
      expect(bad).toEqual([])
    })
  }
})

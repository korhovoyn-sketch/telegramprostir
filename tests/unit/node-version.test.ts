import { describe, it, expect } from 'vitest'
import { readFileSync, readdirSync } from 'node:fs'
import { resolve } from 'node:path'

/**
 * ОДНА ВЕРСІЯ NODE НА ВСІХ, ДЕ ЗБИРАЄТЬСЯ ЗАСТОСУНОК.
 *
 * Vercel бере мажор із `engines.node` і в жовтні 2026 перестав збирати на
 * Node 20 («Node.js Version 20.x is discontinued») — тобто КОЖЕН новий деплой,
 * включно з продом після мерджу, падав, поки CI лишався зеленим: раннер ставив
 * свою двадцятку з `setup-node` і не знав про рішення платформи. Звідси правило:
 * CI мусить збирати на ТІЙ САМІЙ версії, що й прод, інакше зелений CI нічого не
 * каже про те, чи збереться деплой.
 */
const root = process.cwd()
const read = (p: string) => readFileSync(resolve(root, p), 'utf8')

describe('версія Node узгоджена', () => {
  const engines = JSON.parse(read('package.json')).engines?.node as string | undefined
  const major = engines?.match(/^(\d+)\.x$/)?.[1]

  it('package.json фіксує мажор у формі «N.x» (саме її читає Vercel)', () => {
    expect(major, `engines.node = ${engines}`).toBeDefined()
    expect(Number(major), 'Node 20 Vercel більше не збирає').toBeGreaterThanOrEqual(22)
  })

  it('lockfile, .nvmrc і кожен setup-node у воркфлоу — той самий мажор', () => {
    const lock = JSON.parse(read('package-lock.json'))
    expect(lock.packages?.['']?.engines?.node).toBe(engines)
    expect(read('.nvmrc').trim()).toBe(major)

    const dir = resolve(root, '.github/workflows')
    const versions = readdirSync(dir)
      .filter((f) => f.endsWith('.yml'))
      .flatMap((f) => [...readFileSync(resolve(dir, f), 'utf8').matchAll(/node-version:\s*['"]?(\d+)/g)]
        .map((m) => `${f}:${m[1]}`))
    // Антивакуум: воркфлоу з Node є, інакше «усі збігаються» нічого не доводить.
    expect(versions.length).toBeGreaterThanOrEqual(2)
    for (const v of versions) expect(v.split(':')[1], v).toBe(major)
  })
})

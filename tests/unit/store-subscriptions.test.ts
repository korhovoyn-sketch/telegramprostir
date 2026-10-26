import { describe, it, expect } from 'vitest'
import { readFileSync, readdirSync, statSync } from 'node:fs'
import { join } from 'node:path'

// Два правила підписки на стор, обидва з заміру (`_optimize.spec.ts`).
//
// 1. `useAppStore()` БЕЗ селектора підписує компонент на ВЕСЬ стор: будь-який
//    запис (тост, `isOnline`, лічильник непрочитаних) перемальовує екран, хоч
//    той цих полів і не читає. Так було в 43 місцях. Правильно — `useAppSlice`
//    (поверхнева рівність по названих ключах) або селектор на одне поле.
// 2. Ефект чи колбек, що залежить від ОБʼЄКТА `user`, а не від його `id`,
//    перезапускається, коли теплий старт кладе в стор кешований профіль, а за
//    мить — свіжий. Заміряно: чотири запити теплого старту йшли двічі. Виняток
//    можливий, але лише з маркером `user-dep-ok:` і змістовною причиною поруч —
//    файловий дозвіл амністував би кожну майбутню залежність у тому файлі.

const ROOT = join(__dirname, '..', '..', 'src')

function walk(dir: string): string[] {
  return readdirSync(dir).flatMap((name) => {
    const p = join(dir, name)
    if (statSync(p).isDirectory()) return walk(p)
    return /\.(ts|tsx)$/.test(name) ? [p] : []
  })
}

const FILES = walk(ROOT).map((p) => ({ p: p.slice(ROOT.length + 1), src: readFileSync(p, 'utf8') }))

function stripComments(s: string): string {
  return s.replace(/\/\*[\s\S]*?\*\//g, '').replace(/(^|[^:'"`])\/\/.*$/gm, '$1')
}

describe('підписка на стор', () => {
  it('жодного useAppStore() без селектора', () => {
    const bad = FILES.filter(({ src }) => /\buseAppStore\(\s*\)/.test(stripComments(src))).map((f) => f.p)
    expect(bad).toEqual([])
  })

  it('антивакуум: зрізи справді вживаються', () => {
    const n = FILES.reduce((acc, { src }) => acc + (src.match(/\buseAppSlice\(/g) ?? []).length, 0)
    expect(n).toBeGreaterThan(30)
  })
})

describe('залежності від особи, а не від обʼєкта профілю', () => {
  const DEPS = /^\s*\}\s*,\s*\[([^\]]*)\]\s*\)/

  it('жоден ефект чи колбек не залежить від `user` цілком без маркера', () => {
    const bad: string[] = []
    for (const { p, src } of FILES) {
      const lines = src.split('\n')
      lines.forEach((line, i) => {
        const m = DEPS.exec(line)
        if (!m) return
        const deps = m[1].split(',').map((d) => d.trim())
        if (!deps.includes('user')) return
        const marker = /user-dep-ok:\s*(.*)$/.exec(lines[i - 1] ?? '')
        if (marker && marker[1].trim().length >= 30) return
        bad.push(`${p}:${i + 1}  ${line.trim()}`)
      })
    }
    expect(bad).toEqual([])
  })

  it('антивакуум: масиви залежностей справді знаходяться', () => {
    const n = FILES.reduce((acc, { src }) =>
      acc + src.split('\n').filter((l) => DEPS.test(l)).length, 0)
    expect(n).toBeGreaterThan(50)
  })
})

import { describe, it, expect } from 'vitest'
import * as fs from 'node:fs'
import * as path from 'node:path'
import { editDecimal, editInt } from '@/lib/utils'

/**
 * Числове поле: санітайзер міняє введене, і без цього модуля курсор вилітав
 * у кінець (заміряно в браузері: відкинута літера посеред «1800» → курсор 4
 * замість 2). Тут — чиста половина: значення І позиція.
 */
describe('editDecimal — значення і каретка', () => {
  it('відкинутий символ посеред числа лишає каретку на місці', () => {
    // «18|00» + «a» → DOM «18a|00», курсор 3
    expect(editDecimal('18a00', 3)).toEqual({ value: '1800', caret: 2 })
  })

  it('кома стає крапкою, каретка — одразу після неї', () => {
    expect(editDecimal('18,00', 3)).toEqual({ value: '18.00', caret: 3 })
  })

  it('звичайна цифра — без змін (контроль)', () => {
    expect(editDecimal('18500', 3)).toEqual({ value: '18500', caret: 3 })
  })

  it('друга крапка посеред числа ВІДКИДАЄТЬСЯ, а не переносить кому', () => {
    // «1|8.5» + «.» → «1.|8.5». Наївний санітайзер дає «1.85» — сума
    // мовчки зменшується вдесятеро.
    expect(editDecimal('1.8.5', 2)).toEqual({ value: '18.5', caret: 1 })
    expect(editDecimal('18.5,', 5)).toEqual({ value: '18.5', caret: 4 })
  })

  it('перша крапка надрукованим символом приймається', () => {
    expect(editDecimal('18.', 3)).toEqual({ value: '18.', caret: 3 })
  })

  it('вставка з розрядними роздільниками лишається вставкою', () => {
    // Останній символ вставки — цифра, тож правило «другого роздільника» її
    // не чіпає: «1,200,000» → 1200000, а не 1.2.
    expect(editDecimal('1,200,000', 9)).toEqual({ value: '1200000', caret: 7 })
  })

  it('каретка не виходить за довжину значення', () => {
    const r = editDecimal('abc', 3)
    expect(r.value).toBe('')
    expect(r.caret).toBe(0)
  })
})

describe('editInt — значення і каретка', () => {
  it('відкинутий символ посеред числа лишає каретку на місці', () => {
    expect(editInt('1x5', 2)).toEqual({ value: '15', caret: 1 })
  })
  it('цифри — без змін (контроль)', () => {
    expect(editInt('125', 2)).toEqual({ value: '125', caret: 2 })
  })
})

describe('джерело: числові поля йдуть через caretEdit', () => {
  it('жоден onChange не кладе санітайзер напряму в стан', () => {
    // Прямий виклик над e.target.value і є той шлях, що викидав курсор у кінець.
    const root = path.resolve(__dirname, '../../src')
    const bad: string[] = []
    const walk = (d: string) => {
      for (const f of fs.readdirSync(d, { withFileTypes: true })) {
        const p = path.join(d, f.name)
        if (f.isDirectory()) walk(p)
        else if (/\.tsx?$/.test(f.name)) {
          const s = fs.readFileSync(p, 'utf8')
          if (/sanitize(Decimal|Int)\(\s*e\.target\.value/.test(s)) bad.push(path.relative(root, p))
        }
      }
    }
    walk(root)
    expect(bad, 'санітайзер прямо в onChange — курсор вилітає в кінець').toEqual([])
    // антивакуум: мігровані місця справді існують
    const form = fs.readFileSync(path.join(root, 'screens/PropertyFormScreen.tsx'), 'utf8')
    expect(form).toMatch(/caretEdit\(e, editDecimal\)/)
  })
})

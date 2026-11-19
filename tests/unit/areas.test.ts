import { describe, it, expect } from 'vitest'
import { basisArea, hasArea, areaPair, listedArea, calcRentUtils } from '../../src/lib/utils'

/**
 * ДВІ ПЛОЩІ ОДНОГО ОБʼЄКТА: корисна і розрахункова.
 *
 * Модель — рівно два числа на обʼєкт плюс база (`area_basis`, за замовчуванням
 * «розрахункова»). Кімнати на поверсі — це окремі обʼєкти зі спільним текстовим
 * `floor`, ієрархії немає. Тож «кілька площ» тут — це завжди ця пара, і правила
 * мусять бути ОДНАКОВІ на кожній поверхні, яка її читає:
 *
 *  1. 0 — це «не вказано». Форма так і читає (`parseFloat(x) || undefined`), тож
 *     превʼю там рахувало від другої площі, а збережена картка — від нуля.
 *  2. Грошова площа (`basisArea`) і площа, яку ПОКАЗУЄМО, не можуть розходитись:
 *     обʼєкт, у якого задана лише розрахункова (а база за замовчуванням саме
 *     вона), раніше не показував площі взагалі, хоча ціна рахувалась із неї.
 *  3. Невідома площа не вдає із себе відому: «45/45» стверджує розрахункову 45,
 *     якої ніхто не вводив.
 */
describe('hasArea: нуль — це «не вказано»', () => {
  it('додатне скінченне число — задано', () => {
    expect(hasArea(45)).toBe(true)
    expect(hasArea(0.5)).toBe(true)
  })
  it('0, відʼємне, NaN, null, undefined — не задано', () => {
    for (const v of [0, -1, NaN, Infinity, null, undefined]) expect(hasArea(v as number | null | undefined)).toBe(false)
  })
})

describe('basisArea: нуль не вважається площею', () => {
  it('база «корисна», корисна = 0, розрахункова є → береться розрахункова', () => {
    // Було 0: `chosen ?? fallback` бачить 0 як «задано». Картка рахувала $0, а
    // форма (`|| undefined`) показувала суму від розрахункової.
    expect(basisArea(0, 120, 'useful')).toBe(120)
    expect(basisArea(120, 0, 'total')).toBe(120)
  })
  it('жодної додатної площі — нуль', () => {
    expect(basisArea(0, 0, 'total')).toBe(0)
    expect(basisArea(null, 0, 'useful')).toBe(0)
  })
  it('обрана площа є — береться вона, а не запасна', () => {
    // Антивакуум до перших двох: «завжди бери другу» теж не падало б на них.
    expect(basisArea(50, 100, 'useful')).toBe(50)
    expect(basisArea(50, 100, 'total')).toBe(100)
  })
  it('ставка за м² від нульової корисної йде по розрахунковій — як у превʼю форми', () => {
    const { rent } = calcRentUtils(0, 120, 18, 'per_m2', 0, 'useful', false)
    expect(rent).toBe(2160)
  })
})

describe('areaPair: що показуємо в рядку обʼєкта', () => {
  it('обидві → «корисна/розрахункова»', () => {
    expect(areaPair(45, 52)).toBe('45/52')
  })
  it('лише корисна → без вигаданої розрахункової', () => {
    // Було «45/45» (`p.area_total ?? p.area_useful`): рядок стверджував
    // розрахункову площу, якої ніхто не вводив.
    expect(areaPair(45, null)).toBe('45')
    expect(areaPair(45, 0)).toBe('45')
  })
  it('лише розрахункова → видно, що корисної немає', () => {
    // Було: нічого. Обʼєкт із базою за замовчуванням «розрахункова» і єдиною
    // заповненою площею не показував площі, хоча ціну рахували з неї.
    expect(areaPair(null, 52)).toBe('—/52')
    expect(areaPair(0, 52)).toBe('—/52')
  })
  it('жодної → нічого, а не «0»', () => {
    expect(areaPair(null, null)).toBeNull()
    expect(areaPair(0, 0)).toBeNull()
    expect(areaPair(undefined, undefined)).toBeNull()
  })
})

describe('listedArea: розмір для сортування «за площею»', () => {
  it('корисна, а за її відсутності — розрахункова; не 0', () => {
    // Було `area_useful ?? 0`: обʼєкт лише з розрахунковою площею падав на дно
    // списку «за площею» нарівні з обʼєктами без жодної площі.
    expect(listedArea(45, 52)).toBe(45)
    expect(listedArea(null, 52)).toBe(52)
    expect(listedArea(0, 52)).toBe(52)
    expect(listedArea(null, null)).toBe(0)
  })
})

import { describe, it, expect } from 'vitest'
import { readFileSync, readdirSync, statSync } from 'node:fs'
import { join, relative } from 'node:path'

/**
 * ФОТО І ПЕРЕХОДИ: два правила, які рантайм у CI бачить лише частково.
 *
 * 1. Знімок із МЕРЕЖІ малюється через `components/ui/Photo.tsx`, а не сирим
 *    `<img>`. Сирий тег на LTE зʼявлявся ривком (анімація при монтуванні
 *    добігала на порожньому елементі), а на 404 лишав гліф битої картинки з
 *    alt-текстом поверх героя. `photo-loading.spec.ts` міряє це на трьох
 *    поверхнях; цей гард тримає, щоб НОВА поверхня не обійшла компонент.
 *    Виняток — локальне превʼю з `blob:`-URL (черга завантаження): там немає
 *    ні мережі, ні 404.
 * 2. Жодного `transition: all`. Він анімує ВСЕ, що зміниться, включно з
 *    `backdrop-filter` при перемиканні `.glass-s`→`.glass-d` — тобто
 *    перемальовує скло посеред руху саме там, де на iOS це найдорожче.
 *    Перелік властивостей ще й документує, що саме має рухатись.
 */

const SRC = join(__dirname, '..', '..', 'src')

function walk(dir: string, out: string[] = []): string[] {
  for (const e of readdirSync(dir)) {
    const p = join(dir, e)
    if (statSync(p).isDirectory()) walk(p, out)
    else if (p.endsWith('.tsx') || p.endsWith('.ts') || p.endsWith('.css')) out.push(p)
  }
  return out
}

const FILES = walk(SRC).map((p) => ({ rel: relative(SRC, p), text: readFileSync(p, 'utf8') }))

/** Лише код, без коментарів — інакше пояснення «чому не `<img>`» ловилось би як порушення. */
function code(text: string): string {
  return text.replace(/\/\*[\s\S]*?\*\//g, '').replace(/\{\/\*[\s\S]*?\*\/\}/g, '').replace(/^\s*\/\/.*$/gm, '')
}

const RAW_IMG_OK = new Map<string, string>([
  ['components/ui/Photo.tsx', 'сам компонент'],
  ['screens/PhotoUploadScreen.tsx', 'превʼю черги з blob:-URL — локальний файл, мережі немає'],
])

describe('фото з мережі — лише через <Photo>', () => {
  it('сирого <img> немає поза компонентом і локальним превʼю', () => {
    const bad = FILES.filter((f) => f.rel.endsWith('.tsx') && !RAW_IMG_OK.has(f.rel) && /<img[\s>]/.test(code(f.text)))
      .map((f) => f.rel)
    expect(bad, 'сирий <img>: зʼявиться ривком і покаже биту картинку на 404').toEqual([])
  })

  it('антивакуум: компонент справді вживається на всіх поверхнях фото', () => {
    const users = FILES.filter((f) => /<Photo[\s>]/.test(code(f.text))).map((f) => f.rel).sort()
    expect(users).toEqual(expect.arrayContaining([
      'app/v/page.tsx',
      'components/ui/FilePreviewModal.tsx',
      'screens/PhotoGalleryScreen.tsx',
      'screens/PropertyDetailScreen.tsx',
    ]))
  })

  it('компонент ловить обидва кінці: і завантаження, і відмову, і кеш', () => {
    const p = code(FILES.find((f) => f.rel === 'components/ui/Photo.tsx')!.text)
    expect(p).toMatch(/onLoad=/)
    expect(p).toMatch(/onError=/)
    // Знімок із кешу завантажується ДО обробника — без цієї перевірки він
    // лишався б невидимим назавжди.
    expect(p).toMatch(/\.complete/)
    expect(p).toMatch(/naturalWidth/)
  })
})

describe('переходи перелічують властивості', () => {
  it('жодного transition: all — ні в CSS, ні інлайном', () => {
    const bad: string[] = []
    for (const f of FILES) {
      const c = code(f.text)
      if (/transition\s*:\s*all\b/.test(c) || /transition:\s*['"`]all\b/.test(c)) bad.push(f.rel)
    }
    expect(bad).toEqual([])
  })
})

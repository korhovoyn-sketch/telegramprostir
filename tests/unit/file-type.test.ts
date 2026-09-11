import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { resolveDocMime, isDoc, isImage, DOC_MIME } from '@/lib/fileType'

/**
 * КЛАС, ЯКИЙ ЦЕ ТРИМАЄ: два шари одного застосунку по-різному відповідали на
 * питання «це документ?». Зона перетягування питала РОЗШИРЕННЯ (і мала про це
 * коментар), завантажувач — точний `file.type`. Заміряно: із пʼяти реальних
 * комбінацій, які віддають ОС, строгу перевірку проходила рівно ОДНА.
 *
 * Тому тут ДВІ половини, і жодна не зайва: таблиця реальних випадків (що саме
 * приймається) і антивакуум (що НЕ приймається). Без другої «приймай усе»
 * пройшло б першу.
 */

// name/type — рівно те, що віддає браузер у цих середовищах.
const REAL_WORLD = [
  { name: 'Договір оренди.docx', type: '',                         want: DOC_MIME.docx, why: 'Windows без Office' },
  { name: 'Договір.docx',        type: 'application/octet-stream',  want: DOC_MIME.docx, why: 'Android, файлові менеджери' },
  { name: 'Акт.doc',             type: 'application/x-msword',      want: DOC_MIME.doc,  why: 'застарілий mime-db' },
  { name: 'Скан.pdf',            type: '',                          want: DOC_MIME.pdf,  why: 'Windows без Acrobat' },
  { name: 'Договір.pdf',         type: 'application/pdf',           want: DOC_MIME.pdf,  why: 'ідеальний випадок' },
  { name: 'ДОГОВІР.DOCX',        type: '',                          want: DOC_MIME.docx, why: 'верхній регістр розширення' },
]

describe('тип документа розвʼязується, а не читається', () => {
  for (const c of REAL_WORLD) {
    it(`${c.why}: «${c.name}» type="${c.type}"`, () => {
      expect(resolveDocMime(c)).toBe(c.want)
    })
  }

  // АНТИВАКУУМ. Без нього «повертай docx завжди» пройшло б усе вище.
  const ALIEN = [
    { name: 'таблиця.xlsx', type: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet' },
    { name: 'фото.jpg',     type: 'image/jpeg' },
    { name: 'архів.zip',    type: 'application/zip' },
    { name: 'скрипт.js',    type: 'text/javascript' },
    { name: 'без-розширення', type: '' },
    // .docx у назві ПАПКИ, а не розширення — розбір мусить брати останній сегмент
    { name: 'docx.zip',     type: 'application/zip' },
  ]
  for (const c of ALIEN) {
    it(`не документ: «${c.name}»`, () => {
      expect(resolveDocMime(c)).toBeNull()
      expect(isDoc(c)).toBe(false)
    })
  }

  it('розвʼязане значення — завжди одне з трьох, які приймає edge-функція', () => {
    // Zod-енум у supabase/functions/validate-upload/index.ts. Якщо клієнт
    // почне слати щось поза ним, аплоуд відмовлятиме 400 БЕЗ пояснення.
    const edge = readFileSync('supabase/functions/validate-upload/index.ts', 'utf8')
    for (const mime of Object.values(DOC_MIME)) {
      expect(edge, `edge не приймає ${mime}`).toContain(mime)
    }
  })
})

describe('зображення: тип АБО розширення', () => {
  it('heic з айфона без типу — приймається', () => {
    expect(isImage({ name: 'IMG_0042.HEIC', type: '' })).toBe(true)
  })
  it('звичайний jpeg', () => {
    expect(isImage({ name: 'a.jpg', type: 'image/jpeg' })).toBe(true)
  })
  it('антивакуум: pdf зображенням не є', () => {
    expect(isImage({ name: 'a.pdf', type: 'application/pdf' })).toBe(false)
  })
})

/**
 * ДЖЕРЕЛЬНА половина: сам предикат мусить лишатись ОДИН. Поведінкові тести
 * вище цього не бачать — вони міряють модуль, а дефект був у тому, що ПОРУЧ
 * жила друга, розбіжна копія.
 */
describe('предикат не переписують локально', () => {
  const SITES = [
    'src/components/ui/FilesList.tsx',
    'src/screens/PropertyDetailScreen.tsx',
    'src/screens/PhotoUploadScreen.tsx',
    'src/hooks/usePropertyFiles.ts',
  ]
  for (const f of SITES) {
    it(f, () => {
      const src = readFileSync(f, 'utf8')
      expect(src, 'тип документа має приходити з lib/fileType').not.toMatch(
        /application\/vnd\.openxmlformats-officedocument\.wordprocessingml|application\/msword/,
      )
      expect(src, 'розширення зображень — теж у lib/fileType').not.toMatch(
        /jpe\?g\|png\|webp/,
      )
    })
  }
})

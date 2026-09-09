/**
 * ТИП ДОКУМЕНТА — ОДНЕ ДЖЕРЕЛО ПРАВДИ, І ВОНО НЕ МОЖЕ БУТИ `file.type`.
 *
 * Браузер віддає `type` з реєстру ОС, а не з вмісту файлу, тож для того самого
 * `.docx` він законно буває порожнім (Windows без встановленого Office),
 * `application/octet-stream` (Android і частина файлових менеджерів) або
 * застарілим (`application/x-msword`). Заміряно на пʼятьох реальних
 * комбінаціях: строгу перевірку `ALLOWED_MIME.has(file.type)` проходила рівно
 * ОДНА — PDF з ідеальним типом.
 *
 * Наслідок був не «іноді незручно», а «договір завантажити НЕМОЖЛИВО», причому
 * застосунок сам собі суперечив: зона перетягування приймала файл по
 * РОЗШИРЕННЮ (і навіть має про це коментар), а завантажувач одразу відхиляв
 * його по ТИПУ. Користувач бачив підсвічену зону прийому і зараз же «формат не
 * підтримується», без жодного натяку, що робити.
 *
 * Тому тип РОЗВʼЯЗУЄТЬСЯ: якщо ОС дала одне з трьох очікуваних значень — беремо
 * його, інакше виводимо з розширення. Контракт сервера при цьому НЕ
 * послаблюється: `validate-upload` і далі приймає лише свій Zod-енум із трьох
 * значень, просто тепер туди доїжджає осмислене значення замість порожнього.
 * Вмісту не нюхає ні клієнт, ні сервер — ні до, ні після цієї зміни, тож
 * поверхня довіри та сама.
 */

export const DOC_MIME = {
  pdf:  'application/pdf',
  doc:  'application/msword',
  docx: 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
} as const

export type DocMime = (typeof DOC_MIME)[keyof typeof DOC_MIME]

const BY_MIME = new Set<string>(Object.values(DOC_MIME))

/**
 * Тип, з яким файл піде на сервер, або `null` — якщо це не документ.
 * `null` означає «відхилити», і це ЄДИНЕ місце, де таке рішення ухвалюється.
 */
export function resolveDocMime(file: { name: string; type: string }): DocMime | null {
  if (BY_MIME.has(file.type)) return file.type as DocMime
  const ext = file.name.split('.').pop()?.toLowerCase()
  if (ext === 'pdf')  return DOC_MIME.pdf
  if (ext === 'doc')  return DOC_MIME.doc
  if (ext === 'docx') return DOC_MIME.docx
  // Застарілі й альтернативні написання того самого — лише коли розширення
  // нічого не сказало (файл без розширення з коректним типом).
  if (file.type === 'application/x-msword') return DOC_MIME.doc
  return null
}

/** Чи візьме застосунок цей файл як документ. Той самий предикат, що вище. */
export const isDoc = (file: { name: string; type: string }): boolean =>
  resolveDocMime(file) !== null

/**
 * ЗОБРАЖЕННЯ — та сама хвороба, слабший симптом. `heic` з айфона регулярно
 * приходить без типу; тут перевірка й так була по «тип АБО розширення», тож
 * модуль лише зводить дві копії предиката в одну.
 */
const IMG_EXT = /\.(jpe?g|png|webp|heic|heif)$/i

export const isImage = (file: { name: string; type: string }): boolean =>
  file.type.startsWith('image/') || IMG_EXT.test(file.name)

/**
 * МЕЖІ РОЗМІРУ — ДВІ, І ЦЕ НЕ ДУБЛЮВАННЯ.
 *
 * `MAX_PHOTO_MB` перевіряється ПІСЛЯ стиснення: конвеєр навмисно
 * перекодовує знімок (1920px JPEG) саме для того, щоб 12-мегабайтний кадр із
 * камери став кількасот кілобайтами і пройшов — про це прямо сказано в
 * `photoUpload.ts`. `MAX_INPUT_MB` — це інше: захист памʼяті webview від файлу,
 * якому стиснення вже не допоможе.
 *
 * Доти екран завантаження фільтрував ВХІД по 10 МБ, тобто відкидав кадр ДО
 * стиснення — і сам себе позбавляв сенсу: звичайне фото з сучасного телефона
 * (8-15 МБ JPEG) не завантажувалось узагалі, хоч конвеєр був спроєктований
 * саме під нього.
 */
export const MAX_PHOTO_MB = 10
export const MAX_INPUT_MB = 50

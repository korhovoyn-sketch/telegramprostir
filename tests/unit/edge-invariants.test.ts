import { describe, it, expect } from 'vitest'
import { readFileSync, existsSync } from 'node:fs'
import { resolve } from 'node:path'

/**
 * ІНВАРІАНТИ EDGE-ФУНКЦІЙ — ДЖЕРЕЛЬНО, І ЦЕ ВИМУШЕНО.
 *
 * Edge-функції — найбільша непокрита поверхня репозиторію, і вона тримає всю
 * логіку ідентичності. Рантайм-тест звідси НЕДОСЯЖНИЙ: Deno в пісочниці немає,
 * а самі функції імпортують з `https://esm.sh/…`, тобто vitest їх навіть не
 * зарезолвить. Тому тут — перевірки ДЖЕРЕЛА, і кожна відповідає конкретній
 * знахідці, яку Audit playbook §1 називає рецидивною.
 *
 * ЧОГО ЦЕЙ ФАЙЛ НЕ ДАЄ: доказу, що функція працює. Він доводить лише, що
 * конкретні відомі граблі не повернулись. Справжня перевірка — деплой і виклик.
 */

const FN = (name: string) => resolve(process.cwd(), 'supabase/functions', name, 'index.ts')
const read = (name: string) => readFileSync(FN(name), 'utf8')

const FUNCTIONS = ['telegram-auth', 'validate-upload', 'telegram-bot', 'send-reminders']

describe('edge-функції на місці', () => {
  it.each(FUNCTIONS)('%s існує', (name) => {
    expect(existsSync(FN(name)), `${name}: функцію видалено`).toBe(true)
  })

  it.each(FUNCTIONS)('%s використовує Deno.serve, а не legacy serve()', (name) => {
    // `serve()` з deno.land/std@0.168.0 несумісний з Deno 2 і дає EarlyDrop.
    const src = read(name)
    expect(src).toMatch(/Deno\.serve\s*\(/)
    expect(src, 'legacy serve() з deno.land повертає EarlyDrop на Deno 2')
      .not.toMatch(/from\s+['"]https:\/\/deno\.land\/std@[^'"]*\/http\/server\.ts['"]/)
  })
})

describe('telegram-auth', () => {
  const src = read('telegram-auth')

  it('рейт-лімітер ЧИТАЄ error і відмовляє на ньому (fails closed)', () => {
    // supabase-js РЕЗОЛВИТЬ збій запиту як `{data: null, error}` і не кидає, тож
    // catch його не ловить. Поки `error` не читався, будь-яка невдача давала
    // `!data` → upsert → пропуск, тобто fail-OPEN попри коментар у шапці.
    const fn = src.slice(src.indexOf('async function checkRateLimit'))
      .slice(0, src.slice(src.indexOf('async function checkRateLimit')).indexOf('\n}\n') + 3)
    expect(fn, 'checkRateLimit не знайдено — тест застарів').toContain('rate_limits')
    expect(fn, '`error` не деструктуризується: збій запиту стане пропуском')
      .toMatch(/const\s*\{\s*data\s*,\s*error\s*\}\s*=\s*await/)
    expect(fn, 'немає гілки, що відмовляє на помилці запиту')
      .toMatch(/if\s*\(\s*error\s*\)\s*return\s+false/)
  })

  it('tg_id іде в запит числом, а не рядком', () => {
    // BIGINT-колонка відкидає порівняння з рядком — колись це ламало вхід.
    expect(src).toMatch(/parseInt\(\s*tgUser\.id\s*,\s*10\s*\)/)
  })

  it('HMAC звіряється константним часом', () => {
    // Приймаємо ОБИДВІ форми: іменований хелпер і інлайновий XOR-акумулятор
    // (`mismatch |= a[i] ^ b[i]`) — тут використана саме друга. Перша версія
    // цього гарда шукала лише хелпер і падала на КОРЕКТНОМУ коді; це той самий
    // клас помилки, що й вакуумний гард, тільки дзеркальний — хибне падіння
    // замість хибного проходження.
    const constantTime = /timingSafeEqual|constantTimeEqual/.test(src)
      || /\|=\s*\w+\[\s*i\s*\]\s*\^\s*\w+\[\s*i\s*\]/.test(src)
    expect(constantTime, 'немає константного порівняння підпису').toBe(true)
    // І головне — жодного наївного порівняння хешів рядками: воно завершується
    // на першому розбіжному символі, тобто витікає позиція розбіжності.
    expect(src, 'наївне порівняння хешів — таймінговий сайд-канал')
      .not.toMatch(/(expectedHash|calculatedHash)\s*[!=]==\s*(hash|actualHash)/)
  })

  it('відповідь клієнту не несе внутрішніх деталей', () => {
    // Правило 1 Security rules: жодних стек-трейсів і `detail` у тілі 500.
    expect(src, 'stack потрапляє у відповідь клієнту').not.toMatch(/JSON\.stringify\([^)]*\.stack/)
    expect(src, 'error.message ллється у відповідь напряму')
      .not.toMatch(/error:\s*(err|e|error)\.message/)
  })
})

describe('validate-upload', () => {
  const src = read('validate-upload')

  it('порівнює ВЛАСНИКА обʼєкта, а не лише RLS-видимість', () => {
    // Функція ходить під service-role, тобто RLS її не обмежує: без явного
    // порівняння будь-хто отримав би підписаний URL на чужий обʼєкт (IDOR).
    expect(src).toMatch(/me\.id\s*!==\s*prop\.owner_id/)
  })

  it('відмова закрита на обох гілках перевірки членства', () => {
    expect(src).toMatch(/403/)
    expect(src, 'помилка запиту членства мусить вести до відмови, а не до дозволу')
      .toMatch(/memberErr|countErr/)
  })

  it('шлях у сховищі не містить керованих користувачем сегментів', () => {
    // `{propertyId}/{timestamp}_{rand}.{ext}` — жодного імені файлу від клієнта.
    expect(src).toMatch(/\$\{propertyId\}\/\$\{Date\.now\(\)\}_\$\{rand\}/)
  })
})

describe('крон-функції закриті від сторонніх', () => {
  it('send-reminders вимагає service-key константним порівнянням', () => {
    const src = read('send-reminders')
    expect(src).toMatch(/timingSafeEqual/)
    expect(src).toMatch(/401/)
  })

  it('telegram-bot перевіряє secret_token із заголовка', () => {
    const src = read('telegram-bot')
    expect(src).toMatch(/x-telegram-bot-api-secret-token|X-Telegram-Bot-Api-Secret-Token/i)
    expect(src).toMatch(/401/)
  })
})

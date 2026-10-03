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
    // Саме РІШЕННЯ переїхало в `_shared/rateLimit.ts` і тепер перевіряється
    // ВИКОНАННЯМ (`edge-rate-limit.test.ts`), а не регексом по джерелу. Тут
    // лишається єдине, чого той тест бачити не може: що функція справді
    // передає прапорець збою, а не викидає його.
    expect(fn, 'рішення не делеговане тестованому модулю')
      .toMatch(/rateDecision\(\s*data\s*,\s*!!error/)
    expect(fn, 'відмова лімітера не веде до `return false`')
      .toMatch(/if\s*\(\s*!decision\.allow\s*\)\s*return\s+false/)
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

describe('діагностика конфігурації лишається досяжною і бачить ХИБНЕ значення', () => {
  /**
   * ЧОМУ ЦЕ ГАРД, А НЕ ДРІБНИЦЯ.
   *
   * `ALLOWED_ORIGIN` — єдина змінна, яка гейтить сама себе: `corsHeadersFor`
   * пінить на неї `Access-Control-Allow-Origin`, тож поки вона ХИБНА, браузер
   * блокує будь-яку відповідь цієї функції — включно з тією, що мала б про це
   * сказати. Користувач тоді бачить «Edge Function недоступна» і йде
   * перевіряти деплой, хоч зламана одна змінна.
   *
   * Тому GET-гілка свідомо відбиває Origin запиту (тіло — самі булеві
   * прапорці, без токенів і даних користувача) і віддає `origin_match`.
   * Суворе пінування лишається на POST, де у відповіді є сесія.
   */
  it('GET ВЖИВАЄ diagCors у самій відповіді, а не лише оголошує', () => {
    const src = read('telegram-auth')
    expect(src, "diagCors мусить відбивати Origin запиту, інакше сенс утрачено")
      .toMatch(/'Access-Control-Allow-Origin':\s*reqOrigin\s*\?\?\s*'\*'/)
    // ВЖИТОК, а не наявність. Перша редакція вимагала лише підрядка
    // `diagCors` — і повний відкат фікса (`...diagCors` → `...cors` у
    // відповіді) лишав гард зеленим: оголошення на місці, ефекту нуль.
    expect(src, 'відповідь діагностики повернулась на спільний cors — фікс відкочено, оголошення лишилось декорацією')
      .toMatch(/\{ headers: \{ \.\.\.diagCors, 'Content-Type': 'application\/json' \} \}/)
  })

  /**
   * PREFLIGHT — те, на чому провалилась перша редакція, і жоден гард цього
   * не бачив. `diagCors` жив у гілці GET, а клієнт шле не-safelisted
   * заголовки, тож браузер спершу робить OPTIONS — і ТОЙ пінився на хибний
   * ALLOWED_ORIGIN. До GET не доходило НІКОЛИ: досяжність, заради якої все
   * писалось, не працювала в браузері взагалі.
   */
  it('preflight діагностики відбиває Origin, і лише для GET', () => {
    const src = read('telegram-auth')
    expect(src, 'OPTIONS знову віддає спільний cors — preflight ріже діагностику до того, як вона відповість')
      .toMatch(/Access-Control-Request-Method/)
    expect(src, 'preflight мусить відбивати Origin саме для GET')
      .toMatch(/wants === 'GET'[\s\S]{0,160}?'Access-Control-Allow-Origin':\s*reqOrigin\s*\?\?\s*'\*'/)
    // АНТИВАКУУМ: відбиття на preflight POST означало б, що вхід виконується
    // з будь-якого origin (відповідь прочитати не дадуть, побічні ефекти
    // стануться).
    expect(src, 'preflight відбиває Origin беззастережно — POST став виконуваним з будь-якого origin')
      .toMatch(/:\s*cors\s*\n\s*return new Response\('ok'/)
  })

  it('клієнт не провокує preflight на діагностиці', () => {
    const src = readFileSync(resolve(process.cwd(), 'src/screens/WelcomeScreen.tsx'), 'utf8')
    const call = src.match(/fetch\(`\$\{supabaseUrl\}\/functions\/v1\/telegram-auth`[\s\S]{0,300}?\)\n/)
    expect(call, 'діагностичний виклик не знайдено — гард осліп').toBeTruthy()
    // `Authorization`/`apikey` не входять у CORS-safelist: будь-який із них
    // повертає preflight, тобто весь клас дефекту. Функція задеплоєна з
    // --no-verify-jwt, тож вони їй і не потрібні.
    expect(call![0], 'повернувся не-safelisted заголовок — GET знову йде через preflight')
      .not.toMatch(/apikey|Authorization/)
  })

  it('перевіряється ЗБІГ, а не лише наявність', () => {
    const src = read('telegram-auth')
    expect(src, 'зник originMatch — `!!allowedOrigin` каже лише «щось задано», і хибне значення читається як здорове')
      .toMatch(/const originMatch\s*=\s*reqOrigin\s*\?\s*allowedOrigin === reqOrigin\s*:\s*null/)
    expect(src, 'ok мусить падати на розбіжності, інакше клієнт покаже «Конфігурація OK» при мертвому вході')
      .toMatch(/originMatch !== false/)
    // Друга половина: обчислити мало — значення мусить ДОЇХАТИ до клієнта.
    // Без цього видалення рядка в тілі лишало гард зеленим, а клієнтська
    // гілка не спрацьовувала б ніколи.
    expect(src, 'origin_match не потрапляє в тіло — клієнт не може про нього дізнатись')
      .toMatch(/origin_match:\s*originMatch/)
  })

  /**
   * АНТИВАКУУМ: суворе пінування МУСИТЬ лишитись там, де відповідь несе сесію.
   * Без цієї половини «діагностику видно звідусіль» легко перетворюється на
   * «видно звідусіль усе».
   */
  it('POST-шлях суворого пінування НЕ послаблено', () => {
    const shared = readFileSync(resolve(process.cwd(), 'supabase/functions/_shared/cors.ts'), 'utf8')
    expect(shared, 'corsHeadersFor перестав пінити на ALLOWED_ORIGIN — це вже не CORS-обмеження')
      .toMatch(/allowedOrigin \?\? reqOrigin \?\? '\*'/)
    const src = read('telegram-auth')
    expect(src, 'diagCors протік за межі GET-гілки')
      .toMatch(/if \(req\.method === 'GET'\) \{\s*\n\s*const diagCors/)
    // Головне: ЖОДНА відповідь поза preflight і GET не сміє сама виставляти
    // ACAO. Попередня версія дивилась лише на оголошення, тож дописаний у
    // POST `'Access-Control-Allow-Origin': reqOrigin ?? '*'` — тобто видача
    // сесії будь-якому origin — проходив зеленим.
    const acao = [...src.matchAll(/'Access-Control-Allow-Origin':/g)].length
    expect(acao, 'зʼявився зайвий Access-Control-Allow-Origin — перевір, чи не віддає сесію будь-якому origin')
      .toBe(2)
  })

  /**
   * Третє входження класу «перевірено наявність, не правильність»: хибний
   * токен бота провалює HMAC, тобто вхід мертвий, а `!!` показував здоровий
   * прапорець.
   */
  it('валідність токена бота ПЕРЕВІРЯЄТЬСЯ, а не декларується', () => {
    const src = read('telegram-auth')
    expect(src, 'зникла проба getMe — `!!` знову каже лише «задано»')
      .toMatch(/api\.telegram\.org\/bot\$\{Deno\.env\.get\('TELEGRAM_BOT_TOKEN'\)\}\/getMe/)
    // ПІДКЛЮЧЕНИЙ таймаут, а не наявний AbortController поруч: зняття
    // `{ signal: ctl.signal }` лишало контролер у вікні пошуку, гард зеленів,
    // а health-ендпоінт висів на мертвій мережі безкінечно.
    expect(src, 'signal не переданий у fetch — таймаут декоративний, ендпоінт може висіти')
      .toMatch(/getMe`,\s*\n\s*\{ signal: ctl\.signal \},/)
    expect(src, 'хибний токен мусить валити ok, інакше проба нічого не міняє')
      .toMatch(/botTokenValid !== false/)
    expect(src, 'невідомий результат (мережа) НЕ сміє читатись як «зламано»')
      .toMatch(/let botTokenValid: boolean \| null = null/)
    // `r.ok` звело б «токен недійсний» і «Telegram зараз відмовляє» в одне
    // `false`, а ціна помилки несиметрична: оператор іде ротувати РОБОЧИЙ
    // токен за хибним діагнозом.
    expect(src, 'відмова Telegram (429/5xx) читається як «токен хибний» — діагноз штовхає ротувати робочий токен')
      .toMatch(/r\.status === 401 \|\| r\.status === 404/)
  })

  /**
   * Воркфлоу секретів — ЄДИНИЙ шлях задати CRON_SECRET, і він же пушить
   * ALLOWED_ORIGIN. Поки домен був `required`, полагодити сповіщення означало
   * перевбити прод-origin, а одруківка там кладе вхід УСІМ.
   */
  it('воркфлоу секретів не змушує перевбивати origin заради іншого секрета', () => {
    const wf = readFileSync(resolve(process.cwd(), '.github/workflows/set-supabase-secrets.yml'), 'utf8')
    expect(wf, 'vercel_domain знову required — фікс сповіщень знову тягне ризик локауту')
      .toMatch(/vercel_domain:[\s\S]{0,200}?required:\s*false/)
    // РІВНО одне присвоєння, і саме під гілкою наявності. Попередня версія
    // перевіряла лише, що безумовного пушу немає поруч зі `secrets set` —
    // тож дописане вище `extra+=("ALLOWED_ORIGIN=…")` проходило, і порожній
    // ввід пушив ПОРОЖНЄ значення. Це гірше за вихідний стан: `?? null` не
    // ловить порожній рядок, ACAO стає '', і фолбек «відбити Origin» не
    // вмикається — вхід мертвий і нечитабельний.
    const assigns = [...wf.matchAll(/ALLOWED_ORIGIN=/g)].length
    expect(assigns, 'ALLOWED_ORIGIN присвоюється не один раз — перевір, чи порожній ввід не затирає робоче значення')
      .toBe(1)
    expect(wf, 'немає гілки, що пушить ALLOWED_ORIGIN лише за наявності вводу')
      .toMatch(/if \[ -n "\$ORIGIN_INPUT" \];\s*then\s*\n\s*extra\+=\("ALLOWED_ORIGIN=\$ORIGIN_INPUT"\)/)
    // Ввід у тілі `run` = підстановка ТЕКСТОМ, тобто виконання команд у
    // кроці з секретами. Має йти через env:.
    const inputUses = wf.split('\n').filter((l) => l.includes('${{ inputs.'))
    expect(inputUses.length, 'ввід не використовується взагалі — гард осліп').toBeGreaterThan(0)
    for (const line of inputUses) {
      expect(line, `ввід підставляється в скрипт ТЕКСТОМ — $(...) у полі виконається в кроці з секретами: ${line.trim()}`)
        .toMatch(/^\s+[A-Z_]+:\s*\$\{\{\s*inputs\.[a-z_]+\s*\}\}\s*$/)
    }
    // Префіксної перевірки не досить: кінцева скісна — гарантований локаут
    // (ACAO «…/» ніколи не дорівнює origin), і саме вона проходила.
    expect(wf, 'валідація не перевіряє ФОРМУ origin — кінцева скісна кладе вхід усім')
      .toMatch(/grep -Eq '\^https:\/\//)
  })
})

describe('крон-функції закриті від сторонніх', () => {
  it('send-reminders вимагає секрет константним порівнянням', () => {
    const src = read('send-reminders')
    expect(src).toMatch(/timingSafeEqual/)
    expect(src).toMatch(/401/)
  })

  /**
   * FAIL-CLOSED для ОБОХ секретів планувальника.
   *
   * Функція приймає або власний `CRON_SECRET`, або службовий ключ. Порожнє
   * значення кандидатом ставати НЕ сміє: `Bearer ` + '' збіглося б із порожнім
   * `Authorization`, тобто відсутність налаштування відкривала б функцію,
   * яка розсилає нагадування й читає `tg_id` усіх власників. Це той самий
   * клас, що вже описаний для rate-limiter'а (fails-closed, не fails-open).
   *
   * Перевіряється саме наявність перевірки довжини ПЕРЕД порівнянням — гард
   * джерельний, бо Deno в пісочниці немає (див. шапку файлу).
   */
  it('порожній секрет не стає кандидатом — обидві гілки fail-closed', () => {
    const src = read('send-reminders')
    for (const name of ['CRON_SECRET', 'SERVICE_KEY']) {
      const re = new RegExp(`${name}\\.length > 0 && timingSafeEqual`)
      expect(re.test(src),
        `${name} порівнюється без перевірки на порожнечу — незаданий секрет відкриває функцію`)
        .toBe(true)
    }
  })

  it('telegram-bot перевіряє secret_token із заголовка', () => {
    const src = read('telegram-bot')
    expect(src).toMatch(/x-telegram-bot-api-secret-token|X-Telegram-Bot-Api-Secret-Token/i)
    expect(src).toMatch(/401/)
  })
})

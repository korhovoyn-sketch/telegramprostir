/**
 * Збирає ОДИН самодостатній файл `prostir-marketing.html`.
 *
 *   node marketing/bundle.mjs
 *
 * Навіщо, якщо є index.html. Той працює лише разом зі своєю текою: шрифти,
 * кадри й відео лежать поруч. Переслати таке одним файлом не можна, а саме
 * цього від презентації й чекають. Тут усе вшите в data-URI.
 *
 * Кадри продукту ПЕРЕКОДОВУЮТЬСЯ в JPEG і зменшуються вдвічі: у деку вони
 * показуються завширшки 300–600 px, тобто 1125 px — це вага без жодного
 * виграшу в різкості. Повнорозмірні PNG лишаються в `shots/` для креативів.
 *
 * Перекодування йде через canvas у браузері, а не через ffmpeg: той у
 * пісочниці зібраний без PNG-декодера взагалі.
 */
import { chromium } from '@playwright/test'
import { readFile, writeFile, readdir } from 'node:fs/promises'
import { fileURLToPath } from 'node:url'
import { dirname, resolve } from 'node:path'

const HERE = dirname(fileURLToPath(import.meta.url))
const EXEC = '/opt/pw-browsers/chromium-1194/chrome-linux/chrome'
const OUT = resolve(HERE, '..', 'prostir-marketing.html')

const b64 = async (rel) => (await readFile(resolve(HERE, rel))).toString('base64')

let html = await readFile(resolve(HERE, 'index.html'), 'utf8')

// 1 · Шрифти. Без них кирилиця падає на DejaVu і дек виглядає іншим
//     продуктом. Обидві гарнітури ЗМІННІ (одна вага 100–900 на файл),
//     тож вшивається по одному файлу на родину, а не по чотири.
for (const f of ['Inter']) {
  const before = html
  html = html.replace(`url('fonts/${f}.ttf')`,
    `url('data:font/ttf;base64,${await b64(`fonts/${f}.ttf`)}')`)
  if (html === before) throw new Error(`шрифт ${f} не знайдено в index.html`)
}

// 2 · Кадри продукту — через canvas у браузері.
//
// ЧОМУ НЕ САМИЙ РЕГЕКС ПО ШЛЯХАХ. Плитки, слайди й Stories будуються в
// рантаймі, і шлях там — шаблон `shots/${shot}.png`, тобто справжнього імені
// файлу в джерелі НЕМАЄ. Перша версія збирача через це вшила 7 кадрів із 15,
// а решта лишилась зовнішніми посиланнями — у самодостатньому файлі це дірки.
// Тому список беремо з ТЕКИ і лишаємо ті імена, що згадані у файлі хоч як.
const files = (await readdir(resolve(HERE, 'shots'))).filter((f) => f.endsWith('.png'))
const shots = files.map((f) => f.replace(/\.png$/, ''))
  .filter((n) => html.includes(`shots/${n}.png`) || html.includes(`'${n}'`))
const SHOT = {}
const browser = await chromium.launch({ executablePath: EXEC })
const page = await (await browser.newContext()).newPage()
await page.goto('file://' + resolve(HERE, 'index.html'))

for (const name of shots) {
  // ЧЕРЕЗ data-URI, а не шлях: зображення з file:// ЗАБРУДНЮЄ полотно
  // (SecurityError на toDataURL), навіть коли сторінка з того ж файлу.
  const srcUri = `data:image/png;base64,${await b64(`shots/${name}.png`)}`
  const uri = await page.evaluate(async (src) => {
    const img = new Image()
    img.src = src
    await img.decode()
    const c = document.createElement('canvas')
    c.width = Math.round(img.naturalWidth / 2)
    c.height = Math.round(img.naturalHeight / 2)
    c.getContext('2d').drawImage(img, 0, 0, c.width, c.height)
    return c.toDataURL('image/jpeg', 0.82)
  }, srcUri)
  if (!uri.startsWith('data:image/jpeg')) throw new Error(`кадр ${name} не перекодувався`)
  html = html.split(`shots/${name}.png`).join(uri)
  SHOT[name] = uri
  process.stdout.write(`  ${name}\r`)
}
await browser.close()

// Рантаймові шляхи: віддаємо генераторам плиток мапу замість файлів.
// Заміна ОБОВʼЯЗКОВА — мовчазний промах тут і давав «самодостатній»
// файл із дірками; нижній антивакуум це ловить, але помилка тут точніша.
{
  const before = html
  html = html.replace('src="shots/${name}.png"', 'src="${SHOT[name]}"')
  if (html === before) throw new Error('шаблон кадру в index.html змінився — заміна не спрацювала')
}
html = html.replace('<script>', `<script>window.SHOT = ${JSON.stringify(SHOT)};</script>\n<script>`, 1)

// 3 · Сторіборд — той самий клас, що й кадри: шлях будується в рантаймі
// (`creatives/board-${i + 1}.jpg`), тож літеральної заміни тут не існує.
const BOARD = []
for (let i = 1; i <= 5; i++) {
  BOARD.push(`data:image/jpeg;base64,${await b64(`creatives/board-${i}.jpg`)}`)
}
{
  const before = html
  html = html.replace('src="creatives/board-${i}.jpg"', 'src="${BOARD_IMG[i - 1]}"')
  html = html.replace('poster="creatives/board-1.jpg"', `poster="${BOARD[0]}"`)
  if (html === before) throw new Error('шаблон сторіборду в index.html змінився — заміна не спрацювала')
}
html = html.replace('<script>', `<script>window.BOARD_IMG = ${JSON.stringify(BOARD)};</script>\n<script>`, 1)
// У дек іде ЛЕГКА копія: майстер на 6 Мбіт/с у base64 важить 8 МБ, а
// показується він тут у колонці 320 px. Публікувати треба майстер.
{
  const before = html
  html = html.replace('creatives/reel-15s.webm',
    `data:video/webm;base64,${await b64('creatives/reel-15s-preview.webm')}`)
  if (html === before) throw new Error('посилання на відео в index.html змінилось')
}

/* Антивакуум. Перша редакція цієї перевірки була ПОРОЖНЬОЮ: регекс чекав
   лапку ОДРАЗУ за `src`, тобто `src="shots/…"` не матчив ніколи, і збирач
   спокійно віддав файл із вісьмома дірками. Тепер питання простіше й
   відповідь на нього однозначна: підрядка `shots/` у виході бути не може
   взагалі — усі шляхи або замінені на data-URI, або йдуть через SHOT. */
for (const frag of ['shots/', 'fonts/', 'creatives/']) {
  if (html.includes(frag)) throw new Error(`у виході лишився зовнішній шлях: ${frag}`)
}

await writeFile(OUT, html)
const mb = (Buffer.byteLength(html) / 1048576).toFixed(1)
console.log(`\n✓ ${OUT}  (${mb} МБ, кадрів вшито: ${shots.length})`)

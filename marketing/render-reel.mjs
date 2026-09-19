/**
 * Покадровий рендер рілза у відео.
 *
 *   node marketing/render-reel.mjs
 *
 * ЧОМУ ПОКАДРОВО, А НЕ ЗАПИСОМ ЕКРАНА. Запис у реальному часі віддає те, що
 * встиг намалювати браузер під навантаженням — тобто відео з пропущеними
 * кадрами, і дефект неможливо відрізнити від дефекту анімації. Тут кожен кадр
 * рендериться окремо: `currentTime` виставляється на КОЖНІЙ анімації сторінки,
 * тож результат детермінований і не залежить від швидкості машини.
 *
 * ФОРМАТ. ffmpeg у пісочниці зібраний урізаним: із відеокодеків є лише VP8,
 * із демукс-входів — image2pipe, а PNG-ДЕКОДЕРА немає взагалі. Звідси JPEG
 * на вході і WebM на виході; це не вибір смаку, а межа середовища.
 */
import { chromium } from '@playwright/test'
import { spawn } from 'node:child_process'
import { fileURLToPath } from 'node:url'
import { dirname, resolve } from 'node:path'

const HERE = dirname(fileURLToPath(import.meta.url))
const PAGE = 'file://' + resolve(HERE, 'reel.html')
const OUT = resolve(HERE, 'creatives', 'reel-15s.webm')
const FFMPEG = '/opt/pw-browsers/ffmpeg-1011/ffmpeg-linux'
const EXEC = '/opt/pw-browsers/chromium-1194/chrome-linux/chrome'

const FPS = 30
const SECONDS = Number(process.env.SECS || 15)
const FRAMES = FPS * SECONDS

const browser = await chromium.launch({ executablePath: EXEC })
const ctx = await browser.newContext({
  viewport: { width: 1080, height: 1920 },
  deviceScaleFactor: 1,
  reducedMotion: 'no-preference',
})
const page = await ctx.newPage()
await page.goto(PAGE)
await page.waitForFunction(() => document.fonts.status === 'loaded')
await page.waitForFunction(() =>
  [...document.images].every((i) => i.complete && i.naturalWidth > 0), null, { timeout: 30_000 })

const nAnims = await page.evaluate(() => document.getAnimations().length)
if (nAnims === 0) throw new Error('на сторінці нуль анімацій — рендер був би статичним кадром')

/* АНТИВАКУУМ. Перший прогін цього рендера віддав 15 секунд ЧОРНОТИ: ffmpeg
   відзвітував успіхом, файл важив 2,7 МБ, і дефект було видно лише оком.
   Причина — інлайновий `animation:` скидає animation-fill-mode, тож поза
   активною фазою застосовувався базовий opacity:0.
   Тому перед рендером перевіряємо ІНВАРІАНТ таймлайну: у кожен контрольний
   момент видно РІВНО ОДНУ сцену. Нуль — чорний кадр, більше однієї —
   накладення (так проявився другий дефект: `both` на анімації виходу
   заповнював назад і тримав сцену видимою до її такту). */
for (const sec of [0.8, 2.2, 4.8, 8.4, 10.2, 13.4]) {
  const seen = await page.evaluate((ms) => {
    for (const a of document.getAnimations()) { a.pause(); a.currentTime = ms }
    return [...document.querySelectorAll('.scene')]
      .filter((e) => +getComputedStyle(e).opacity > 0.5).length
  }, sec * 1000)
  if (seen !== 1) throw new Error(`на ${sec}s видно сцен: ${seen} (треба рівно 1)`)
}
console.log('✓ таймлайн: одна сцена в кадрі на всіх шести контрольних точках')
console.log(`анімацій на сторінці: ${nAnims}; кадрів: ${FRAMES} @ ${FPS}fps`)

const ff = spawn(FFMPEG, [
  // `-vcodec mjpeg` ОБОВʼЯЗКОВИЙ: image2pipe сам кодек не визначає, і без
  // нього потік читається як `Video: none` — ffmpeg падає аж на відкритті
  // виходу («Output file does not contain any stream»), тобто вказує не туди.
  '-y', '-f', 'image2pipe', '-vcodec', 'mjpeg', '-framerate', String(FPS), '-i', 'pipe:0',
  // Білд зібраний із --disable-everything: фільтра `format` у ньому немає,
  // тож ЖОДНОЇ конвертації пікформату просити не можна — ffmpeg не зможе
  // побудувати граф і падає ще на відкритті виходу. JPEG уже yuv420p.
  '-c:v', 'libvpx', '-b:v', '6M', '-an', '-f', 'webm', 'file:' + OUT,
], { stdio: ['pipe', 'ignore', 'pipe'] })
let ffErr = ''
ff.stderr.on('data', (d) => { ffErr += d.toString() })

const done = new Promise((res, rej) => {
  ff.on('close', (code) => (code === 0 ? res() : rej(new Error('ffmpeg ' + code + '\n' + ffErr.slice(-1200)))))
})

for (let f = 0; f < FRAMES; f++) {
  const t = (f / FPS) * 1000
  await page.evaluate((ms) => {
    for (const a of document.getAnimations()) { a.pause(); a.currentTime = ms }
  }, t)
  const buf = await page.screenshot({ type: 'jpeg', quality: 92 })
  if (!ff.stdin.write(buf)) await new Promise((r) => ff.stdin.once('drain', r))
  if (f % 60 === 0) process.stdout.write(`  ${f}/${FRAMES}\r`)
}
ff.stdin.end()
await done
await browser.close()
console.log(`\n✓ ${OUT}`)

'use client'

// Client-side photo compression before upload. Phone cameras produce 4–12 MB
// HEIC/JPEG; resized to ≤1920px JPEG they drop to ~200–600 KB with no visible
// loss at card/gallery sizes — that's the user's mobile traffic on every
// upload AND every later view.
//
// Fail-open by design: any decode/canvas failure (old WebView, HEIC without
// createImageBitmap support, jsdom in tests) returns the ORIGINAL file, so
// the upload path never breaks — worst case we upload uncompressed, which is
// exactly today's behaviour. «Оригінал» при цьому — БЕЗ EXIF/XMP для JPEG
// (`withoutMetadata`): ці гілки інакше везли б GPS у публічний бакет.
const MAX_DIM = 1920
const JPEG_QUALITY = 0.82
// Keep the original unless compression actually wins ≥10% — re-encoding an
// already-optimised small JPEG can come out larger.
const MIN_GAIN = 0.9

// Сегменти JPEG, що несуть ОПИС знімка, а не сам знімок: APP1 — EXIF (GPS-
// координати, модель камери, час) і XMP; APP13 — Photoshop/IPTC (теж буває з
// локацією). Фото обʼєкта лягає в ПУБЛІЧНИЙ бакет і роздається на `/v`, тобто
// GPS із нього — це адреса, яку власник НЕ публікував (часто власне житло).
// APP2 (ICC-профіль) свідомо лишається: без нього пливуть кольори.
const META_MARKERS = new Set([0xe1, 0xed])

/**
 * Прибирає EXIF/XMP/IPTC з JPEG, не перекодовуючи пікселі. Перекодування на
 * canvas метадані й так знімає, але є ДВІ гілки, де вгору йде ОРИГІНАЛ: виграш
 * у розмірі < 10% і fail-open (декодер недоступний). Саме вони несли GPS.
 * `null` — це не JPEG або структура не розпізнана (тоді нічого не чіпаємо).
 */
export function stripJpegMetadata(buf: Uint8Array<ArrayBuffer>): Uint8Array<ArrayBuffer> | null {
  if (buf.length < 4 || buf[0] !== 0xff || buf[1] !== 0xd8) return null
  const out: Uint8Array<ArrayBuffer>[] = [buf.subarray(0, 2)]
  let i = 2
  let removed = false
  while (i < buf.length) {
    if (buf[i] !== 0xff) return null
    let m = i + 1
    while (m < buf.length && buf[m] === 0xff) m++ // байти-заповнювачі
    if (m >= buf.length) return null
    const marker = buf[m]
    // Від SOS далі — стиснені дані; заголовків там уже немає.
    if (marker === 0xda || marker === 0xd9) {
      out.push(buf.subarray(i))
      break
    }
    // Самостійні маркери (TEM, RSTn) довжини не мають.
    if (marker === 0x01 || (marker >= 0xd0 && marker <= 0xd7)) {
      out.push(buf.subarray(i, m + 1))
      i = m + 1
      continue
    }
    if (m + 2 >= buf.length) return null
    const len = (buf[m + 1] << 8) | buf[m + 2]
    const end = m + 1 + len
    if (len < 2 || end > buf.length) return null
    if (META_MARKERS.has(marker)) removed = true
    else out.push(buf.subarray(i, end))
    i = end
  }
  if (!removed) return buf
  const total = out.reduce((n, p) => n + p.length, 0)
  const res = new Uint8Array(total)
  let o = 0
  for (const p of out) { res.set(p, o); o += p.length }
  return res
}

async function withoutMetadata(file: File): Promise<File> {
  if (file.type !== 'image/jpeg' && file.type !== 'image/jpg' && !/\.jpe?g$/i.test(file.name)) return file
  try {
    const buf = new Uint8Array(await file.arrayBuffer())
    const clean = stripJpegMetadata(buf)
    if (!clean || clean === buf) return file
    return new File([clean], file.name, { type: 'image/jpeg' })
  } catch {
    return file
  }
}

export async function compressImage(file: File): Promise<File> {
  try {
    if (!file.type.startsWith('image/') || file.type === 'image/gif') return file

    const bitmap = await createImageBitmap(file)
    const scale = Math.min(1, MAX_DIM / Math.max(bitmap.width, bitmap.height))
    const w = Math.max(1, Math.round(bitmap.width * scale))
    const h = Math.max(1, Math.round(bitmap.height * scale))

    const canvas = document.createElement('canvas')
    canvas.width = w
    canvas.height = h
    const ctx = canvas.getContext('2d')
    if (!ctx) return withoutMetadata(file)
    ctx.drawImage(bitmap, 0, 0, w, h)
    bitmap.close?.()

    const blob = await new Promise<Blob | null>((resolve) =>
      canvas.toBlob(resolve, 'image/jpeg', JPEG_QUALITY),
    )
    if (!blob || blob.size >= file.size * MIN_GAIN) return withoutMetadata(file)

    const name = file.name.replace(/\.\w+$/, '') + '.jpg'
    return new File([blob], name, { type: 'image/jpeg' })
  } catch {
    return withoutMetadata(file)
  }
}

import { describe, it, expect } from 'vitest'
import { compressImage, stripJpegMetadata } from '@/lib/image'

// jsdom has no createImageBitmap/canvas — exactly the fail-open path the
// helper must take on old WebViews: return the ORIGINAL file untouched.
describe('compressImage (fail-open)', () => {
  it('passes non-images through untouched', async () => {
    const f = new File(['%PDF-1.4'], 'doc.pdf', { type: 'application/pdf' })
    expect(await compressImage(f)).toBe(f)
  })

  it('passes gifs through untouched (animation would be lost)', async () => {
    const f = new File(['GIF89a'], 'anim.gif', { type: 'image/gif' })
    expect(await compressImage(f)).toBe(f)
  })

  it('returns the original when decoding is unavailable (jsdom = old WebView)', async () => {
    const f = new File([new Uint8Array(64)], 'photo.heic', { type: 'image/heic' })
    const out = await compressImage(f)
    expect(out).toBe(f)
    expect(out.size).toBe(f.size)
  })
})

// Мінімальний JPEG із тими сегментами, які трапляються в знімку з телефона.
// Пікселі тут не важать — `stripJpegMetadata` працює на рівні маркерів.
function seg(marker: number, payload: number[]): number[] {
  const len = payload.length + 2
  return [0xff, marker, len >> 8, len & 0xff, ...payload]
}
const ascii = (s: string) => [...s].map((c) => c.charCodeAt(0))
const GPS = ascii('Exif\0\0GPSLatitude=50.4501;GPSLongitude=30.5234')
function jpeg(withMeta: boolean): Uint8Array<ArrayBuffer> {
  return new Uint8Array([
    0xff, 0xd8,
    ...seg(0xe0, ascii('JFIF\0')),
    ...(withMeta ? seg(0xe1, GPS) : []),
    ...seg(0xe2, ascii('ICC_PROFILE\0')),
    ...(withMeta ? seg(0xed, ascii('Photoshop 3.0\0IPTC')) : []),
    ...seg(0xdb, [0, 1, 2, 3]),
    ...seg(0xda, [0, 1, 0]),
    0x12, 0xff, 0x00, 0x34, // «стиснені дані»: FF00 — не маркер
    0xff, 0xd9,
  ])
}
const has = (buf: Uint8Array, needle: string) =>
  new TextDecoder('latin1').decode(buf).includes(needle)

describe('stripJpegMetadata — GPS не їде в публічний бакет', () => {
  it('прибирає APP1 (EXIF/XMP) і APP13 (IPTC), лишаючи решту байт у байт', () => {
    const out = stripJpegMetadata(jpeg(true))!
    expect(out).not.toBeNull()
    expect(has(out, 'GPSLatitude')).toBe(false)
    expect(has(out, 'Photoshop')).toBe(false)
    // Антивакуум: «прибрати все» теж прибрало б GPS. Лишитись мусить
    // рівно файл без метаданих — включно з ICC-профілем і даними після SOS.
    expect(Array.from(out)).toEqual(Array.from(jpeg(false)))
  })

  it('JPEG без метаданих повертається тим самим буфером', () => {
    const clean = jpeg(false)
    expect(stripJpegMetadata(clean)).toBe(clean)
  })

  it('не-JPEG і обірвана структура — null, нічого не чіпаємо', () => {
    expect(stripJpegMetadata(new Uint8Array([0x89, 0x50, 0x4e, 0x47]))).toBeNull()
    const broken = jpeg(true).subarray(0, 12)
    expect(stripJpegMetadata(broken)).toBeNull()
  })

  it('fail-open гілка compressImage віддає JPEG БЕЗ GPS (декодера в jsdom немає)', async () => {
    const f = new File([jpeg(true)], 'IMG_0001.JPG', { type: 'image/jpeg' })
    const out = await compressImage(f)
    const bytes = new Uint8Array(await out.arrayBuffer())
    expect(has(bytes, 'GPSLatitude')).toBe(false)
    expect(out.type).toBe('image/jpeg')
    expect(out.name).toBe('IMG_0001.JPG')
  })
})

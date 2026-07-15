import { describe, it, expect } from 'vitest'
import { compressImage } from '@/lib/image'

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

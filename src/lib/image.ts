'use client'

// Client-side photo compression before upload. Phone cameras produce 4–12 MB
// HEIC/JPEG; resized to ≤1920px JPEG they drop to ~200–600 KB with no visible
// loss at card/gallery sizes — that's the user's mobile traffic on every
// upload AND every later view.
//
// Fail-open by design: any decode/canvas failure (old WebView, HEIC without
// createImageBitmap support, jsdom in tests) returns the ORIGINAL file, so
// the upload path never breaks — worst case we upload uncompressed, which is
// exactly today's behaviour.
const MAX_DIM = 1920
const JPEG_QUALITY = 0.82
// Keep the original unless compression actually wins ≥10% — re-encoding an
// already-optimised small JPEG can come out larger.
const MIN_GAIN = 0.9

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
    if (!ctx) return file
    ctx.drawImage(bitmap, 0, 0, w, h)
    bitmap.close?.()

    const blob = await new Promise<Blob | null>((resolve) =>
      canvas.toBlob(resolve, 'image/jpeg', JPEG_QUALITY),
    )
    if (!blob || blob.size >= file.size * MIN_GAIN) return file

    const name = file.name.replace(/\.\w+$/, '') + '.jpg'
    return new File([blob], name, { type: 'image/jpeg' })
  } catch {
    return file
  }
}

import { supabase } from '@/lib/supabase'
import { compressImage } from '@/lib/image'

const MAX_MB = 10
const ALLOWED = /\.(jpe?g|png|webp|heic|heif)$/i

/**
 * Single source for the property-photo pipeline: validate → compress →
 * size-check → `{propertyId}/{ts}_{rand}.{ext}` path → storage upload →
 * property_photos insert → orphan-cleanup on DB failure.
 *
 * Both `useProperties.uploadPhoto` (single add) and `PhotoUploadScreen` (batch,
 * passes sortOrder) route through here. They previously reimplemented this
 * separately and had already drifted — a `_{queueIdx}_` segment in the path on
 * one side but not the other, and `sort_order` set on one insert but not the
 * other — so a future change to storage layout would only land in one place.
 *
 * The first path segment MUST stay `{propertyId}` — the storage RLS policy
 * checks `SPLIT_PART(name,'/',1)` for ownership. Uniqueness comes from
 * `Date.now()` + a random suffix (sequential awaited uploads never collide).
 */
export async function uploadPropertyPhoto(propertyId: string, rawFile: File, sortOrder?: number): Promise<string> {
  // Lenient accept: a correctly-typed image with an odd filename (common for
  // HEIC straight off iOS) still uploads.
  if (!ALLOWED.test(rawFile.name) && !rawFile.type.startsWith('image/')) {
    throw new Error('Дозволені лише зображення (JPG, PNG, WEBP, HEIC)')
  }
  // Resize/re-encode BEFORE the size check: a 12 MB camera shot becomes a few
  // hundred KB and passes; compressImage fails open, so the original comes back
  // on any decode failure.
  const file = await compressImage(rawFile)
  if (file.size > MAX_MB * 1024 * 1024) {
    throw new Error(`Файл занадто великий (макс. ${MAX_MB}МБ)`)
  }

  const rawExt = file.name.split('.').pop() ?? ''
  const ext = /^[a-z0-9]{2,5}$/i.test(rawExt) ? rawExt.toLowerCase() : 'jpg'
  const path = `${propertyId}/${Date.now()}_${Math.random().toString(36).slice(2)}.${ext}`

  const { error: upErr } = await supabase.storage.from('photos').upload(path, file)
  if (upErr) throw upErr

  const { error: dbErr } = await supabase.from('property_photos').insert({
    property_id: propertyId,
    storage_path: path,
    ...(sortOrder != null ? { sort_order: sortOrder } : {}),
  })
  if (dbErr) {
    // Clean up the orphaned storage file so it doesn't accumulate.
    await supabase.storage.from('photos').remove([path]).catch(() => {})
    throw dbErr
  }

  return path
}

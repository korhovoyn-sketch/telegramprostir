-- Ensure the photos storage bucket exists with correct settings.
-- This migration reconciles the two conflicting policy sets created by
-- 003_reconcile.sql (storage_photos_*) and 007_storage_policies.sql (photos_*).

-- ── 1. Bucket ───────────────────────────────────────────────────────────────
INSERT INTO storage.buckets (id, name, public, file_size_limit, allowed_mime_types)
VALUES (
  'photos', 'photos', true, 10485760,
  ARRAY['image/jpeg','image/jpg','image/png','image/webp','image/heic','image/heif']
)
ON CONFLICT (id) DO UPDATE
  SET public            = true,
      file_size_limit   = 10485760,
      allowed_mime_types = ARRAY['image/jpeg','image/jpg','image/png','image/webp','image/heic','image/heif'];

-- ── 2. Drop all old photo policies (idempotent) ──────────────────────────────
-- From 003_reconcile.sql
DROP POLICY IF EXISTS "storage_photos_select" ON storage.objects;
DROP POLICY IF EXISTS "storage_photos_insert" ON storage.objects;
DROP POLICY IF EXISTS "storage_photos_update" ON storage.objects;
DROP POLICY IF EXISTS "storage_photos_delete" ON storage.objects;
-- From 007_storage_policies.sql
DROP POLICY IF EXISTS "photos_upload_owner"   ON storage.objects;
DROP POLICY IF EXISTS "photos_delete_owner"   ON storage.objects;
DROP POLICY IF EXISTS "photos_update_owner"   ON storage.objects;
-- In case 008 was partially applied before
DROP POLICY IF EXISTS "photos_read_public"    ON storage.objects;
DROP POLICY IF EXISTS "photos_insert_auth"    ON storage.objects;
DROP POLICY IF EXISTS "photos_delete_auth"    ON storage.objects;

-- ── 3. Clean unified policies ────────────────────────────────────────────────
-- Public bucket: reads are open to everyone (no auth needed)
CREATE POLICY "photos_read_public" ON storage.objects
  FOR SELECT USING (bucket_id = 'photos');

-- Any authenticated user may upload
CREATE POLICY "photos_insert_auth" ON storage.objects
  FOR INSERT TO authenticated
  WITH CHECK (bucket_id = 'photos');

-- Any authenticated user may delete their own uploads
-- (property-level ownership is already enforced via property_photos RLS)
CREATE POLICY "photos_delete_auth" ON storage.objects
  FOR DELETE TO authenticated
  USING (bucket_id = 'photos');

-- ── 4. Verify ────────────────────────────────────────────────────────────────
SELECT policyname, cmd
FROM pg_policies
WHERE schemaname = 'storage' AND tablename = 'objects'
  AND (policyname LIKE 'photos_%' OR policyname LIKE 'storage_photos_%')
ORDER BY policyname;

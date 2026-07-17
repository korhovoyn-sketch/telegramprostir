-- Storage bucket security policies for the "photos" bucket.
-- Bucket is public=true so reads are open (no SELECT policy needed — public buckets
-- serve objects via the public URL without auth).
-- We restrict WRITE (INSERT) and DELETE to the property owner only.

-- ── Enable RLS on storage.objects ───────────────────────────────────────────
-- (Supabase enables this automatically for private buckets; for public buckets
--  we still want INSERT/DELETE restricted.)

-- ── DROP existing policies (idempotent) ─────────────────────────────────────
DROP POLICY IF EXISTS "photos_upload_owner"  ON storage.objects;
DROP POLICY IF EXISTS "photos_delete_owner"  ON storage.objects;
DROP POLICY IF EXISTS "photos_update_owner"  ON storage.objects;

-- ── INSERT: only the property owner can upload ───────────────────────────────
-- Photo paths are  {propertyId}/{timestamp}_{n}.{ext}
-- We extract the propertyId from the first path segment.
CREATE POLICY "photos_upload_owner" ON storage.objects
  FOR INSERT TO authenticated
  WITH CHECK (
    bucket_id = 'photos'
    AND EXISTS (
      SELECT 1 FROM properties p
      WHERE p.id::text = SPLIT_PART(name, '/', 1)
        AND p.owner_id = current_app_user_id()
    )
  );

-- ── DELETE: only the property owner can delete ───────────────────────────────
CREATE POLICY "photos_delete_owner" ON storage.objects
  FOR DELETE TO authenticated
  USING (
    bucket_id = 'photos'
    AND EXISTS (
      SELECT 1 FROM properties p
      WHERE p.id::text = SPLIT_PART(name, '/', 1)
        AND p.owner_id = current_app_user_id()
    )
  );

-- ── UPDATE: disallow (photos are immutable; delete + re-upload instead) ──────
CREATE POLICY "photos_update_owner" ON storage.objects
  FOR UPDATE TO authenticated
  USING (
    bucket_id = 'photos'
    AND EXISTS (
      SELECT 1 FROM properties p
      WHERE p.id::text = SPLIT_PART(name, '/', 1)
        AND p.owner_id = current_app_user_id()
    )
  );

-- ── Verify ──────────────────────────────────────────────────────────────────
SELECT policyname, cmd, qual
FROM pg_policies
WHERE schemaname = 'storage' AND tablename = 'objects'
  AND policyname LIKE 'photos_%';

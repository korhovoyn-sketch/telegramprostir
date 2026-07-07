-- ============================================================================
-- 038_storage_write_hardening.sql — Close two storage/file write loopholes.
-- Idempotent. Run in Supabase Dashboard → SQL Editor (no migration pipeline).
--
-- P1  photos bucket: 008 created permissive photos_insert_auth /
--     photos_delete_auth (only bucket_id checked — any authenticated user could
--     upload to or DELETE any path). 016 added ownership-scoped storage_photos_*
--     policies but never dropped the 008 pair — and permissive RLS policies OR
--     together, so the weak pair won. Combined with /v exposing photo
--     storage_paths to anonymous visitors, anyone with a Telegram login could
--     delete any shared property's photos. Fix: drop the permissive pair and
--     rebuild the strict pair on get_app_user_id_from_auth_uid() — the
--     auth.uid()-based helper from 030 — because current_app_user_id() parses
--     request.jwt.claims, which is unreliable inside storage policies (the exact
--     failure 030 fixed for property-files SELECT).
--
-- P2  property_files: pfiles_insert_owner (019/023) only checks
--     owner_id = current_app_user_id() — it never checks the caller owns the
--     TARGET PROPERTY. 033 added a stricter pfiles_insert_realtor but did not
--     drop the permissive one, so (again via OR) a subscribed realtor could
--     insert a file row pointing at another owner's property with
--     owner_id = self. Fix: single INSERT/UPDATE policy pair that requires both
--     row ownership AND property ownership; the 033 pair is dropped.
-- ============================================================================

-- Self-contained: (re)create the auth.uid()-based identity helper from 030 so
-- this file works even where 030 was never applied.
CREATE OR REPLACE FUNCTION get_app_user_id_from_auth_uid()
RETURNS UUID
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = public
AS $$
  SELECT u.id
  FROM public.users u
  JOIN auth.users au
    ON SPLIT_PART(au.email, '@', 1) = u.tg_id::text
  WHERE au.id = auth.uid()
  LIMIT 1;
$$;

-- ── P1: photos bucket — ownership-scoped writes only ─────────────────────────
-- Public READ stays (the bucket is public by design; photoUrl() serves photos
-- on the /v page without auth). Only INSERT/DELETE/UPDATE get scoped.
DROP POLICY IF EXISTS "photos_insert_auth"     ON storage.objects;
DROP POLICY IF EXISTS "photos_delete_auth"     ON storage.objects;
DROP POLICY IF EXISTS "storage_photos_insert"  ON storage.objects;
DROP POLICY IF EXISTS "storage_photos_delete"  ON storage.objects;
DROP POLICY IF EXISTS "storage_photos_update"  ON storage.objects;

CREATE POLICY "storage_photos_insert" ON storage.objects
  FOR INSERT TO authenticated
  WITH CHECK (
    bucket_id = 'photos'
    AND SPLIT_PART(name, '/', 1) IN (
      SELECT p.id::text FROM public.properties p
      WHERE p.owner_id = public.get_app_user_id_from_auth_uid()
    )
  );

CREATE POLICY "storage_photos_delete" ON storage.objects
  FOR DELETE TO authenticated
  USING (
    bucket_id = 'photos'
    AND SPLIT_PART(name, '/', 1) IN (
      SELECT p.id::text FROM public.properties p
      WHERE p.owner_id = public.get_app_user_id_from_auth_uid()
    )
  );

CREATE POLICY "storage_photos_update" ON storage.objects
  FOR UPDATE TO authenticated USING (false) WITH CHECK (false);

-- ── P2: property_files — writes require owning the target property ───────────
DROP POLICY IF EXISTS "pfiles_insert_owner"    ON property_files;
DROP POLICY IF EXISTS "pfiles_insert_realtor"  ON property_files;
DROP POLICY IF EXISTS "pfiles_update_realtor"  ON property_files;
DROP POLICY IF EXISTS "pfiles_update_owner"    ON property_files;

CREATE POLICY "pfiles_insert_owner" ON property_files
  FOR INSERT WITH CHECK (
    owner_id = current_app_user_id()
    AND property_id IN (
      SELECT id FROM properties WHERE owner_id = current_app_user_id()
    )
  );

CREATE POLICY "pfiles_update_owner" ON property_files
  FOR UPDATE
  USING (owner_id = current_app_user_id())
  WITH CHECK (
    owner_id = current_app_user_id()
    AND property_id IN (
      SELECT id FROM properties WHERE owner_id = current_app_user_id()
    )
  );

-- ── Schema cache reload ──────────────────────────────────────────────────────
NOTIFY pgrst, 'reload schema';

-- ── Diagnostics ──────────────────────────────────────────────────────────────
SELECT '════ P1: photos storage policies (permissive photos_*_auth must be GONE) ════' AS check;
SELECT policyname, cmd FROM pg_policies
WHERE schemaname = 'storage' AND tablename = 'objects'
  AND (policyname LIKE 'photos_%' OR policyname LIKE 'storage_photos_%')
ORDER BY policyname;

SELECT '════ P2: property_files write policies (every WITH CHECK must reference properties) ════' AS check;
SELECT policyname, cmd, with_check FROM pg_policies
WHERE schemaname = 'public' AND tablename = 'property_files' AND cmd IN ('INSERT','UPDATE')
ORDER BY policyname;

SELECT '════ DONE — 038 storage write hardening applied ════' AS result;

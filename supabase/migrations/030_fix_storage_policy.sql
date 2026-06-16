-- ============================================================================
-- 030_fix_storage_policy.sql — Fix Storage SELECT policy for file viewing
-- Idempotent. Run in Supabase SQL Editor.
--
-- Problem: Migration 026 added a storage SELECT policy using current_app_user_id()
-- which parses request.jwt.claims. In the Supabase Storage policy context,
-- this GUC may not be set the same way as in PostgREST API calls, causing
-- createSignedUrl to fail with access denied and returning null to the client.
-- This manifests as "Не вдалося відкрити файл" for all files.
--
-- Fix: Use auth.uid() (guaranteed to work in storage policies) as the primary
-- identity lookup, mapping through auth.users.email → tg_id → public.users.id.
-- This is more reliable than parsing request.jwt.claims in storage context.
-- ============================================================================

-- Helper: maps auth.uid() → public.users.id via tg_id extracted from auth email.
-- Uses auth.uid() which is explicitly supported in Supabase storage policies.
-- Falls back gracefully to NULL if the user isn't found.
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

-- ── Rebuild storage SELECT policy ────────────────────────────────────────────
DROP POLICY IF EXISTS "pfiles_storage_select" ON storage.objects;

CREATE POLICY "pfiles_storage_select" ON storage.objects
  FOR SELECT TO authenticated
  USING (
    bucket_id = 'property-files'
    AND (
      -- Property owner: first path segment is the property UUID
      SPLIT_PART(name, '/', 1) IN (
        SELECT p.id::text FROM public.properties p
        WHERE p.owner_id = get_app_user_id_from_auth_uid()
      )
      OR
      -- Realtor subscribed to the property's database
      SPLIT_PART(name, '/', 1) IN (
        SELECT p.id::text FROM public.properties p
        WHERE p.db_id IN (
          SELECT public.get_realtor_db_ids(get_app_user_id_from_auth_uid())
        )
      )
    )
  );

-- ── Schema cache reload ───────────────────────────────────────────────────────
NOTIFY pgrst, 'reload schema';

-- ── Diagnostics ──────────────────────────────────────────────────────────────
SELECT '════ 030: pfiles_storage_select policy (must use get_app_user_id_from_auth_uid) ════' AS check;
SELECT policyname, cmd, roles, qual
FROM pg_policies
WHERE schemaname = 'storage' AND tablename = 'objects' AND policyname = 'pfiles_storage_select';

SELECT '════ DONE — 030 storage policy fix applied ════' AS result;

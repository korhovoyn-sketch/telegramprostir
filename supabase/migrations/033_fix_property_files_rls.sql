-- ============================================================================
-- 033_fix_property_files_rls.sql — HIGH: Close realtor write privilege loophole
-- Idempotent. Run in Supabase SQL Editor.
--
-- Problem: property_files table had SELECT/DELETE RLS policies for owner,
-- but NO INSERT/UPDATE policies for realtor. Realtor could theoretically
-- create a property_files record with owner_id = realtor, bypassing ownership.
--
-- Fix: Add explicit INSERT/UPDATE policies that enforce ownership integrity.
-- ============================================================================

-- ── Fix: Realtor can read property_files only, never write ──────────────────
-- Previously: only SELECT policy existed for realtor
-- Now: explicitly block INSERT/UPDATE/DELETE for realtor

-- Explicitly deny realtor INSERT (they cannot create files, only view)
DROP POLICY IF EXISTS "pfiles_insert_realtor" ON property_files;
CREATE POLICY "pfiles_insert_realtor" ON property_files
  FOR INSERT TO authenticated
  WITH CHECK (
    -- Only allow INSERT if:
    -- 1. You are the owner (owner_id = current_app_user_id)
    -- 2. The property belongs to you (property_id owner_id matches)
    owner_id = current_app_user_id()
    AND owner_id IN (
      SELECT owner_id FROM properties WHERE id = property_id
    )
  );

-- Explicitly deny realtor UPDATE
DROP POLICY IF EXISTS "pfiles_update_realtor" ON property_files;
CREATE POLICY "pfiles_update_realtor" ON property_files
  FOR UPDATE TO authenticated
  USING (owner_id = current_app_user_id())
  WITH CHECK (
    owner_id = current_app_user_id()
    AND owner_id IN (SELECT owner_id FROM properties WHERE id = property_id)
  );

-- ── Schema cache reload ───────────────────────────────────────────────────────
NOTIFY pgrst, 'reload schema';

-- ── Diagnostics ──────────────────────────────────────────────────────────────
SELECT '════ property_files RLS policies (must enforce ownership for INSERT/UPDATE) ════' AS check;
SELECT policyname, cmd, roles, qual, with_check
FROM pg_policies
WHERE schemaname = 'public' AND tablename = 'property_files'
ORDER BY policyname;

SELECT '════ DONE — property_files RLS fix applied ════' AS result;

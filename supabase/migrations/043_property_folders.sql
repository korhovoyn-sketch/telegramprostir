-- ============================================================================
-- 043_property_folders.sql — folders to group objects inside a database.
-- Idempotent. Run in Supabase Dashboard → SQL Editor (no migration pipeline).
--
-- A database (databases) → objects (properties) gains an optional middle level:
-- named folders (property_folders) that live inside ONE database. An object
-- belongs to ≤1 folder; deleting a folder UNGROUPS its objects (SET NULL),
-- never deletes them. Folders are an owner/editor organisation tool — distinct
-- from collections (realtor cross-database sharing).
--
-- IMPORTANT — order: properties.folder_id is added to the main properties SELECT
-- (PROPERTY_COLUMNS). The client is written to tolerate the column being absent
-- (retries the select without folder_id on a 42703), so the frontend is safe to
-- deploy before this migration — but apply it to unlock the feature.
-- ============================================================================

-- ── Folder table ─────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS property_folders (
  id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  db_id      UUID NOT NULL REFERENCES databases(id) ON DELETE CASCADE,
  owner_id   UUID NOT NULL REFERENCES users(id)     ON DELETE CASCADE,
  name       TEXT NOT NULL,
  sort_order INT  NOT NULL DEFAULT 0,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
ALTER TABLE property_folders ENABLE ROW LEVEL SECURITY;

CREATE INDEX IF NOT EXISTS idx_property_folders_db ON property_folders (db_id, sort_order);

-- ── RLS: owner + team editor, mirroring the properties policies ──────────────
-- New/updated rows MUST belong to the database owner (WITH CHECK), so an editor
-- can't reassign folders to themselves.
DROP POLICY IF EXISTS "folders_owner_all"  ON property_folders;
CREATE POLICY "folders_owner_all" ON property_folders
  FOR ALL
  USING     (db_id IN (SELECT get_owner_db_ids(current_app_user_id())))
  WITH CHECK (
    db_id IN (SELECT get_owner_db_ids(current_app_user_id()))
    AND owner_id = (SELECT d.owner_id FROM databases d WHERE d.id = db_id)
  );

DROP POLICY IF EXISTS "folders_editor_all" ON property_folders;
CREATE POLICY "folders_editor_all" ON property_folders
  FOR ALL
  USING     (db_id IN (SELECT get_editor_db_ids(current_app_user_id())))
  WITH CHECK (
    db_id IN (SELECT get_editor_db_ids(current_app_user_id()))
    AND owner_id = (SELECT d.owner_id FROM databases d WHERE d.id = db_id)
  );

-- ── Link objects to a folder ─────────────────────────────────────────────────
-- ON DELETE SET NULL: removing a folder ungroups its objects, keeps the objects.
ALTER TABLE properties
  ADD COLUMN IF NOT EXISTS folder_id UUID NULL REFERENCES property_folders(id) ON DELETE SET NULL;
CREATE INDEX IF NOT EXISTS idx_properties_folder ON properties (folder_id) WHERE folder_id IS NOT NULL;

-- ── Schema cache reload ──────────────────────────────────────────────────────
NOTIFY pgrst, 'reload schema';

-- ── Diagnostics ──────────────────────────────────────────────────────────────
SELECT '════ property_folders table + RLS ════' AS check;
SELECT relrowsecurity FROM pg_class WHERE relname = 'property_folders';
SELECT policyname FROM pg_policies WHERE tablename = 'property_folders' ORDER BY policyname;

SELECT '════ properties.folder_id exists ════' AS check;
SELECT column_name, is_nullable FROM information_schema.columns
WHERE table_name = 'properties' AND column_name = 'folder_id';

SELECT '════ DONE — 043 property folders applied ════' AS result;

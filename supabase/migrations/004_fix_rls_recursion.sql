-- Fix: infinite recursion in RLS policies between databases ↔ realtor_subscriptions
-- Root cause: db_realtor_select queries realtor_subscriptions (which has subs_owner_select
--   that queries databases, which triggers db_realtor_select again → cycle).
--
-- Solution: SECURITY DEFINER helper functions bypass RLS on each table,
--   breaking the recursion at the source.

-- ── Helper functions (SECURITY DEFINER = bypass RLS) ────────────────────────

CREATE OR REPLACE FUNCTION get_realtor_db_ids(p_uid UUID)
RETURNS SETOF UUID LANGUAGE sql STABLE SECURITY DEFINER AS $$
  SELECT db_id FROM realtor_subscriptions WHERE realtor_id = p_uid
$$;

CREATE OR REPLACE FUNCTION get_owner_db_ids(p_uid UUID)
RETURNS SETOF UUID LANGUAGE sql STABLE SECURITY DEFINER AS $$
  SELECT id FROM databases WHERE owner_id = p_uid
$$;

-- ── Drop and recreate the four policies that caused recursion ────────────────

DROP POLICY IF EXISTS "db_realtor_select"     ON databases;
DROP POLICY IF EXISTS "props_realtor_select"  ON properties;
DROP POLICY IF EXISTS "photos_realtor_select" ON property_photos;
DROP POLICY IF EXISTS "subs_owner_select"     ON realtor_subscriptions;

-- databases: realtor can SELECT databases they are subscribed to
CREATE POLICY "db_realtor_select" ON databases FOR SELECT
  USING (id IN (SELECT get_realtor_db_ids(current_app_user_id())));

-- properties: realtor can SELECT properties in subscribed databases
CREATE POLICY "props_realtor_select" ON properties FOR SELECT
  USING (db_id IN (SELECT get_realtor_db_ids(current_app_user_id())));

-- property_photos: realtor can SELECT photos of properties in subscribed databases
CREATE POLICY "photos_realtor_select" ON property_photos FOR SELECT
  USING (property_id IN (
    SELECT p.id FROM properties p
    WHERE p.db_id IN (SELECT get_realtor_db_ids(current_app_user_id()))
  ));

-- realtor_subscriptions: owner can SELECT subscriptions to their databases
CREATE POLICY "subs_owner_select" ON realtor_subscriptions FOR SELECT
  USING (db_id IN (SELECT get_owner_db_ids(current_app_user_id())));

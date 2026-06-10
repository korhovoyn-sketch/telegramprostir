-- 022_search_path_hardening.sql
-- Pin search_path = public on every SECURITY DEFINER helper. Migrations 012/013/016
-- already recreate these with search_path set, but a DB that only ran the early
-- chain (001-010) would still have unpinned versions vulnerable to search_path
-- manipulation. Idempotent: silently skips functions that don't exist.

DO $$
DECLARE
  fn TEXT;
BEGIN
  FOREACH fn IN ARRAY ARRAY[
    'current_app_user_id()',
    'update_updated_at()',
    'prevent_privilege_escalation()',
    'get_realtor_db_ids(UUID)',
    'get_owner_db_ids(UUID)',
    'get_owner_property_ids(UUID)',
    'get_realtor_property_ids(UUID)',
    'get_realtor_collection_ids(UUID)'
  ]
  LOOP
    BEGIN
      EXECUTE format('ALTER FUNCTION %s SET search_path = public', fn);
    EXCEPTION
      WHEN undefined_function THEN
        NULL; -- not created on this DB (older/partial chain) — nothing to pin
    END;
  END LOOP;
END $$;

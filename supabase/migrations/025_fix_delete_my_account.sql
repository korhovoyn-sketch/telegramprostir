-- ── 025_fix_delete_my_account.sql ────────────────────────────────────────────
-- Fixes a use-after-free bug: the previous version queried `tg_id` from
-- `public.users` AFTER the row was already deleted by the CASCADE, so the
-- subquery always returned NULL and the `auth.users` row was never cleaned up.
-- Now `v_tg_id` is captured before the DELETE.

CREATE OR REPLACE FUNCTION delete_my_account()
RETURNS void
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
  v_user_id  UUID;
  v_tg_id    BIGINT;
  v_auth_uid UUID;
BEGIN
  v_user_id := current_app_user_id();
  IF v_user_id IS NULL THEN
    RAISE EXCEPTION 'Not authenticated';
  END IF;

  -- Capture tg_id BEFORE the DELETE so auth.users lookup still works
  SELECT tg_id INTO v_tg_id FROM users WHERE id = v_user_id;

  -- Cascade in public.users removes all associated data via FK ON DELETE CASCADE
  DELETE FROM users WHERE id = v_user_id;

  -- Remove auth.users entry to prevent orphaned JWT sessions
  IF v_tg_id IS NOT NULL THEN
    SELECT id INTO v_auth_uid FROM auth.users
    WHERE email = v_tg_id::text || '@telegram.propspace.app';
    IF v_auth_uid IS NOT NULL THEN
      DELETE FROM auth.users WHERE id = v_auth_uid;
    END IF;
  END IF;
END;
$$;

REVOKE ALL ON FUNCTION delete_my_account() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION delete_my_account() TO authenticated;

NOTIFY pgrst, 'reload schema';

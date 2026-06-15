-- PropSpace 028 — Bug fixes for guest role (idempotent)
-- Apply in Supabase Dashboard → SQL Editor.
--
-- Fixes:
--   1. claim_guest_link: prevent owner from claiming their own link (self-demotion to guest)
--   2. get_due_guest_reminders: clamp due_day to last day of month (make_date crash)
--   3. get_due_guest_reminders: deduplicate rows when guest has both property+db-level links

-- ── Fix 1 + 2 + 3: replace claim_guest_link with owner-self-claim guard ─────
CREATE OR REPLACE FUNCTION claim_guest_link(p_token TEXT)
RETURNS JSONB LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE
  v_uid  UUID := current_app_user_id();
  v_link RECORD;
BEGIN
  IF v_uid IS NULL THEN
    RAISE EXCEPTION 'not authenticated';
  END IF;

  SELECT id, property_id, db_id, guest_user_id, status, owner_id
  INTO v_link
  FROM guest_links
  WHERE invite_token = p_token
  FOR UPDATE;

  IF NOT FOUND THEN
    RETURN jsonb_build_object('error', 'not_found');
  END IF;

  IF v_link.status = 'revoked' THEN
    RETURN jsonb_build_object('error', 'revoked');
  END IF;

  -- Owner must never claim their own invite: it would demote them to guest role,
  -- locking them out of all their databases with no client-side recovery path.
  IF v_uid = v_link.owner_id THEN
    RETURN jsonb_build_object('error', 'cannot_claim_own_link');
  END IF;

  -- Already claimed by this user → idempotent success
  IF v_link.status = 'active' AND v_link.guest_user_id = v_uid THEN
    RETURN jsonb_build_object(
      'property_id', v_link.property_id,
      'db_id',       v_link.db_id
    );
  END IF;

  -- Already claimed by someone else
  IF v_link.status = 'active' AND v_link.guest_user_id IS DISTINCT FROM v_uid THEN
    RETURN jsonb_build_object('error', 'already_claimed');
  END IF;

  -- Claim it
  UPDATE guest_links
  SET guest_user_id = v_uid,
      status        = 'active',
      claimed_at    = now()
  WHERE id = v_link.id;

  -- Ensure user has guest role (onboarding may have left them as owner default)
  UPDATE users SET role = 'guest' WHERE id = v_uid AND role = 'owner';

  RETURN jsonb_build_object(
    'property_id', v_link.property_id,
    'db_id',       v_link.db_id
  );
END;
$$;
REVOKE ALL ON FUNCTION claim_guest_link(TEXT) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION claim_guest_link(TEXT) TO authenticated;

-- ── Fix 2 + 3: replace get_due_guest_reminders ───────────────────────────────
-- Fixes: make_date crash for months shorter than due_day (e.g. April has no day 31).
-- Fixes: duplicate rows when a guest has both property-level and db-level links
--        for the same property — DISTINCT ON (guest, property) deduplicates.
CREATE OR REPLACE FUNCTION get_due_guest_reminders()
RETURNS TABLE(
  guest_id    UUID,
  tg_id       BIGINT,
  property_id UUID,
  property_name TEXT,
  due_day     INT,
  due_date    DATE
)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE v_today DATE := current_date;
BEGIN
  RETURN QUERY
  SELECT DISTINCT ON (u.id, rp.property_id)
    u.id,
    u.tg_id,
    rp.property_id,
    p.name,
    rp.due_day::INT,
    make_date(
      EXTRACT(YEAR  FROM (v_today + rp.notify_days_before * INTERVAL '1 day'))::INT,
      EXTRACT(MONTH FROM (v_today + rp.notify_days_before * INTERVAL '1 day'))::INT,
      -- Clamp due_day to the last day of the target month to avoid make_date errors
      -- (e.g. due_day=31 but April has only 30 days).
      LEAST(
        rp.due_day,
        EXTRACT(DAY FROM (
          DATE_TRUNC('month', (v_today + rp.notify_days_before * INTERVAL '1 day'))
          + INTERVAL '1 month'
          - INTERVAL '1 day'
        ))::INT
      )
    )
  FROM rent_payments rp
  JOIN properties p ON p.id = rp.property_id
  -- Match active guest links targeting this property directly or via its database
  JOIN guest_links gl ON (
    gl.property_id = rp.property_id
    OR gl.db_id = p.db_id
  ) AND gl.status = 'active'
  JOIN users u ON u.id = gl.guest_user_id
  WHERE rp.is_active = true
    AND p.status = 'occupied'
    AND EXTRACT(DAY FROM (v_today + rp.notify_days_before * INTERVAL '1 day'))::INT = rp.due_day
    -- Dedup: skip if guest already got a reminder this month
    AND NOT EXISTS (
      SELECT 1 FROM notifications n
      WHERE n.user_id = u.id
        AND n.type = 'rent_reminder'
        AND (n.data->>'property_id')::UUID = rp.property_id
        AND DATE_TRUNC('month', n.created_at) = DATE_TRUNC('month', v_today::TIMESTAMPTZ)
    )
  ORDER BY u.id, rp.property_id;
END;
$$;
REVOKE ALL ON FUNCTION get_due_guest_reminders() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION get_due_guest_reminders() TO service_role;

-- ── SCHEMA CACHE RELOAD ───────────────────────────────────────────────────────
NOTIFY pgrst, 'reload schema';

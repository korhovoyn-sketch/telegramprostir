-- ============================================================================
-- 037_db_share_fixes.sql — Fix the "share a database" flow end-to-end.
-- Idempotent. Run in Supabase SQL Editor (no migration pipeline exists — only
-- deploy-edge-function.yml runs on push, and it deploys telegram-auth only).
--
-- Self-contained: applying THIS file alone repairs database sharing even if
-- 036_share_management.sql was never applied — the two RPCs it needs
-- (subscribe_to_shared_db, manage_share) are (re)created here too.
--
-- P0  databases.share_token could be NULL on legacy DBs — the ADD COLUMN path in
--     013/016 had no DEFAULT and no backfill, and 023 only forced NOT NULL on
--     properties/collections. A NULL token means the public /v link and the
--     deep-link subscribe both silently fail. Fix: default + backfill + NOT NULL.
--
-- P1  The public /v database page was a dead end for visitors without Telegram:
--     get_public_db_preview returned no owner contact and no photos, so a viewer
--     saw a bare list with no way to reach the owner. Fix: preview now returns
--     owner_{first_name,last_name,tg_username,phone} + a first_photo per row.
--
-- P2  A brand-new user opening a DB share link was created with the default
--     role 'owner' (edge fn) yet dropped onto realtor-dashboard — a role/home
--     mismatch. Fix: subscribe_to_shared_db promotes a default-owner who has
--     never created a database to 'realtor' (an established owner keeps owner).
-- ============================================================================

-- ── P0: databases.share_token — default + backfill + NOT NULL ────────────────
ALTER TABLE databases
  ALTER COLUMN share_token SET DEFAULT encode(gen_random_bytes(12), 'hex');

UPDATE databases SET share_token = encode(gen_random_bytes(12), 'hex')
WHERE share_token IS NULL;

ALTER TABLE databases ALTER COLUMN share_token SET NOT NULL;

CREATE UNIQUE INDEX IF NOT EXISTS idx_databases_share_token
  ON databases(share_token);

-- ── P1: public DB preview now carries owner contact + first photo ────────────
DROP FUNCTION IF EXISTS get_public_db_preview(TEXT);
CREATE FUNCTION get_public_db_preview(p_token TEXT)
RETURNS TABLE (
  db_id UUID, db_name TEXT, db_type TEXT, db_color TEXT,
  share_expires_at TIMESTAMPTZ,
  property_id UUID, property_name TEXT, property_status TEXT,
  property_floor TEXT, property_area_useful FLOAT,
  property_area_total FLOAT, property_rent_type TEXT,
  property_rent_rate FLOAT, property_description TEXT,
  owner_first_name TEXT, owner_last_name TEXT,
  owner_tg_username TEXT, owner_phone TEXT,
  first_photo TEXT
)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT d.id, d.name, d.type, d.color, d.share_expires_at,
         p.id, p.name, p.status, p.floor, p.area_useful,
         p.area_total, p.rent_type, p.rent_rate, p.description,
         u.first_name, u.last_name, u.tg_username, u.phone,
         (SELECT ph.storage_path FROM property_photos ph
          WHERE ph.property_id = p.id ORDER BY ph.sort_order LIMIT 1)
  FROM databases d
  JOIN users u ON u.id = d.owner_id
  LEFT JOIN properties p ON p.db_id = d.id
  WHERE d.share_token = p_token
    AND (d.share_expires_at IS NULL OR d.share_expires_at > now())
  ORDER BY p.name;
$$;
REVOKE ALL ON FUNCTION get_public_db_preview(TEXT) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION get_public_db_preview(TEXT) TO anon, authenticated, service_role;

-- ── P2: subscribe_to_shared_db — token-gated + role normalisation ────────────
CREATE OR REPLACE FUNCTION subscribe_to_shared_db(p_token TEXT)
RETURNS TABLE (db_id UUID, db_name TEXT, error TEXT)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE
  v_uid UUID;
  v_db  RECORD;
BEGIN
  v_uid := current_app_user_id();
  IF v_uid IS NULL THEN
    RETURN QUERY SELECT NULL::UUID, NULL::TEXT, 'not_authenticated'::TEXT; RETURN;
  END IF;

  SELECT d.id, d.owner_id, d.name INTO v_db FROM databases d
  WHERE d.share_token = p_token
    AND (d.share_expires_at IS NULL OR d.share_expires_at > now())
  LIMIT 1;

  IF v_db.id IS NULL THEN
    RETURN QUERY SELECT NULL::UUID, NULL::TEXT, 'not_found'::TEXT; RETURN;
  END IF;
  IF v_db.owner_id = v_uid THEN
    RETURN QUERY SELECT v_db.id, v_db.name, 'own_db'::TEXT; RETURN;
  END IF;

  INSERT INTO realtor_subscriptions (realtor_id, db_id)
  VALUES (v_uid, v_db.id)
  ON CONFLICT (realtor_id, db_id) DO NOTHING;

  -- Someone who receives a DB share is acting as a realtor. A user still on the
  -- default 'owner' role who has never created a database of their own is one of
  -- these — normalise them so their home screen (realtor-dashboard) matches their
  -- role. An established owner (owns >=1 database) keeps 'owner'. The
  -- prevent_privilege_escalation trigger permits owner->realtor (it only blocks
  -- the realtor->owner self-promotion), so this is safe under SECURITY DEFINER.
  UPDATE users SET role = 'realtor'
  WHERE id = v_uid
    AND role = 'owner'
    AND NOT EXISTS (SELECT 1 FROM databases WHERE owner_id = v_uid);

  RETURN QUERY SELECT v_db.id, v_db.name, NULL::TEXT;
END;
$$;
REVOKE ALL ON FUNCTION subscribe_to_shared_db(TEXT) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION subscribe_to_shared_db(TEXT) TO authenticated, service_role;

-- ── manage_share — rotate / set_expiry / clear_expiry / revoke ───────────────
-- Re-created here so this migration alone restores share management (rotate,
-- expiry presets, revoke) even where 036 was never run.
CREATE OR REPLACE FUNCTION manage_share(
  p_kind   TEXT,   -- 'db' | 'prop' | 'col'
  p_id     UUID,
  p_action TEXT,   -- 'rotate' | 'set_expiry' | 'clear_expiry' | 'revoke'
  p_days   INT DEFAULT NULL
)
RETURNS TABLE (share_token TEXT, share_expires_at TIMESTAMPTZ, error TEXT)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE
  v_uid   UUID;
  v_owner UUID;
  v_tok   TEXT;
  v_exp   TIMESTAMPTZ;
BEGIN
  v_uid := current_app_user_id();
  IF v_uid IS NULL THEN
    RETURN QUERY SELECT NULL::TEXT, NULL::TIMESTAMPTZ, 'not_authenticated'::TEXT; RETURN;
  END IF;
  IF p_kind NOT IN ('db','prop','col') OR p_action NOT IN ('rotate','set_expiry','clear_expiry','revoke') THEN
    RETURN QUERY SELECT NULL::TEXT, NULL::TIMESTAMPTZ, 'bad_request'::TEXT; RETURN;
  END IF;
  IF p_action = 'set_expiry' AND (p_days IS NULL OR p_days < 1 OR p_days > 365) THEN
    RETURN QUERY SELECT NULL::TEXT, NULL::TIMESTAMPTZ, 'bad_request'::TEXT; RETURN;
  END IF;

  IF p_kind = 'db' THEN
    SELECT owner_id INTO v_owner FROM databases WHERE id = p_id FOR UPDATE;
  ELSIF p_kind = 'prop' THEN
    SELECT owner_id INTO v_owner FROM properties WHERE id = p_id FOR UPDATE;
  ELSE
    SELECT realtor_id INTO v_owner FROM collections WHERE id = p_id FOR UPDATE;
  END IF;

  IF v_owner IS NULL OR v_owner <> v_uid THEN
    RETURN QUERY SELECT NULL::TEXT, NULL::TIMESTAMPTZ, 'forbidden'::TEXT; RETURN;
  END IF;

  IF p_kind = 'db' THEN
    UPDATE databases SET
      share_token      = CASE WHEN p_action = 'rotate' THEN encode(gen_random_bytes(12),'hex') ELSE databases.share_token END,
      share_expires_at = CASE p_action
                           WHEN 'set_expiry'   THEN now() + make_interval(days => p_days)
                           WHEN 'clear_expiry' THEN NULL
                           WHEN 'revoke'       THEN now()
                           ELSE databases.share_expires_at
                         END
    WHERE id = p_id
    RETURNING databases.share_token, databases.share_expires_at INTO v_tok, v_exp;
  ELSIF p_kind = 'prop' THEN
    UPDATE properties SET
      share_token      = CASE WHEN p_action = 'rotate' THEN encode(gen_random_bytes(12),'hex') ELSE properties.share_token END,
      share_expires_at = CASE p_action
                           WHEN 'set_expiry'   THEN now() + make_interval(days => p_days)
                           WHEN 'clear_expiry' THEN NULL
                           WHEN 'revoke'       THEN now()
                           ELSE properties.share_expires_at
                         END
    WHERE id = p_id
    RETURNING properties.share_token, properties.share_expires_at INTO v_tok, v_exp;
  ELSE
    UPDATE collections SET
      share_token      = CASE WHEN p_action = 'rotate' THEN encode(gen_random_bytes(12),'hex') ELSE collections.share_token END,
      share_expires_at = CASE p_action
                           WHEN 'set_expiry'   THEN now() + make_interval(days => p_days)
                           WHEN 'clear_expiry' THEN NULL
                           WHEN 'revoke'       THEN now()
                           ELSE collections.share_expires_at
                         END
    WHERE id = p_id
    RETURNING collections.share_token, collections.share_expires_at INTO v_tok, v_exp;
  END IF;

  RETURN QUERY SELECT v_tok, v_exp, NULL::TEXT;
END;
$$;
REVOKE ALL ON FUNCTION manage_share(TEXT, UUID, TEXT, INT) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION manage_share(TEXT, UUID, TEXT, INT) TO authenticated, service_role;

-- ── Schema cache reload ──────────────────────────────────────────────────────
NOTIFY pgrst, 'reload schema';

-- ── Diagnostics ──────────────────────────────────────────────────────────────
SELECT '════ databases.share_token: no NULLs, NOT NULL enforced ════' AS check;
SELECT count(*) AS null_tokens FROM databases WHERE share_token IS NULL;

SELECT '════ DB-share RPCs present ════' AS check;
SELECT routine_name FROM information_schema.routines
WHERE routine_schema = 'public'
  AND routine_name IN ('get_public_db_preview','subscribe_to_shared_db','manage_share');

SELECT '════ DONE — 037 db share fixes applied ════' AS result;

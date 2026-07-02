-- ============================================================================
-- 036_share_management.sql — Share-link management + subscription hardening
-- Idempotent. Run in Supabase SQL Editor or via migration pipeline.
--
-- P1: realtor_subscriptions INSERT was client-side only — any authenticated
--     user could subscribe to any db_id without holding a valid share token.
--     Fix: token-validating SECURITY DEFINER RPC + policy narrowed to
--     SELECT/DELETE (no direct INSERT from clients).
--
-- P2: share_expires_at was never written by any code path, so expiry checks
--     always passed and links could not be rotated or revoked.
--     Fix: manage_share() RPC — rotate / set_expiry / clear_expiry / revoke.
--
-- P3: anon could INSERT unlimited fake rows into property_views (analytics
--     spam). Fix: record_public_view() RPC with token validation + 1/min
--     dedup per property; anon branch dropped from views_insert_auth.
-- ============================================================================

-- ── P1: subscribe_to_shared_db — token-gated subscription ───────────────────
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

  RETURN QUERY SELECT v_db.id, v_db.name, NULL::TEXT;
END;
$$;
REVOKE ALL ON FUNCTION subscribe_to_shared_db(TEXT) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION subscribe_to_shared_db(TEXT) TO authenticated, service_role;

-- Narrow the realtor policy: reads and unsubscribes stay client-side, but new
-- subscriptions must come through subscribe_to_shared_db (token-validated).
DROP POLICY IF EXISTS "subs_realtor_all"    ON realtor_subscriptions;
DROP POLICY IF EXISTS "subs_realtor_select" ON realtor_subscriptions;
DROP POLICY IF EXISTS "subs_realtor_delete" ON realtor_subscriptions;

CREATE POLICY "subs_realtor_select" ON realtor_subscriptions FOR SELECT
  USING (realtor_id = current_app_user_id());
CREATE POLICY "subs_realtor_delete" ON realtor_subscriptions FOR DELETE
  USING (realtor_id = current_app_user_id());

-- ── P3: record_public_view — validated, deduped anon view recording ─────────
CREATE OR REPLACE FUNCTION record_public_view(p_token TEXT)
RETURNS BOOLEAN
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE
  v_prop_id UUID;
BEGIN
  SELECT p.id INTO v_prop_id FROM properties p
  WHERE
    CASE
      -- Legacy: plain UUID links (same convention as lookup_shared_property)
      WHEN p_token ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
        THEN p.id = p_token::UUID
          AND (p.share_expires_at IS NULL OR p.share_expires_at > now())
      ELSE p.share_token = p_token
        AND (p.share_expires_at IS NULL OR p.share_expires_at > now())
    END
  LIMIT 1;

  IF v_prop_id IS NULL THEN RETURN FALSE; END IF;

  -- Dedup: at most one anonymous web view per property per minute.
  IF EXISTS (
    SELECT 1 FROM property_views
    WHERE property_id = v_prop_id
      AND viewer_id IS NULL
      AND created_at > now() - interval '1 minute'
  ) THEN RETURN TRUE; END IF;

  INSERT INTO property_views (property_id, viewer_id, viewer_name, action)
  VALUES (v_prop_id, NULL, 'Веб-перегляд', 'view');
  RETURN TRUE;
END;
$$;
REVOKE ALL ON FUNCTION record_public_view(TEXT) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION record_public_view(TEXT) TO anon, authenticated, service_role;

-- Drop the anon direct-INSERT branch: web views now go through the RPC only.
DROP POLICY IF EXISTS "views_insert_all"  ON property_views;
DROP POLICY IF EXISTS "views_insert_auth" ON property_views;

CREATE POLICY "views_insert_auth" ON property_views
  FOR INSERT WITH CHECK (
    auth.role() = 'authenticated'
    AND (viewer_id IS NULL OR viewer_id = current_app_user_id())
    AND (
      property_id IN (SELECT get_owner_property_ids(current_app_user_id()))
      OR
      property_id IN (SELECT get_realtor_property_ids(current_app_user_id()))
    )
  );

-- ── P2: manage_share — rotate / expiry / revoke for db|prop|col ─────────────
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

  -- Ownership check (row locked so concurrent rotates serialize)
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
SELECT '════ P1: realtor_subscriptions policies (no FOR ALL / INSERT for clients) ════' AS check;
SELECT polname, polcmd FROM pg_policy p JOIN pg_class c ON p.polrelid = c.oid
WHERE c.relname = 'realtor_subscriptions';

SELECT '════ P3: views_insert_auth (must NOT contain anon branch) ════' AS check;
SELECT polname, pg_get_expr(polwithcheck, polrelid) FROM pg_policy p JOIN pg_class c ON p.polrelid = c.oid
WHERE c.relname = 'property_views' AND polname = 'views_insert_auth';

SELECT '════ New RPCs present ════' AS check;
SELECT routine_name FROM information_schema.routines
WHERE routine_schema = 'public'
  AND routine_name IN ('subscribe_to_shared_db','record_public_view','manage_share');

SELECT '════ DONE — 036 share management applied ════' AS result;

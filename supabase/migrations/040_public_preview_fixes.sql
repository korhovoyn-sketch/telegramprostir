-- ============================================================================
-- 040_public_preview_fixes.sql — Public /v preview: currency, sale price,
-- ordering, db/collection view tracking.
-- Idempotent. Run in Supabase Dashboard → SQL Editor (no migration pipeline).
--
-- Fixes found by the public-view audit:
--   P1  Preview RPCs never return the owner's currency, so /v hardcodes "$".
--       An owner who prices in UAH/EUR publicly shows wrong prices. Add
--       owner_currency to all three preview RPCs.
--   P2  get_public_db_preview doesn't return sale_price — a "Продаж" card in
--       the public db list shows no figure at all. Add property_sale_price to
--       db + collection previews.
--   P3  Public lists are ORDER BY p.name (lexicographic: "Офіс 10" before
--       "Офіс 2") while the app orders by sort_order. Align: db preview by
--       sort_order, collection preview by the order the realtor added items.
--   P4  record_public_view only counts property opens; db/collection opens
--       never reach «Аналітика поширення». Track them: property_views gets
--       nullable db_id/collection_id targets + owner/realtor SELECT policies,
--       and record_public_view takes p_kind ('prop'|'db'|'col').
-- ============================================================================

-- ── P4a: property_views — allow db/collection as view targets ────────────────
ALTER TABLE property_views ALTER COLUMN property_id DROP NOT NULL;
ALTER TABLE property_views ADD COLUMN IF NOT EXISTS db_id UUID REFERENCES databases(id) ON DELETE CASCADE;
ALTER TABLE property_views ADD COLUMN IF NOT EXISTS collection_id UUID REFERENCES collections(id) ON DELETE CASCADE;

-- Exactly one target per row (existing rows all have property_id only → pass).
ALTER TABLE property_views DROP CONSTRAINT IF EXISTS property_views_one_target;
ALTER TABLE property_views ADD CONSTRAINT property_views_one_target CHECK (
  (property_id IS NOT NULL)::int + (db_id IS NOT NULL)::int + (collection_id IS NOT NULL)::int = 1
);

CREATE INDEX IF NOT EXISTS idx_property_views_db
  ON property_views (db_id, created_at) WHERE db_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_property_views_collection
  ON property_views (collection_id, created_at) WHERE collection_id IS NOT NULL;

-- Owners see opens of their shared dbs; realtors see opens of their collections.
-- (get_owner_db_ids / get_realtor_collection_ids are the SECURITY DEFINER
-- helpers from 003/016 — same pattern as every other property_views policy.)
DROP POLICY IF EXISTS "views_db_owner_select"    ON property_views;
DROP POLICY IF EXISTS "views_db_owner_delete"    ON property_views;
DROP POLICY IF EXISTS "views_col_realtor_select" ON property_views;

CREATE POLICY "views_db_owner_select" ON property_views FOR SELECT
  USING (db_id IN (SELECT get_owner_db_ids(current_app_user_id())));
CREATE POLICY "views_db_owner_delete" ON property_views FOR DELETE
  USING (db_id IN (SELECT get_owner_db_ids(current_app_user_id())));
CREATE POLICY "views_col_realtor_select" ON property_views FOR SELECT
  USING (collection_id IN (SELECT get_realtor_collection_ids(current_app_user_id())));

-- ── P4b: record_public_view — accept db/col tokens ───────────────────────────
-- Drop the 1-arg version first: leaving it alongside the 2-arg (defaulted)
-- version makes the RPC call ambiguous for PostgREST.
DROP FUNCTION IF EXISTS record_public_view(TEXT);
DROP FUNCTION IF EXISTS record_public_view(TEXT, TEXT);

CREATE FUNCTION record_public_view(p_token TEXT, p_kind TEXT DEFAULT 'prop')
RETURNS BOOLEAN
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE
  v_id UUID;
BEGIN
  IF p_kind = 'db' THEN
    SELECT d.id INTO v_id FROM databases d
    WHERE d.share_token = p_token
      AND (d.share_expires_at IS NULL OR d.share_expires_at > now())
    LIMIT 1;
    IF v_id IS NULL THEN RETURN FALSE; END IF;
    IF EXISTS (
      SELECT 1 FROM property_views
      WHERE db_id = v_id AND viewer_id IS NULL
        AND created_at > now() - interval '1 minute'
    ) THEN RETURN TRUE; END IF;
    INSERT INTO property_views (property_id, db_id, viewer_id, viewer_name, action)
    VALUES (NULL, v_id, NULL, 'Веб-перегляд бази', 'view');
    RETURN TRUE;

  ELSIF p_kind = 'col' THEN
    SELECT c.id INTO v_id FROM collections c
    WHERE c.share_token = p_token
      AND (c.share_expires_at IS NULL OR c.share_expires_at > now())
    LIMIT 1;
    IF v_id IS NULL THEN RETURN FALSE; END IF;
    IF EXISTS (
      SELECT 1 FROM property_views
      WHERE collection_id = v_id AND viewer_id IS NULL
        AND created_at > now() - interval '1 minute'
    ) THEN RETURN TRUE; END IF;
    INSERT INTO property_views (property_id, collection_id, viewer_id, viewer_name, action)
    VALUES (NULL, v_id, NULL, 'Веб-перегляд підбірки', 'view');
    RETURN TRUE;

  ELSE
    SELECT p.id INTO v_id FROM properties p
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
    IF v_id IS NULL THEN RETURN FALSE; END IF;
    IF EXISTS (
      SELECT 1 FROM property_views
      WHERE property_id = v_id AND viewer_id IS NULL
        AND created_at > now() - interval '1 minute'
    ) THEN RETURN TRUE; END IF;
    INSERT INTO property_views (property_id, viewer_id, viewer_name, action)
    VALUES (v_id, NULL, 'Веб-перегляд', 'view');
    RETURN TRUE;
  END IF;
END;
$$;
REVOKE ALL ON FUNCTION record_public_view(TEXT, TEXT) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION record_public_view(TEXT, TEXT) TO anon, authenticated, service_role;

-- ── P1+P2+P3: preview RPCs ────────────────────────────────────────────────────
-- Return-type changes require DROP + CREATE (not OR REPLACE).

-- get_public_property_preview: 039 definition + owner_currency.
DROP FUNCTION IF EXISTS get_public_property_preview(TEXT);
CREATE FUNCTION get_public_property_preview(p_token TEXT)
RETURNS TABLE (
  property_id             UUID,
  property_name           TEXT,
  property_status         TEXT,
  property_floor          TEXT,
  property_area_useful    FLOAT,
  property_area_total     FLOAT,
  property_rent_type      TEXT,
  property_rent_rate      FLOAT,
  property_utilities_rate FLOAT,
  property_description    TEXT,
  property_address        TEXT,
  property_has_parking    BOOLEAN,
  property_parking_spaces INT,
  property_parking_type   TEXT,
  property_ev_charger     BOOLEAN,
  property_sale_price     FLOAT,
  share_expires_at        TIMESTAMPTZ,
  db_id                   UUID,
  db_name                 TEXT,
  db_type                 TEXT,
  db_color                TEXT,
  owner_first_name        TEXT,
  owner_last_name         TEXT,
  owner_tg_username       TEXT,
  owner_phone             TEXT,
  owner_currency          TEXT,
  photos                  TEXT[]
)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT
    p.id, p.name, p.status, p.floor,
    p.area_useful, p.area_total, p.rent_type, p.rent_rate, p.utilities_rate,
    p.description, p.address, p.has_parking, p.parking_spaces,
    p.parking_type, p.ev_charger, p.sale_price,
    p.share_expires_at,
    d.id, d.name, d.type, d.color,
    u.first_name, u.last_name, u.tg_username, u.phone, u.currency,
    ARRAY(
      SELECT ph.storage_path FROM property_photos ph
      WHERE ph.property_id = p.id
      ORDER BY ph.sort_order
    )
  FROM properties p
  JOIN databases d ON d.id = p.db_id
  JOIN users u ON u.id = p.owner_id
  WHERE p.share_token = p_token
    AND (p.share_expires_at IS NULL OR p.share_expires_at > now())
  LIMIT 1;
$$;
REVOKE ALL ON FUNCTION get_public_property_preview(TEXT) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION get_public_property_preview(TEXT) TO anon, authenticated, service_role;

-- get_public_db_preview: 037 definition + sale_price + owner_currency,
-- ordered like the app (sort_order, name as stable tiebreak).
DROP FUNCTION IF EXISTS get_public_db_preview(TEXT);
CREATE FUNCTION get_public_db_preview(p_token TEXT)
RETURNS TABLE (
  db_id UUID, db_name TEXT, db_type TEXT, db_color TEXT,
  share_expires_at TIMESTAMPTZ,
  property_id UUID, property_name TEXT, property_status TEXT,
  property_floor TEXT, property_area_useful FLOAT,
  property_area_total FLOAT, property_rent_type TEXT,
  property_rent_rate FLOAT, property_sale_price FLOAT,
  property_description TEXT,
  owner_first_name TEXT, owner_last_name TEXT,
  owner_tg_username TEXT, owner_phone TEXT, owner_currency TEXT,
  first_photo TEXT
)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT d.id, d.name, d.type, d.color, d.share_expires_at,
         p.id, p.name, p.status, p.floor, p.area_useful,
         p.area_total, p.rent_type, p.rent_rate, p.sale_price, p.description,
         u.first_name, u.last_name, u.tg_username, u.phone, u.currency,
         (SELECT ph.storage_path FROM property_photos ph
          WHERE ph.property_id = p.id ORDER BY ph.sort_order LIMIT 1)
  FROM databases d
  JOIN users u ON u.id = d.owner_id
  LEFT JOIN properties p ON p.db_id = d.id
  WHERE d.share_token = p_token
    AND (d.share_expires_at IS NULL OR d.share_expires_at > now())
  ORDER BY p.sort_order NULLS LAST, p.name;
$$;
REVOKE ALL ON FUNCTION get_public_db_preview(TEXT) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION get_public_db_preview(TEXT) TO anon, authenticated, service_role;

-- get_public_collection_preview: 023 definition + sale_price + owner_currency
-- (the PROPERTY owner's currency — prices belong to the owner, the contact on
-- the page stays the realtor), ordered by when the realtor added each item.
DROP FUNCTION IF EXISTS get_public_collection_preview(TEXT);
CREATE FUNCTION get_public_collection_preview(p_token TEXT)
RETURNS TABLE (
  collection_id UUID, collection_name TEXT, share_expires_at TIMESTAMPTZ,
  realtor_first_name TEXT, realtor_last_name TEXT,
  realtor_tg_username TEXT, realtor_phone TEXT,
  property_id UUID, property_name TEXT, property_status TEXT, property_floor TEXT,
  property_area_useful FLOAT, property_area_total FLOAT,
  property_rent_type TEXT, property_rent_rate FLOAT, property_sale_price FLOAT,
  property_description TEXT, owner_currency TEXT,
  db_id UUID, db_name TEXT, db_type TEXT, db_color TEXT, first_photo TEXT
)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT c.id, c.name, c.share_expires_at,
         u.first_name, u.last_name, u.tg_username, u.phone,
         p.id, p.name, p.status, p.floor,
         p.area_useful, p.area_total, p.rent_type, p.rent_rate, p.sale_price,
         p.description, po.currency,
         d.id, d.name, d.type, d.color,
         (SELECT ph.storage_path FROM property_photos ph
          WHERE ph.property_id = p.id ORDER BY ph.sort_order LIMIT 1)
  FROM collections c
  JOIN users u ON u.id = c.realtor_id
  LEFT JOIN collection_properties cp ON cp.collection_id = c.id
  LEFT JOIN properties p ON p.id = cp.property_id
  LEFT JOIN users po ON po.id = p.owner_id
  LEFT JOIN databases d ON d.id = p.db_id
  WHERE c.share_token = p_token
    AND (c.share_expires_at IS NULL OR c.share_expires_at > now())
  ORDER BY cp.added_at;
$$;
REVOKE ALL ON FUNCTION get_public_collection_preview(TEXT) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION get_public_collection_preview(TEXT) TO anon, authenticated, service_role;

-- ── Schema cache reload ──────────────────────────────────────────────────────
NOTIFY pgrst, 'reload schema';

-- ── Diagnostics ──────────────────────────────────────────────────────────────
SELECT '════ property_views targets (db_id + collection_id must exist, property_id nullable) ════' AS check;
SELECT column_name, is_nullable FROM information_schema.columns
WHERE table_name = 'property_views' AND column_name IN ('property_id','db_id','collection_id')
ORDER BY column_name;

SELECT '════ record_public_view must have (p_token, p_kind) ════' AS check;
SELECT proname, pg_get_function_arguments(oid) FROM pg_proc WHERE proname = 'record_public_view';

SELECT '════ preview RPCs must return owner_currency ════' AS check;
SELECT proname FROM pg_proc
WHERE proname IN ('get_public_property_preview','get_public_db_preview','get_public_collection_preview')
  AND pg_get_function_result(oid) LIKE '%owner_currency%';

SELECT '════ new view policies present ════' AS check;
SELECT policyname FROM pg_policies
WHERE tablename = 'property_views'
  AND policyname IN ('views_db_owner_select','views_db_owner_delete','views_col_realtor_select');

SELECT '════ DONE — 040 public preview fixes applied ════' AS result;

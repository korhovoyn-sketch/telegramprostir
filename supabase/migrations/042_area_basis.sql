-- ============================================================================
-- 042_area_basis.sql — per-object choice of WHICH area the per-m² rate multiplies.
-- Idempotent. Run in Supabase Dashboard → SQL Editor (no migration pipeline).
--
-- Product change: the per-m² rent AND expenses (formerly "комунальні", now
-- "експлуатаційні") rate is multiplied by the object's area. Historically rent
-- used area_useful (корисна) and expenses used area_total. Owners now pick the
-- basis per object — 'useful' (корисна) or 'total' (розрахункова, the renamed
-- area_total) — applied to BOTH rent and expenses. Default 'total' (розрахункова),
-- matching the requested behaviour; when the chosen area is empty the client
-- falls back to the other area, so nothing computes to zero.
--
-- Only get_public_property_preview needs the new column: the /v property detail
-- computes a monthly total (calcRentUtils) and must know the basis. The db and
-- collection previews show the RAW rate only, so their signatures stay put.
-- ============================================================================

-- ── Column ───────────────────────────────────────────────────────────────────
ALTER TABLE properties
  ADD COLUMN IF NOT EXISTS area_basis TEXT NOT NULL DEFAULT 'total'
  CHECK (area_basis IN ('useful', 'total'));

-- ── get_public_property_preview: 040 definition + property_area_basis ────────
-- Return-type change requires DROP + CREATE (not OR REPLACE).
DROP FUNCTION IF EXISTS get_public_property_preview(TEXT);
CREATE FUNCTION get_public_property_preview(p_token TEXT)
RETURNS TABLE (
  property_id             UUID,
  property_name           TEXT,
  property_status         TEXT,
  property_floor          TEXT,
  property_area_useful    FLOAT,
  property_area_total     FLOAT,
  property_area_basis     TEXT,
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
    p.area_useful, p.area_total, p.area_basis,
    p.rent_type, p.rent_rate, p.utilities_rate,
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

-- ── Schema cache reload ──────────────────────────────────────────────────────
NOTIFY pgrst, 'reload schema';

-- ── Diagnostics ──────────────────────────────────────────────────────────────
SELECT '════ properties.area_basis must exist with default total ════' AS check;
SELECT column_name, column_default, is_nullable FROM information_schema.columns
WHERE table_name = 'properties' AND column_name = 'area_basis';

SELECT '════ preview RPC must return property_area_basis ════' AS check;
SELECT proname FROM pg_proc
WHERE proname = 'get_public_property_preview'
  AND pg_get_function_result(oid) LIKE '%property_area_basis%';

SELECT '════ DONE — 042 area_basis applied ════' AS result;

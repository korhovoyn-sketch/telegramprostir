-- ============================================================================
-- 039_parking_fields.sql — Parking-specific property fields.
-- Idempotent. Run in Supabase Dashboard → SQL Editor (no migration pipeline).
--
-- A property inside a `parking`-type database is described very differently
-- from an office/apartment: it has a spot number, a single spot area, a spot
-- kind (underground / covered / open), an optional EV charger, a monthly OR
-- daily rate, and a flat utilities charge (not $/m²). The office-oriented
-- columns are reused where they fit (name = spot number, floor = level,
-- area_useful = spot area, utilities_rate = flat parking utilities); the two
-- genuinely new attributes get their own columns, and rent_type gains 'per_day'.
-- ============================================================================

-- ── rent_type: allow 'per_day' (подобова) alongside per_m2 / fixed ───────────
ALTER TABLE properties DROP CONSTRAINT IF EXISTS properties_rent_type_check;
ALTER TABLE properties
  ADD CONSTRAINT properties_rent_type_check
  CHECK (rent_type IN ('per_m2', 'fixed', 'per_day'));

-- ── New parking attributes ───────────────────────────────────────────────────
ALTER TABLE properties
  ADD COLUMN IF NOT EXISTS parking_type TEXT,
  ADD COLUMN IF NOT EXISTS ev_charger   BOOLEAN NOT NULL DEFAULT false;

ALTER TABLE properties DROP CONSTRAINT IF EXISTS properties_parking_type_check;
ALTER TABLE properties
  ADD CONSTRAINT properties_parking_type_check
  CHECK (parking_type IS NULL OR parking_type IN ('underground', 'covered', 'open'));

COMMENT ON COLUMN properties.parking_type IS 'Parking spot kind: underground | covered | open (parking DBs only)';
COMMENT ON COLUMN properties.ev_charger   IS 'Whether the parking spot has an EV charger';

-- ── Public property preview: expose parking attributes on /v ─────────────────
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
    u.first_name, u.last_name, u.tg_username, u.phone,
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
SELECT '════ rent_type constraint (must include per_day) ════' AS check;
SELECT pg_get_constraintdef(oid) FROM pg_constraint WHERE conname = 'properties_rent_type_check';

SELECT '════ parking columns present ════' AS check;
SELECT column_name, data_type FROM information_schema.columns
WHERE table_name = 'properties' AND column_name IN ('parking_type', 'ev_charger');

SELECT '════ DONE — 039 parking fields applied ════' AS result;

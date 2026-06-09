-- 020_public_share_tokens.sql
-- Adds share_token + share_expires_at to properties and collections,
-- plus public SECURITY DEFINER RPCs for the /v viewer page and the in-app deep-link handler.

-- ── Properties ───────────────────────────────────────────────────────────────

ALTER TABLE properties
  ADD COLUMN IF NOT EXISTS share_token TEXT UNIQUE
    DEFAULT encode(gen_random_bytes(12), 'hex'),
  ADD COLUMN IF NOT EXISTS share_expires_at TIMESTAMPTZ;

-- Backfill rows created before this migration
UPDATE properties SET share_token = encode(gen_random_bytes(12), 'hex')
WHERE share_token IS NULL;

ALTER TABLE properties ALTER COLUMN share_token SET NOT NULL;

CREATE INDEX IF NOT EXISTS idx_properties_share_token ON properties(share_token);

-- ── Collections ──────────────────────────────────────────────────────────────

ALTER TABLE collections
  ADD COLUMN IF NOT EXISTS share_token TEXT UNIQUE
    DEFAULT encode(gen_random_bytes(12), 'hex'),
  ADD COLUMN IF NOT EXISTS share_expires_at TIMESTAMPTZ;

UPDATE collections SET share_token = encode(gen_random_bytes(12), 'hex')
WHERE share_token IS NULL;

ALTER TABLE collections ALTER COLUMN share_token SET NOT NULL;

CREATE INDEX IF NOT EXISTS idx_collections_share_token ON collections(share_token);

-- ── Public property preview (anon-accessible via share token) ────────────────

CREATE OR REPLACE FUNCTION get_public_property_preview(p_token TEXT)
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
    p.description, p.address, p.has_parking, p.parking_spaces, p.sale_price,
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

-- ── Property lookup for in-app deep-link handler (authenticated only) ────────
-- Handles both new share_token format AND legacy UUID format (backward compat).

CREATE OR REPLACE FUNCTION lookup_shared_property(p_token TEXT)
RETURNS TABLE (id UUID, db_id UUID)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT p.id, p.db_id FROM properties p
  WHERE
    CASE
      -- Legacy: plain UUID (36 chars with hyphens) — look up by id directly
      WHEN p_token ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
        THEN p.id = p_token::UUID
      -- New: 24-char hex share_token
      ELSE p.share_token = p_token
        AND (p.share_expires_at IS NULL OR p.share_expires_at > now())
    END
  LIMIT 1;
$$;
REVOKE ALL ON FUNCTION lookup_shared_property(TEXT) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION lookup_shared_property(TEXT) TO authenticated, service_role;

-- ── Public collection preview (anon-accessible via share token) ──────────────

CREATE OR REPLACE FUNCTION get_public_collection_preview(p_token TEXT)
RETURNS TABLE (
  collection_id        UUID,
  collection_name      TEXT,
  share_expires_at     TIMESTAMPTZ,
  realtor_first_name   TEXT,
  realtor_last_name    TEXT,
  realtor_tg_username  TEXT,
  realtor_phone        TEXT,
  property_id          UUID,
  property_name        TEXT,
  property_status      TEXT,
  property_floor       TEXT,
  property_area_useful FLOAT,
  property_area_total  FLOAT,
  property_rent_type   TEXT,
  property_rent_rate   FLOAT,
  property_description TEXT,
  db_id                UUID,
  db_name              TEXT,
  db_type              TEXT,
  db_color             TEXT,
  first_photo          TEXT
)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT
    c.id, c.name, c.share_expires_at,
    u.first_name, u.last_name, u.tg_username, u.phone,
    p.id, p.name, p.status, p.floor,
    p.area_useful, p.area_total, p.rent_type, p.rent_rate, p.description,
    d.id, d.name, d.type, d.color,
    (SELECT ph.storage_path FROM property_photos ph
     WHERE ph.property_id = p.id ORDER BY ph.sort_order LIMIT 1)
  FROM collections c
  JOIN users u ON u.id = c.realtor_id
  LEFT JOIN collection_properties cp ON cp.collection_id = c.id
  LEFT JOIN properties p ON p.id = cp.property_id
  LEFT JOIN databases d ON d.id = p.db_id
  WHERE c.share_token = p_token
    AND (c.share_expires_at IS NULL OR c.share_expires_at > now())
  ORDER BY p.name;
$$;
REVOKE ALL ON FUNCTION get_public_collection_preview(TEXT) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION get_public_collection_preview(TEXT) TO anon, authenticated, service_role;

-- ── Collection lookup for in-app deep-link handler ───────────────────────────

CREATE OR REPLACE FUNCTION lookup_shared_collection(p_token TEXT)
RETURNS TABLE (id UUID, realtor_id UUID)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT c.id, c.realtor_id FROM collections c
  WHERE
    CASE
      WHEN p_token ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
        THEN c.id = p_token::UUID
      ELSE c.share_token = p_token
        AND (c.share_expires_at IS NULL OR c.share_expires_at > now())
    END
  LIMIT 1;
$$;
REVOKE ALL ON FUNCTION lookup_shared_collection(TEXT) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION lookup_shared_collection(TEXT) TO authenticated, service_role;

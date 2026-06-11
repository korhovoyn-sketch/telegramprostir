-- ============================================================================
-- 023_complete_idempotent.sql
-- Brings ANY database state (fresh or partial) to full v1.0.0 spec.
-- SAFE to run multiple times — every statement is idempotent.
-- Run this in Supabase SQL Editor if you've applied 016_complete_setup.sql
-- (which wiped property_files RLS) and/or are missing 017–022 additions.
-- ============================================================================

-- ── 1. PROPERTIES — missing columns ─────────────────────────────────────────
ALTER TABLE properties ADD COLUMN IF NOT EXISTS sort_order      INT     NOT NULL DEFAULT 0;
ALTER TABLE properties ADD COLUMN IF NOT EXISTS share_token     TEXT;
ALTER TABLE properties ADD COLUMN IF NOT EXISTS share_expires_at TIMESTAMPTZ;
ALTER TABLE properties ADD COLUMN IF NOT EXISTS sale_price       FLOAT;
ALTER TABLE properties ADD COLUMN IF NOT EXISTS tenant_name      TEXT;
ALTER TABLE properties ADD COLUMN IF NOT EXISTS lease_start_date DATE;
ALTER TABLE properties ADD COLUMN IF NOT EXISTS lease_end_date   DATE;
ALTER TABLE properties ADD COLUMN IF NOT EXISTS address          TEXT;
ALTER TABLE properties ADD COLUMN IF NOT EXISTS utilities        TEXT[] DEFAULT '{}';

UPDATE properties SET share_token = encode(gen_random_bytes(12), 'hex') WHERE share_token IS NULL;
ALTER TABLE properties ALTER COLUMN share_token SET NOT NULL;

-- ── 2. COLLECTIONS — missing columns ────────────────────────────────────────
ALTER TABLE collections ADD COLUMN IF NOT EXISTS share_token      TEXT;
ALTER TABLE collections ADD COLUMN IF NOT EXISTS share_expires_at TIMESTAMPTZ;

UPDATE collections SET share_token = encode(gen_random_bytes(12), 'hex') WHERE share_token IS NULL;
ALTER TABLE collections ALTER COLUMN share_token SET NOT NULL;

-- ── 3. INDEXES ────────────────────────────────────────────────────────────────
CREATE INDEX IF NOT EXISTS idx_properties_sort_order    ON properties(db_id, sort_order, created_at);
CREATE UNIQUE INDEX IF NOT EXISTS idx_properties_share_token   ON properties(share_token);
CREATE UNIQUE INDEX IF NOT EXISTS idx_collections_share_token  ON collections(share_token);

-- ── 4. property_files TABLE ───────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS property_files (
  id           UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
  property_id  UUID        NOT NULL REFERENCES properties(id) ON DELETE CASCADE,
  owner_id     UUID        NOT NULL REFERENCES users(id)      ON DELETE CASCADE,
  storage_path TEXT        NOT NULL,
  file_name    TEXT        NOT NULL,
  file_size    BIGINT      NOT NULL DEFAULT 0,
  mime_type    TEXT        NOT NULL,
  sort_order   INT         NOT NULL DEFAULT 0,
  created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

ALTER TABLE property_files ENABLE ROW LEVEL SECURITY;
CREATE INDEX IF NOT EXISTS idx_property_files_property ON property_files(property_id);
CREATE INDEX IF NOT EXISTS idx_property_files_owner    ON property_files(owner_id);

-- ── 5. rent_payments TABLES ───────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS rent_payments (
  id                 UUID     PRIMARY KEY DEFAULT gen_random_uuid(),
  property_id        UUID     NOT NULL REFERENCES properties(id) ON DELETE CASCADE,
  owner_id           UUID     NOT NULL REFERENCES users(id)      ON DELETE CASCADE,
  due_day            SMALLINT NOT NULL CHECK (due_day BETWEEN 1 AND 28),
  notify_days_before SMALLINT NOT NULL DEFAULT 3 CHECK (notify_days_before BETWEEN 0 AND 14),
  is_active          BOOLEAN  NOT NULL DEFAULT true,
  created_at         TIMESTAMPTZ DEFAULT now(),
  updated_at         TIMESTAMPTZ DEFAULT now(),
  UNIQUE(property_id)
);
ALTER TABLE rent_payments ENABLE ROW LEVEL SECURITY;

CREATE TABLE IF NOT EXISTS rent_payment_records (
  id          UUID    PRIMARY KEY DEFAULT gen_random_uuid(),
  property_id UUID    NOT NULL REFERENCES properties(id) ON DELETE CASCADE,
  owner_id    UUID    NOT NULL REFERENCES users(id)      ON DELETE CASCADE,
  due_date    DATE    NOT NULL,
  paid_at     TIMESTAMPTZ,
  amount      FLOAT,
  status      TEXT    NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','paid','overdue')),
  notes       TEXT,
  created_at  TIMESTAMPTZ DEFAULT now(),
  updated_at  TIMESTAMPTZ DEFAULT now(),
  CONSTRAINT uniq_property_due UNIQUE(property_id, due_date)
);
ALTER TABLE rent_payment_records ENABLE ROW LEVEL SECURITY;

CREATE INDEX IF NOT EXISTS idx_rent_payments_property         ON rent_payments(property_id);
CREATE INDEX IF NOT EXISTS idx_rent_payments_owner            ON rent_payments(owner_id, is_active);
CREATE INDEX IF NOT EXISTS idx_payment_records_property_due   ON rent_payment_records(property_id, due_date);
CREATE INDEX IF NOT EXISTS idx_payment_records_owner_status   ON rent_payment_records(owner_id, status);

-- ── 6. RLS POLICIES — rebuild for ALL tables (drop + recreate, idempotent) ────

-- property_files
DROP POLICY IF EXISTS "pfiles_select_owner"   ON property_files;
DROP POLICY IF EXISTS "pfiles_insert_owner"   ON property_files;
DROP POLICY IF EXISTS "pfiles_delete_owner"   ON property_files;
DROP POLICY IF EXISTS "pfiles_select_realtor" ON property_files;

CREATE POLICY "pfiles_select_owner" ON property_files
  FOR SELECT USING (owner_id = current_app_user_id());

CREATE POLICY "pfiles_insert_owner" ON property_files
  FOR INSERT WITH CHECK (owner_id = current_app_user_id());

CREATE POLICY "pfiles_delete_owner" ON property_files
  FOR DELETE USING (owner_id = current_app_user_id());

CREATE POLICY "pfiles_select_realtor" ON property_files
  FOR SELECT USING (
    EXISTS (
      SELECT 1 FROM realtor_subscriptions rs
      JOIN properties p ON p.db_id = rs.db_id
      WHERE rs.realtor_id = current_app_user_id()
        AND p.id = property_files.property_id
    )
  );

-- rent_payments
DROP POLICY IF EXISTS "owner manages rent_payments"   ON rent_payments;
DROP POLICY IF EXISTS "owner manages payment_records" ON rent_payment_records;

CREATE POLICY "owner manages rent_payments"
  ON rent_payments FOR ALL
  USING     (owner_id = current_app_user_id())
  WITH CHECK (owner_id = current_app_user_id());

CREATE POLICY "owner manages payment_records"
  ON rent_payment_records FOR ALL
  USING     (owner_id = current_app_user_id())
  WITH CHECK (owner_id = current_app_user_id());

-- Fix property_views INSERT: restrict action to accessible properties only
-- (prevents authenticated users inserting fake views for properties they can't see)
DROP POLICY IF EXISTS "views_insert_all"  ON property_views;
DROP POLICY IF EXISTS "views_insert_auth" ON property_views;

CREATE POLICY "views_insert_auth" ON property_views
  FOR INSERT WITH CHECK (
    (
      -- Authenticated users: property must be owned by or subscribed to by the caller
      auth.role() = 'authenticated'
      AND (viewer_id IS NULL OR viewer_id = current_app_user_id())
      AND (
        property_id IN (SELECT get_owner_property_ids(current_app_user_id()))
        OR
        property_id IN (SELECT get_realtor_property_ids(current_app_user_id()))
      )
    )
    OR
    -- Anon (public /v page) — allow view events, viewer_id must be null
    (auth.role() = 'anon' AND viewer_id IS NULL AND action = 'view')
  );

-- ── 7. STORAGE BUCKET — property-files (private, 20 MB, PDF/DOC/DOCX) ─────────
INSERT INTO storage.buckets (id, name, public, file_size_limit, allowed_mime_types)
VALUES (
  'property-files', 'property-files', false, 20971520,
  ARRAY[
    'application/pdf',
    'application/msword',
    'application/vnd.openxmlformats-officedocument.wordprocessingml.document'
  ]
)
ON CONFLICT (id) DO UPDATE
  SET public             = false,
      file_size_limit    = 20971520,
      allowed_mime_types = ARRAY[
        'application/pdf',
        'application/msword',
        'application/vnd.openxmlformats-officedocument.wordprocessingml.document'
      ];

-- ── 8. STORAGE POLICIES — property-files ──────────────────────────────────────
DROP POLICY IF EXISTS "pfiles_storage_select" ON storage.objects;
DROP POLICY IF EXISTS "pfiles_storage_insert" ON storage.objects;
DROP POLICY IF EXISTS "pfiles_storage_delete" ON storage.objects;

-- SELECT: any authenticated user (signed URLs bypass this for actual downloads,
-- but we still restrict direct storage reads to authenticated callers)
CREATE POLICY "pfiles_storage_select" ON storage.objects
  FOR SELECT TO authenticated
  USING (bucket_id = 'property-files');

-- INSERT: path must start with a property owned by the caller
CREATE POLICY "pfiles_storage_insert" ON storage.objects
  FOR INSERT TO authenticated
  WITH CHECK (
    bucket_id = 'property-files'
    AND SPLIT_PART(name, '/', 1) IN (
      SELECT p.id::text FROM public.properties p
      WHERE p.owner_id = public.current_app_user_id()
    )
  );

-- DELETE: path must start with a property owned by the caller
CREATE POLICY "pfiles_storage_delete" ON storage.objects
  FOR DELETE TO authenticated
  USING (
    bucket_id = 'property-files'
    AND SPLIT_PART(name, '/', 1) IN (
      SELECT p.id::text FROM public.properties p
      WHERE p.owner_id = public.current_app_user_id()
    )
  );

-- ── 9. UPDATED_AT TRIGGERS for new tables ────────────────────────────────────
DROP TRIGGER IF EXISTS trg_rent_payments_updated_at       ON rent_payments;
DROP TRIGGER IF EXISTS trg_rent_payment_records_updated_at ON rent_payment_records;

CREATE TRIGGER trg_rent_payments_updated_at
  BEFORE UPDATE ON rent_payments FOR EACH ROW EXECUTE FUNCTION update_updated_at();
CREATE TRIGGER trg_rent_payment_records_updated_at
  BEFORE UPDATE ON rent_payment_records FOR EACH ROW EXECUTE FUNCTION update_updated_at();

-- ── 10. SECURITY DEFINER HELPER FUNCTIONS ────────────────────────────────────
-- Pin search_path on all helpers (safe to re-run)
DO $$
DECLARE fn TEXT;
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
    EXCEPTION WHEN undefined_function THEN NULL;
    END;
  END LOOP;
END $$;

-- ── 11. PUBLIC SHARE RPCs (from 020, fixed: UUID path now checks expiry) ─────

CREATE OR REPLACE FUNCTION get_public_property_preview(p_token TEXT)
RETURNS TABLE (
  property_id UUID, property_name TEXT, property_status TEXT, property_floor TEXT,
  property_area_useful FLOAT, property_area_total FLOAT, property_rent_type TEXT,
  property_rent_rate FLOAT, property_utilities_rate FLOAT, property_description TEXT,
  property_address TEXT, property_has_parking BOOLEAN, property_parking_spaces INT,
  property_sale_price FLOAT, share_expires_at TIMESTAMPTZ,
  db_id UUID, db_name TEXT, db_type TEXT, db_color TEXT,
  owner_first_name TEXT, owner_last_name TEXT, owner_tg_username TEXT, owner_phone TEXT,
  photos TEXT[]
)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT p.id, p.name, p.status, p.floor,
         p.area_useful, p.area_total, p.rent_type, p.rent_rate, p.utilities_rate,
         p.description, p.address, p.has_parking, p.parking_spaces, p.sale_price,
         p.share_expires_at,
         d.id, d.name, d.type, d.color,
         u.first_name, u.last_name, u.tg_username, u.phone,
         ARRAY(SELECT ph.storage_path FROM property_photos ph
               WHERE ph.property_id = p.id ORDER BY ph.sort_order)
  FROM properties p
  JOIN databases d ON d.id = p.db_id
  JOIN users u ON u.id = p.owner_id
  WHERE p.share_token = p_token
    AND (p.share_expires_at IS NULL OR p.share_expires_at > now())
  LIMIT 1;
$$;
REVOKE ALL ON FUNCTION get_public_property_preview(TEXT) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION get_public_property_preview(TEXT) TO anon, authenticated, service_role;

-- FIX: lookup_shared_property — legacy UUID path now also checks expiry
CREATE OR REPLACE FUNCTION lookup_shared_property(p_token TEXT)
RETURNS TABLE (id UUID, db_id UUID)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT p.id, p.db_id FROM properties p
  WHERE
    CASE
      WHEN p_token ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
        THEN p.id = p_token::UUID
             AND (p.share_expires_at IS NULL OR p.share_expires_at > now())
      ELSE p.share_token = p_token
           AND (p.share_expires_at IS NULL OR p.share_expires_at > now())
    END
  LIMIT 1;
$$;
REVOKE ALL ON FUNCTION lookup_shared_property(TEXT) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION lookup_shared_property(TEXT) TO authenticated, service_role;

-- FIX: lookup_shared_collection — legacy UUID path now also checks expiry
CREATE OR REPLACE FUNCTION lookup_shared_collection(p_token TEXT)
RETURNS TABLE (id UUID, realtor_id UUID)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT c.id, c.realtor_id FROM collections c
  WHERE
    CASE
      WHEN p_token ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
        THEN c.id = p_token::UUID
             AND (c.share_expires_at IS NULL OR c.share_expires_at > now())
      ELSE c.share_token = p_token
           AND (c.share_expires_at IS NULL OR c.share_expires_at > now())
    END
  LIMIT 1;
$$;
REVOKE ALL ON FUNCTION lookup_shared_collection(TEXT) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION lookup_shared_collection(TEXT) TO authenticated, service_role;

CREATE OR REPLACE FUNCTION get_public_collection_preview(p_token TEXT)
RETURNS TABLE (
  collection_id UUID, collection_name TEXT, share_expires_at TIMESTAMPTZ,
  realtor_first_name TEXT, realtor_last_name TEXT,
  realtor_tg_username TEXT, realtor_phone TEXT,
  property_id UUID, property_name TEXT, property_status TEXT, property_floor TEXT,
  property_area_useful FLOAT, property_area_total FLOAT,
  property_rent_type TEXT, property_rent_rate FLOAT, property_description TEXT,
  db_id UUID, db_name TEXT, db_type TEXT, db_color TEXT, first_photo TEXT
)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT c.id, c.name, c.share_expires_at,
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

-- ── 12. RENT REMINDER FUNCTION ───────────────────────────────────────────────
CREATE OR REPLACE FUNCTION get_due_reminders_today()
RETURNS TABLE(
  owner_id UUID, tg_id BIGINT, property_id UUID, property_name TEXT,
  due_day INT, tenant_name TEXT, due_date DATE
)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE v_today DATE := current_date;
BEGIN
  RETURN QUERY
  SELECT rp.owner_id, u.tg_id, rp.property_id, p.name,
         rp.due_day::INT, p.tenant_name,
         make_date(
           EXTRACT(YEAR  FROM (v_today + rp.notify_days_before * INTERVAL '1 day'))::INT,
           EXTRACT(MONTH FROM (v_today + rp.notify_days_before * INTERVAL '1 day'))::INT,
           rp.due_day
         )
  FROM rent_payments rp
  JOIN properties p ON p.id = rp.property_id
  JOIN users u ON u.id = rp.owner_id
  WHERE rp.is_active = true
    AND p.status = 'occupied'
    AND EXTRACT(DAY FROM (v_today + rp.notify_days_before * INTERVAL '1 day'))::INT = rp.due_day
    AND NOT EXISTS (
      SELECT 1 FROM notifications n
      WHERE n.user_id = rp.owner_id
        AND n.type = 'rent_reminder'
        AND (n.data->>'property_id')::UUID = rp.property_id
        AND DATE_TRUNC('month', n.created_at) = DATE_TRUNC('month', v_today::TIMESTAMPTZ)
    );
END;
$$;
GRANT EXECUTE ON FUNCTION get_due_reminders_today() TO service_role;

-- ── 13. SCHEMA CACHE RELOAD ───────────────────────────────────────────────────
NOTIFY pgrst, 'reload schema';

-- ── 14. DIAGNOSTICS ───────────────────────────────────────────────────────────
SELECT '═══ TABLES (must include property_files, rent_payments, rent_payment_records) ═══' AS check;
SELECT table_name FROM information_schema.tables
WHERE table_schema = 'public'
  AND table_name IN ('users','databases','properties','property_photos',
                     'property_files','rent_payments','rent_payment_records',
                     'realtor_subscriptions','collections','property_views',
                     'notifications','rate_limits','audit_log')
ORDER BY table_name;

SELECT '═══ BUCKETS (must include photos AND property-files) ═══' AS check;
SELECT id, name, public, file_size_limit FROM storage.buckets
WHERE id IN ('photos','property-files');

SELECT '═══ RLS POLICIES ═══' AS check;
SELECT tablename, count(*) AS policies
FROM pg_policies WHERE schemaname = 'public'
GROUP BY tablename ORDER BY tablename;

SELECT '═══ DONE ═══' AS result,
  (SELECT count(*) FROM pg_policies WHERE schemaname='public')::text || ' public RLS policies' AS detail;

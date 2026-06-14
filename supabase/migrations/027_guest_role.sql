-- PropSpace 027 — Guest role: invite-only read-only access + payment reminders
-- Apply in Supabase Dashboard → SQL Editor (idempotent).

-- ── 1. EXTEND role CHECK ──────────────────────────────────────────────────────
ALTER TABLE users DROP CONSTRAINT IF EXISTS users_role_check;
ALTER TABLE users ADD CONSTRAINT users_role_check
  CHECK (role IN ('owner', 'realtor', 'guest'));

-- ── 2. UPDATE prevent_privilege_escalation ────────────────────────────────────
-- Allow onboarding transitions (owner→realtor, owner→guest, realtor→guest).
-- Block escalation back to owner/realtor from guest, and realtor→owner.
CREATE OR REPLACE FUNCTION prevent_privilege_escalation()
RETURNS TRIGGER LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
BEGIN
  IF current_setting('request.jwt.claims', true) IS NOT NULL
     AND current_setting('request.jwt.claims', true) != ''
  THEN
    -- Always block plan changes from client sessions
    NEW.plan := OLD.plan;
    -- Block escalation: guest→owner, guest→realtor, realtor→owner
    IF (OLD.role = 'guest'   AND NEW.role IN ('owner','realtor')) OR
       (OLD.role = 'realtor' AND NEW.role = 'owner')
    THEN
      NEW.role := OLD.role;
    END IF;
  END IF;
  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trg_prevent_privilege_escalation ON users;
CREATE TRIGGER trg_prevent_privilege_escalation
  BEFORE UPDATE ON users
  FOR EACH ROW EXECUTE FUNCTION prevent_privilege_escalation();

-- ── 3. guest_links TABLE ──────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS guest_links (
  id            UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
  owner_id      UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  -- Exactly one target: property OR database
  property_id   UUID        REFERENCES properties(id) ON DELETE CASCADE,
  db_id         UUID        REFERENCES databases(id)  ON DELETE CASCADE,
  invite_token  TEXT        UNIQUE NOT NULL DEFAULT encode(gen_random_bytes(12),'hex'),
  label         TEXT,
  guest_user_id UUID        REFERENCES users(id) ON DELETE SET NULL,
  status        TEXT        NOT NULL DEFAULT 'pending'
                            CHECK (status IN ('pending','active','revoked')),
  claimed_at    TIMESTAMPTZ,
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
  CONSTRAINT one_target CHECK (
    (property_id IS NULL) <> (db_id IS NULL)
  )
);
ALTER TABLE guest_links ENABLE ROW LEVEL SECURITY;

CREATE INDEX IF NOT EXISTS idx_guest_links_owner  ON guest_links(owner_id);
CREATE INDEX IF NOT EXISTS idx_guest_links_guest  ON guest_links(guest_user_id)
  WHERE guest_user_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_guest_links_token  ON guest_links(invite_token);
CREATE INDEX IF NOT EXISTS idx_guest_links_status ON guest_links(status)
  WHERE status = 'active';

-- ── 4. RLS POLICIES — guest_links ─────────────────────────────────────────────
DROP POLICY IF EXISTS "glinks_owner_all"   ON guest_links;
DROP POLICY IF EXISTS "glinks_guest_read"  ON guest_links;
DROP POLICY IF EXISTS "glinks_service"     ON guest_links;

CREATE POLICY "glinks_owner_all" ON guest_links
  FOR ALL USING (owner_id = current_app_user_id());

CREATE POLICY "glinks_guest_read" ON guest_links
  FOR SELECT USING (
    guest_user_id = current_app_user_id()
    AND status = 'active'
  );

CREATE POLICY "glinks_service" ON guest_links
  FOR ALL TO service_role USING (true);

-- ── 5. RLS POLICIES — guest read access to properties/databases/photos/files ──

-- Helper: returns true if caller has an active guest_link targeting the property
-- (either directly by property_id, or via the property's db_id)
CREATE OR REPLACE FUNCTION is_guest_of_property(p_prop_id UUID)
RETURNS BOOLEAN LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT EXISTS (
    SELECT 1 FROM guest_links gl
    JOIN properties p ON p.id = p_prop_id
    WHERE gl.guest_user_id = current_app_user_id()
      AND gl.status = 'active'
      AND (
        gl.property_id = p_prop_id
        OR gl.db_id = p.db_id
      )
  );
$$;
REVOKE ALL ON FUNCTION is_guest_of_property(UUID) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION is_guest_of_property(UUID) TO authenticated;

-- databases — guest sees database if they have a db-level guest_link
DROP POLICY IF EXISTS "db_guest_select" ON databases;
CREATE POLICY "db_guest_select" ON databases
  FOR SELECT USING (
    EXISTS (
      SELECT 1 FROM guest_links gl
      WHERE gl.guest_user_id = current_app_user_id()
        AND gl.status = 'active'
        AND gl.db_id = databases.id
    )
  );

-- properties — guest sees property if they have property-level or db-level link
DROP POLICY IF EXISTS "props_guest_select" ON properties;
CREATE POLICY "props_guest_select" ON properties
  FOR SELECT USING (is_guest_of_property(id));

-- property_photos — same check
DROP POLICY IF EXISTS "photos_guest_select" ON property_photos;
CREATE POLICY "photos_guest_select" ON property_photos
  FOR SELECT USING (is_guest_of_property(property_id));

-- property_files — same check
DROP POLICY IF EXISTS "pfiles_select_guest" ON property_files;
CREATE POLICY "pfiles_select_guest" ON property_files
  FOR SELECT USING (is_guest_of_property(property_id));

-- rent_payments — guest can read schedule for their property
DROP POLICY IF EXISTS "rent_payments_guest_select" ON rent_payments;
CREATE POLICY "rent_payments_guest_select" ON rent_payments
  FOR SELECT USING (is_guest_of_property(property_id));

-- rent_payment_records — guest can see payment history for their property
DROP POLICY IF EXISTS "rent_records_guest_select" ON rent_payment_records;
CREATE POLICY "rent_records_guest_select" ON rent_payment_records
  FOR SELECT USING (is_guest_of_property(property_id));

-- ── 6. RPC: get_guest_property_preview ───────────────────────────────────────
-- Anonymous preview before claiming the link (mirrors get_public_db_preview).
CREATE OR REPLACE FUNCTION get_guest_property_preview(p_token TEXT)
RETURNS JSONB LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = public AS $$
DECLARE
  v_link RECORD;
  v_result JSONB;
BEGIN
  SELECT gl.property_id, gl.db_id, gl.status, gl.owner_id
  INTO v_link
  FROM guest_links gl
  WHERE gl.invite_token = p_token
  LIMIT 1;

  IF NOT FOUND OR v_link.status = 'revoked' THEN
    RETURN NULL;
  END IF;

  IF v_link.property_id IS NOT NULL THEN
    SELECT jsonb_build_object(
      'type',        'property',
      'status',      gl.status,
      'owner_first', u.first_name,
      'property', jsonb_build_object(
        'id',          p.id,
        'name',        p.name,
        'status',      p.status,
        'floor',       p.floor,
        'area_useful', p.area_useful,
        'area_total',  p.area_total,
        'description', p.description,
        'db_name',     d.name,
        'db_type',     d.type,
        'db_color',    d.color
      )
    )
    INTO v_result
    FROM guest_links gl
    JOIN properties p ON p.id = gl.property_id
    JOIN databases  d ON d.id = p.db_id
    JOIN users      u ON u.id = gl.owner_id
    WHERE gl.invite_token = p_token;
  ELSE
    SELECT jsonb_build_object(
      'type',        'database',
      'status',      gl.status,
      'owner_first', u.first_name,
      'database', jsonb_build_object(
        'id',    d.id,
        'name',  d.name,
        'type',  d.type,
        'color', d.color
      ),
      'properties', COALESCE((
        SELECT jsonb_agg(jsonb_build_object(
          'id',          p.id,
          'name',        p.name,
          'status',      p.status,
          'floor',       p.floor,
          'area_useful', p.area_useful,
          'area_total',  p.area_total
        ) ORDER BY p.sort_order, p.created_at)
        FROM properties p
        WHERE p.db_id = d.id
      ), '[]'::jsonb)
    )
    INTO v_result
    FROM guest_links gl
    JOIN databases d ON d.id = gl.db_id
    JOIN users     u ON u.id = gl.owner_id
    WHERE gl.invite_token = p_token;
  END IF;

  RETURN v_result;
END;
$$;
REVOKE ALL ON FUNCTION get_guest_property_preview(TEXT) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION get_guest_property_preview(TEXT) TO anon, authenticated, service_role;

-- ── 7. RPC: claim_guest_link ──────────────────────────────────────────────────
-- Called by an authenticated user to claim a pending invite.
-- Returns the target (property_id/db_id) so the client can navigate.
CREATE OR REPLACE FUNCTION claim_guest_link(p_token TEXT)
RETURNS JSONB LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE
  v_uid  UUID := current_app_user_id();
  v_link RECORD;
BEGIN
  IF v_uid IS NULL THEN
    RAISE EXCEPTION 'not authenticated';
  END IF;

  SELECT id, property_id, db_id, guest_user_id, status
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

-- ── 8. RPC: get_due_guest_reminders ──────────────────────────────────────────
-- Mirrors get_due_reminders_today but returns guest recipients.
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
  SELECT
    u.id,
    u.tg_id,
    rp.property_id,
    p.name,
    rp.due_day::INT,
    make_date(
      EXTRACT(YEAR  FROM (v_today + rp.notify_days_before * INTERVAL '1 day'))::INT,
      EXTRACT(MONTH FROM (v_today + rp.notify_days_before * INTERVAL '1 day'))::INT,
      rp.due_day
    )
  FROM rent_payments rp
  JOIN properties p ON p.id = rp.property_id
  -- Find active guest links targeting this property (directly or via db)
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
    );
END;
$$;
REVOKE ALL ON FUNCTION get_due_guest_reminders() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION get_due_guest_reminders() TO service_role;

-- ── 9. SCHEMA CACHE RELOAD ────────────────────────────────────────────────────
NOTIFY pgrst, 'reload schema';

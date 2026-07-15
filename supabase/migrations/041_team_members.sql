-- ============================================================================
-- 041_team_members.sql — «Команда бази»: запрошені редактори з правом запису.
-- Idempotent. Через migrate.yml (після baseline) або Dashboard → SQL Editor.
--
-- Модель: db_members — інвайт-рядки за перевіреним зразком guest_links
-- (invite_token / label / pending→active / claim-RPC). Роль 'editor' дає
-- ПОВНИЙ CRUD по об'єктах, фото, файлах і платежах бази. Власницькі політики
-- НЕ ЧІПАЮТЬСЯ — редакторські додаються паралельно (permissive OR), і кожен
-- WITH CHECK примушує owner_id рядків = власник БАЗИ, тож редактор не може
-- «привласнити» дані чи підкинути рядок із чужим owner_id.
--
-- Свідомо owner-only лишаються: керування шарингом/гостями/командою,
-- редагування та видалення самої бази, аналітика переглядів.
-- На відміну від гостей, claim НЕ змінює users.role.
-- ============================================================================

-- ── 1. Таблиця ────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS db_members (
  id           UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
  db_id        UUID        NOT NULL REFERENCES databases(id) ON DELETE CASCADE,
  user_id      UUID        REFERENCES users(id) ON DELETE CASCADE,
  role         TEXT        NOT NULL DEFAULT 'editor' CHECK (role IN ('editor')),
  invite_token TEXT        UNIQUE NOT NULL DEFAULT encode(gen_random_bytes(12),'hex'),
  label        TEXT,
  -- Ім'я члена копіюється при клеймі (SECURITY DEFINER має доступ), бо RLS на
  -- users дозволяє читати лише власний рядок — власник інакше не побачив би,
  -- ХТО прийняв інвайт.
  member_name  TEXT,
  status       TEXT        NOT NULL DEFAULT 'pending'
                           CHECK (status IN ('pending','active','revoked')),
  claimed_at   TIMESTAMPTZ,
  created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);
ALTER TABLE db_members ENABLE ROW LEVEL SECURITY;

CREATE INDEX IF NOT EXISTS idx_db_members_db   ON db_members (db_id);
CREATE INDEX IF NOT EXISTS idx_db_members_user ON db_members (user_id) WHERE status = 'active';
-- Один активний запис на людину в базі (pending-рядки з NULL user_id не заважають)
CREATE UNIQUE INDEX IF NOT EXISTS uq_db_members_db_user
  ON db_members (db_id, user_id) WHERE user_id IS NOT NULL;

-- ── 2. Хелпери (SECURITY DEFINER — той самий патерн, що get_owner_db_ids) ────
CREATE OR REPLACE FUNCTION get_editor_db_ids(p_uid UUID)
RETURNS SETOF UUID LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT db_id FROM db_members
  WHERE user_id = p_uid AND status = 'active' AND role = 'editor';
$$;

CREATE OR REPLACE FUNCTION get_editor_property_ids(p_uid UUID)
RETURNS SETOF UUID LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT p.id FROM properties p
  WHERE p.db_id IN (SELECT get_editor_db_ids(p_uid));
$$;

-- Для storage-політик: current_app_user_id() ненадійний у storage-контексті
-- (урок 030/038) — резолвимо через auth.uid(), як get_app_user_id_from_auth_uid.
CREATE OR REPLACE FUNCTION get_editor_db_ids_from_auth_uid()
RETURNS SETOF UUID LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT m.db_id
  FROM db_members m
  JOIN public.users u ON u.id = m.user_id
  JOIN auth.users au ON SPLIT_PART(au.email, '@', 1) = u.tg_id::text
  WHERE au.id = auth.uid() AND m.status = 'active' AND m.role = 'editor';
$$;

-- ── 3. RLS db_members ─────────────────────────────────────────────────────────
DROP POLICY IF EXISTS "members_owner_all"  ON db_members;
DROP POLICY IF EXISTS "members_self_select" ON db_members;

-- Власник бази керує інвайтами/членами своєї бази
CREATE POLICY "members_owner_all" ON db_members
  FOR ALL
  USING     (db_id IN (SELECT get_owner_db_ids(current_app_user_id())))
  WITH CHECK (db_id IN (SELECT get_owner_db_ids(current_app_user_id())));

-- Член бачить власний запис (клієнту треба знати свої membership-и)
CREATE POLICY "members_self_select" ON db_members
  FOR SELECT USING (user_id = current_app_user_id());

-- ── 4. Редакторські політики (додаткові, паралельні власницьким) ─────────────
DROP POLICY IF EXISTS "db_editor_select"        ON databases;
DROP POLICY IF EXISTS "props_editor_all"        ON properties;
DROP POLICY IF EXISTS "photos_editor_all"       ON property_photos;
DROP POLICY IF EXISTS "pfiles_editor_select"    ON property_files;
DROP POLICY IF EXISTS "pfiles_editor_insert"    ON property_files;
DROP POLICY IF EXISTS "pfiles_editor_update"    ON property_files;
DROP POLICY IF EXISTS "pfiles_editor_delete"    ON property_files;
DROP POLICY IF EXISTS "rent_payments_editor_all" ON rent_payments;
DROP POLICY IF EXISTS "rent_records_editor_all"  ON rent_payment_records;

CREATE POLICY "db_editor_select" ON databases
  FOR SELECT USING (id IN (SELECT get_editor_db_ids(current_app_user_id())));

-- Об'єкти: повний CRUD у межах бази; нові/оновлені рядки МУСЯТЬ належати
-- власнику бази (owner_id перевіряється проти databases.owner_id).
CREATE POLICY "props_editor_all" ON properties
  FOR ALL
  USING (db_id IN (SELECT get_editor_db_ids(current_app_user_id())))
  WITH CHECK (
    db_id IN (SELECT get_editor_db_ids(current_app_user_id()))
    AND owner_id = (SELECT d.owner_id FROM databases d WHERE d.id = db_id)
  );

CREATE POLICY "photos_editor_all" ON property_photos
  FOR ALL
  USING     (property_id IN (SELECT get_editor_property_ids(current_app_user_id())))
  WITH CHECK (property_id IN (SELECT get_editor_property_ids(current_app_user_id())));

CREATE POLICY "pfiles_editor_select" ON property_files
  FOR SELECT USING (property_id IN (SELECT get_editor_property_ids(current_app_user_id())));
CREATE POLICY "pfiles_editor_insert" ON property_files
  FOR INSERT WITH CHECK (
    property_id IN (SELECT get_editor_property_ids(current_app_user_id()))
    AND owner_id = (SELECT p.owner_id FROM properties p WHERE p.id = property_id)
  );
CREATE POLICY "pfiles_editor_update" ON property_files
  FOR UPDATE
  USING (property_id IN (SELECT get_editor_property_ids(current_app_user_id())))
  WITH CHECK (
    property_id IN (SELECT get_editor_property_ids(current_app_user_id()))
    AND owner_id = (SELECT p.owner_id FROM properties p WHERE p.id = property_id)
  );
CREATE POLICY "pfiles_editor_delete" ON property_files
  FOR DELETE USING (property_id IN (SELECT get_editor_property_ids(current_app_user_id())));

CREATE POLICY "rent_payments_editor_all" ON rent_payments
  FOR ALL
  USING (property_id IN (SELECT get_editor_property_ids(current_app_user_id())))
  WITH CHECK (
    property_id IN (SELECT get_editor_property_ids(current_app_user_id()))
    AND owner_id = (SELECT p.owner_id FROM properties p WHERE p.id = property_id)
  );

CREATE POLICY "rent_records_editor_all" ON rent_payment_records
  FOR ALL
  USING (property_id IN (SELECT get_editor_property_ids(current_app_user_id())))
  WITH CHECK (
    property_id IN (SELECT get_editor_property_ids(current_app_user_id()))
    AND owner_id = (SELECT p.owner_id FROM properties p WHERE p.id = property_id)
  );

-- ── 5. Storage (bucket photos): редактор пише/видаляє у своїх базах ──────────
DROP POLICY IF EXISTS "storage_photos_editor_insert" ON storage.objects;
DROP POLICY IF EXISTS "storage_photos_editor_delete" ON storage.objects;

CREATE POLICY "storage_photos_editor_insert" ON storage.objects
  FOR INSERT TO authenticated
  WITH CHECK (
    bucket_id = 'photos'
    AND SPLIT_PART(name, '/', 1) IN (
      SELECT p.id::text FROM public.properties p
      WHERE p.db_id IN (SELECT public.get_editor_db_ids_from_auth_uid())
    )
  );

CREATE POLICY "storage_photos_editor_delete" ON storage.objects
  FOR DELETE TO authenticated
  USING (
    bucket_id = 'photos'
    AND SPLIT_PART(name, '/', 1) IN (
      SELECT p.id::text FROM public.properties p
      WHERE p.db_id IN (SELECT public.get_editor_db_ids_from_auth_uid())
    )
  );

-- ── 6. Клейм інвайта (дзеркало claim_guest_link; users.role НЕ чіпається) ────
CREATE OR REPLACE FUNCTION claim_team_invite(p_token TEXT)
RETURNS JSONB LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE
  v_uid    UUID := current_app_user_id();
  v_row    RECORD;
  v_name   TEXT;
  v_owner  UUID;
BEGIN
  IF v_uid IS NULL THEN
    RAISE EXCEPTION 'not authenticated';
  END IF;

  SELECT m.id, m.db_id, m.user_id, m.status INTO v_row
  FROM db_members m
  WHERE m.invite_token = p_token
  FOR UPDATE;

  IF NOT FOUND THEN
    RETURN jsonb_build_object('error', 'not_found');
  END IF;

  IF v_row.status = 'revoked' THEN
    RETURN jsonb_build_object('error', 'revoked');
  END IF;

  SELECT d.owner_id INTO v_owner FROM databases d WHERE d.id = v_row.db_id;
  IF v_uid = v_owner THEN
    RETURN jsonb_build_object('error', 'cannot_claim_own_link');
  END IF;

  -- Ідемпотентність: повторний клейм тим самим користувачем — успіх
  IF v_row.status = 'active' AND v_row.user_id = v_uid THEN
    RETURN jsonb_build_object('db_id', v_row.db_id);
  END IF;
  IF v_row.status = 'active' AND v_row.user_id IS DISTINCT FROM v_uid THEN
    RETURN jsonb_build_object('error', 'already_claimed');
  END IF;

  -- Людина вже в команді цієї бази іншим інвайтом → успіх без дубля
  IF EXISTS (SELECT 1 FROM db_members
             WHERE db_id = v_row.db_id AND user_id = v_uid AND status = 'active') THEN
    UPDATE db_members SET status = 'revoked' WHERE id = v_row.id AND status = 'pending';
    RETURN jsonb_build_object('db_id', v_row.db_id);
  END IF;

  SELECT trim(concat(u.first_name, ' ', coalesce(u.last_name, ''))) INTO v_name
  FROM users u WHERE u.id = v_uid;

  UPDATE db_members
  SET user_id = v_uid, status = 'active', claimed_at = now(), member_name = v_name
  WHERE id = v_row.id;

  RETURN jsonb_build_object('db_id', v_row.db_id);
END;
$$;
REVOKE ALL ON FUNCTION claim_team_invite(TEXT) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION claim_team_invite(TEXT) TO authenticated, service_role;

-- ── Schema cache reload ──────────────────────────────────────────────────────
NOTIFY pgrst, 'reload schema';

-- ── Diagnostics ──────────────────────────────────────────────────────────────
SELECT '════ db_members створена з RLS ════' AS check;
SELECT relrowsecurity FROM pg_class WHERE relname = 'db_members';

SELECT '════ редакторські політики (має бути 9+2 storage) ════' AS check;
SELECT tablename, policyname FROM pg_policies
WHERE policyname LIKE '%editor%' ORDER BY tablename, policyname;

SELECT '════ claim_team_invite існує ════' AS check;
SELECT proname FROM pg_proc WHERE proname = 'claim_team_invite';

SELECT '════ DONE — 041 team members applied ════' AS result;

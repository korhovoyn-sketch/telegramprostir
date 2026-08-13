-- 046: гостьовий лінк мусить вказувати на ВЛАСНУ базу/обʼєкт
--
-- ПРОБЛЕМА (знайдено аудитом коду; у проді не перевірялось — з робочого
-- середовища немає мережі до Supabase).
--
-- `027_guest_role.sql` дав guest_links політику:
--
--     CREATE POLICY "glinks_owner_all" ON guest_links
--       FOR ALL USING (owner_id = current_app_user_id());
--
-- Для FOR ALL без явного WITH CHECK Postgres перевіряє запис тим самим USING,
-- тобто єдина вимога — «постав ВЛАСНИКОМ ЛІНКА СЕБЕ». Те, що `db_id` чи
-- `property_id` вказують на ЧУЖУ базу, не перевіряється ніде.
--
-- Порівняй із db_members (041), де ця ж думка виражена правильно:
--     USING/WITH CHECK (db_id IN (SELECT get_owner_db_ids(current_app_user_id())))
--
-- ЛАНЦЮГ ЕКСПЛУАТАЦІЇ:
--   1. Зловмисник вставляє guest_links{ owner_id: self, db_id: <база жертви> } —
--      політика пропускає.
--   2. Будь-хто (друга сесія зловмисника) клеймить лінк: claim_guest_link ставить
--      guest_user_id.
--   3. `is_guest_of_property()` бачить активний лінк із db_id жертви й повертає
--      TRUE — а на ній стоять db_guest_select / props_guest_select /
--      photos_guest_select / pfiles_select_guest / rent_*_guest_select.
--   Результат: читання всієї бази жертви.
--
-- ФІКС ДВОШАРОВИЙ, і обидва шари потрібні:
--   (1) політика більше не дає СТВОРИТИ такий рядок;
--   (2) `is_guest_of_property()` більше не ВИЗНАЄ такий рядок, навіть якщо він
--       уже лежить у таблиці. Без другого шару вже посаджені рядки працювали б
--       далі — міграція, що лікує лише запис, не лікує вже завдану шкоду.

-- ── 1. Запис: ціль мусить належати власнику лінка ────────────────────────────

DROP POLICY IF EXISTS "glinks_owner_all" ON guest_links;

CREATE POLICY "glinks_owner_all" ON guest_links
  FOR ALL
  USING (owner_id = current_app_user_id())
  WITH CHECK (
    owner_id = current_app_user_id()
    -- db-лінк: база моя
    AND (
      db_id IS NULL
      OR db_id IN (SELECT get_owner_db_ids(current_app_user_id()))
    )
    -- property-лінк: обʼєкт лежить у моїй базі
    AND (
      property_id IS NULL
      OR property_id IN (
        SELECT p.id FROM properties p
        WHERE p.db_id IN (SELECT get_owner_db_ids(current_app_user_id()))
      )
    )
  );

-- ── 2. Читання: лінк діє, лише якщо його автор — справжній власник цілі ──────
--
-- Та сама умова, але з боку СПОЖИВАННЯ. Тепер підроблений рядок нічого не дає
-- навіть після клейму: `gl.owner_id` мусить збігтися з власником бази обʼєкта.
CREATE OR REPLACE FUNCTION is_guest_of_property(p_prop_id UUID)
RETURNS BOOLEAN LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT EXISTS (
    SELECT 1
    FROM guest_links gl
    JOIN properties p ON p.id = p_prop_id
    JOIN databases  d ON d.id = p.db_id
    WHERE gl.guest_user_id = current_app_user_id()
      AND gl.status = 'active'
      AND (gl.property_id = p_prop_id OR gl.db_id = p.db_id)
      -- Лінк дійсний лише від справжнього власника цілі.
      AND gl.owner_id = d.owner_id
  );
$$;
REVOKE ALL ON FUNCTION is_guest_of_property(UUID) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION is_guest_of_property(UUID) TO authenticated;

-- ── 3. Верифікація ───────────────────────────────────────────────────────────
-- Має показати політику з непорожнім WITH CHECK і функцію з перевіркою власника.
SELECT
  (SELECT COUNT(*) FROM pg_policies
    WHERE tablename = 'guest_links' AND policyname = 'glinks_owner_all'
      AND with_check IS NOT NULL)                                    AS policy_has_with_check,
  (SELECT COUNT(*) FROM pg_proc
    WHERE proname = 'is_guest_of_property'
      AND prosrc LIKE '%gl.owner_id = d.owner_id%')                  AS predicate_checks_owner;

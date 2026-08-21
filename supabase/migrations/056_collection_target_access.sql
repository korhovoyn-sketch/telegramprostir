-- ============================================================================
-- 056 — рієлтор публікував ЧУЖИЙ обʼєкт у власній підбірці
-- ============================================================================
-- ЦЕ ВИПРАВЛЕННЯ МОЄЇ Ж ПОМИЛКОВОЇ «СПРОСТОВАНОЇ ГІПОТЕЗИ».
-- У 053 записано, що цей клас на `collection_properties` перевірено і
-- публічної поверхні він не має. Замір був НЕВАЛІДНИЙ: тестова підбірка
-- створювалась без `is_draft`, а дефолт цієї колонки — TRUE, тоді як
-- `get_public_collection_preview` має `AND c.is_draft = false`. Тобто нуль
-- рядків пояснювався ЧЕРНЕТКОЮ, а не фільтрацією чужого обʼєкта.
--
-- Повторний замір на ОПУБЛІКОВАНІЙ підбірці гіпотезу ПІДТВЕРДИВ:
--   рядків у підбірці: 1
--   ПУБЛІЧНА підбірка Клима показує: ТАЄМНИЙ ОБʼЄКТ ЖЕРТВИ
--
-- ── ЩО ЦЕ ДАЄ ──────────────────────────────────────────────────────────────
-- `col_props_realtor_all` перевіряє лише «підбірка моя?», не питаючи, чи є в
-- мене доступ до ОБʼЄКТА. Тож будь-який рієлтор вставляє чужий `property_id`
-- у свою підбірку, публікує її — і `get_public_collection_preview`
-- (SECURITY DEFINER, тобто повз RLS) віддає назву, площу, ціну, опис і ФОТО
-- чужого обʼєкта анонімам, ще й поруч із контактами ЦЬОГО рієлтора, тобто з
-- хибним авторством.
--
-- UUID вгадувати не треба: `get_public_db_preview(token)` віддає `property_id`
-- кожного обʼєкта бази. Тобто досить одного шер-лінка жертви.
--
-- Той самий клас, що 046 (guest_links) і 053 (properties): політика перевіряє
-- ВЛАСНИКА рядка, але не те, що ЦІЛЬ доступна. Виправляємо ОБИДВА боки —
-- інакше вже посаджені рядки продовжують світитись (урок 046).
--
-- КОНТРАКТ ФУНКЦІЇ НЕ МІНЯЄТЬСЯ: ті самі 24 колонки в тому ж порядку —
-- додається рівно один предикат у JOIN. Це прямий урок 050, де перейменовані
-- ключі зламали б гостьовий екран.
-- ============================================================================

-- ── 1. ЗАПИС: ціль мусить бути доступна рієлтору ───────────────────────────
DROP POLICY IF EXISTS col_props_realtor_all ON collection_properties;
CREATE POLICY col_props_realtor_all ON collection_properties FOR ALL
  USING (collection_id IN (SELECT get_realtor_collection_ids(current_app_user_id())))
  WITH CHECK (
    collection_id IN (SELECT get_realtor_collection_ids(current_app_user_id()))
    AND (
      -- обʼєкт із бази, на яку рієлтор підписаний…
      property_id IN (SELECT get_realtor_property_ids(current_app_user_id()))
      -- …або власний обʼєкт (акаунт може бути і власником, і рієлтором)
      OR property_id IN (SELECT get_owner_property_ids(current_app_user_id()))
    )
  );

-- ── 2. ЧИТАННЯ: уже посаджені рядки перестають світитись ───────────────────
CREATE OR REPLACE FUNCTION get_public_collection_preview(p_token TEXT)
RETURNS TABLE (
  collection_id UUID, collection_name TEXT, share_expires_at TIMESTAMPTZ,
  realtor_first_name TEXT, realtor_last_name TEXT, realtor_tg_username TEXT, realtor_phone TEXT,
  property_id UUID, property_name TEXT, property_status TEXT, property_floor TEXT,
  property_area_useful DOUBLE PRECISION, property_area_total DOUBLE PRECISION,
  property_area_basis TEXT, property_rent_type TEXT, property_rent_rate DOUBLE PRECISION,
  property_sale_price DOUBLE PRECISION, property_description TEXT, owner_currency TEXT,
  db_id UUID, db_name TEXT, db_type TEXT, db_color TEXT, first_photo TEXT
)
LANGUAGE sql
STABLE SECURITY DEFINER
SET search_path = public
AS $$
  SELECT c.id, c.name, c.share_expires_at,
         r.first_name, r.last_name, r.tg_username, r.phone,
         p.id, p.name, p.status, p.floor,
         p.area_useful, p.area_total, COALESCE(p.area_basis, 'total'),
         p.rent_type, p.rent_rate, p.sale_price,
         p.description, po.currency,
         d.id, d.name, d.type, d.color,
         (SELECT ph.storage_path FROM property_photos ph
          WHERE ph.property_id = p.id ORDER BY ph.sort_order, ph.created_at LIMIT 1)
  FROM collections c
  JOIN users r ON r.id = c.realtor_id
  LEFT JOIN collection_properties cp ON cp.collection_id = c.id
  -- 056: показуємо обʼєкт, ЛИШЕ якщо рієлтор досі має до нього доступ —
  -- власний, або через активну підписку на його базу. Це друга половина
  -- фікса: без неї рядки, посаджені до 056, світились би далі.
  LEFT JOIN properties p ON p.id = cp.property_id
    AND (
      p.owner_id = c.realtor_id
      OR EXISTS (
        SELECT 1 FROM realtor_subscriptions rs
        WHERE rs.realtor_id = c.realtor_id AND rs.db_id = p.db_id
      )
    )
  LEFT JOIN databases  d ON d.id = p.db_id
  LEFT JOIN users     po ON po.id = p.owner_id
  WHERE c.share_token = p_token
    AND c.is_draft = false
    AND (c.share_expires_at IS NULL OR c.share_expires_at > now())
  ORDER BY cp.added_at;
$$;

REVOKE ALL ON FUNCTION get_public_collection_preview(TEXT) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION get_public_collection_preview(TEXT) TO anon, authenticated, service_role;

NOTIFY pgrst, 'reload schema';

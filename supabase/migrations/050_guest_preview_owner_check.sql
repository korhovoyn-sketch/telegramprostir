-- ═══════════════════════════════════════════════════════════════════════════
-- 050: доробки після наскрізного код-рев'ю
--   1. get_guest_property_preview — третій, пропущений 046 споживач
--   2. get_public_collection_preview — база розрахунку площі
-- ═══════════════════════════════════════════════════════════════════════════

-- ── 1. Залишкова експозиція гостьових лінків ────────────────────────────────
--
-- 046 закрила діру З ДВОХ БОКІВ — і запис (політика `guest_links`), і читання
-- (`is_guest_of_property`), бо «вже посаджені рядки продовжували б діяти».
-- Але споживачів читання виявилось ТРИ: `get_guest_property_preview` —
-- SECURITY DEFINER, виданий `anon` — джойнить guest_links → databases БЕЗ
-- перевірки, що лінк створив саме власник цілі.
--
-- Наслідок для рядка, посадженого ДО 046 (`owner_id` зловмисника, `db_id`
-- жертви): анонімний виклик із токеном і досі віддає повний список обʼєктів
-- жертви. Нові такі рядки вже неможливі (`WITH CHECK` з 046), тож це саме
-- залишок, а не відкритий вектор.
CREATE OR REPLACE FUNCTION get_guest_property_preview(p_token TEXT)
RETURNS JSONB LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = public AS $$
DECLARE
  v_link RECORD;
  v_out  JSONB;
BEGIN
  SELECT gl.id, gl.property_id, gl.db_id, gl.status, gl.owner_id, gl.label
  INTO v_link
  FROM guest_links gl
  WHERE gl.invite_token = p_token;

  IF NOT FOUND OR v_link.status = 'revoked' THEN
    RETURN NULL;
  END IF;

  -- ЦІЛЬ МУСИТЬ НАЛЕЖАТИ ТОМУ, ХТО ВИДАВ ЛІНК. Той самий предикат, що 046
  -- додала в `is_guest_of_property`; тут його бракувало.
  IF v_link.property_id IS NOT NULL THEN
    SELECT jsonb_build_object(
      'kind', 'property',
      'label', v_link.label,
      'property', jsonb_build_object(
        'id', p.id, 'name', p.name, 'status', p.status, 'floor', p.floor,
        'area_useful', p.area_useful, 'area_total', p.area_total
      ),
      'db', jsonb_build_object('id', d.id, 'name', d.name, 'type', d.type, 'color', d.color)
    )
    INTO v_out
    FROM properties p
    JOIN databases d ON d.id = p.db_id
    WHERE p.id = v_link.property_id
      AND d.owner_id = v_link.owner_id;   -- ← перевірка власності цілі
  ELSE
    SELECT jsonb_build_object(
      'kind', 'db',
      'label', v_link.label,
      'db', jsonb_build_object('id', d.id, 'name', d.name, 'type', d.type, 'color', d.color),
      'properties', COALESCE((
        SELECT jsonb_agg(jsonb_build_object(
          'id', p.id, 'name', p.name, 'status', p.status, 'floor', p.floor,
          'area_useful', p.area_useful, 'area_total', p.area_total
        ) ORDER BY p.sort_order, p.created_at)
        FROM properties p WHERE p.db_id = d.id
      ), '[]'::jsonb)
    )
    INTO v_out
    FROM databases d
    WHERE d.id = v_link.db_id
      AND d.owner_id = v_link.owner_id;   -- ← перевірка власності цілі
  END IF;

  RETURN v_out;   -- NULL, якщо ціль не належить видавцеві лінка
END;
$$;
REVOKE ALL ON FUNCTION get_guest_property_preview(TEXT) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION get_guest_property_preview(TEXT) TO anon, authenticated, service_role;

-- ── 2. Аудит рядків, посаджених ДО 046 ──────────────────────────────────────
-- Має показати 0. Ненульовий результат = у базі лежать лінки, чия ціль НЕ
-- належить їхньому власнику; після цієї міграції вони мертві, але їх варто
-- побачити й видалити вручну.
SELECT count(*) AS mismatched_guest_links
FROM guest_links gl
LEFT JOIN databases  d  ON d.id  = gl.db_id
LEFT JOIN properties p  ON p.id  = gl.property_id
LEFT JOIN databases  pd ON pd.id = p.db_id
WHERE gl.owner_id <> COALESCE(d.owner_id, pd.owner_id);

-- ── 3. База розрахунку площі в публічній підбірці ───────────────────────────
--
-- `get_public_collection_preview` не віддавала `area_basis`, тож клієнт
-- фолбечився на розрахункову площу. Для обʼєкта з базою «корисна» (50 м²
-- корисної проти 100 розрахункової) картка в застосунку каже $900, а спільна
-- підбірка — $1 800. Той самий клас, який для валюти закрила 040.
--
-- Тип результату міняється, тож потрібен DROP: `CREATE OR REPLACE` не змінює
-- сигнатуру наявної функції (42P13) — та сама пастка, що в 042 і 044.
DROP FUNCTION IF EXISTS get_public_collection_preview(TEXT);

CREATE FUNCTION get_public_collection_preview(p_token TEXT)
RETURNS TABLE (
  collection_id UUID, collection_name TEXT, share_expires_at TIMESTAMPTZ,
  realtor_first_name TEXT, realtor_last_name TEXT,
  realtor_tg_username TEXT, realtor_phone TEXT,
  property_id UUID, property_name TEXT, property_status TEXT, property_floor TEXT,
  property_area_useful FLOAT, property_area_total FLOAT, property_area_basis TEXT,
  property_rent_type TEXT, property_rent_rate FLOAT, property_sale_price FLOAT,
  property_description TEXT, owner_currency TEXT,
  db_id UUID, db_name TEXT, db_type TEXT, db_color TEXT, first_photo TEXT
)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
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
  LEFT JOIN properties p ON p.id = cp.property_id
  LEFT JOIN databases  d ON d.id = p.db_id
  LEFT JOIN users     po ON po.id = p.owner_id
  WHERE c.share_token = p_token
    AND c.is_draft = false
    AND (c.share_expires_at IS NULL OR c.share_expires_at > now())
  ORDER BY cp.created_at;
$$;
REVOKE ALL ON FUNCTION get_public_collection_preview(TEXT) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION get_public_collection_preview(TEXT) TO anon, authenticated, service_role;

NOTIFY pgrst, 'reload schema';

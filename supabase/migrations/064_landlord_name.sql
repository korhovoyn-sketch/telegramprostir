-- 064: ОРЕНДОДАВЕЦЬ — той, хто здає.
--
-- У моделі досі було двоє: `tenant_name` (орендар — хто знімає) і `owner_id`
-- (акаунт у застосунку). Того, хто ЗДАЄ, не було ніде — і для власника з
-- однією юрособою це збігалось із ним самим, тож не заважало. Щойно базою
-- керує агенція або приміщення розділені між кількома юрособами, документ
-- перестає відповідати, ХТО саме здає конкретний офіс.
--
-- УСПАДКУВАННЯ ЧЕРЕЗ NULL. Орендодавець задається на БАЗІ (дефолт на всі
-- обʼєкти) і за потреби перевизначається на ОБʼЄКТІ. `properties.landlord_name
-- IS NULL` означає «як у базі», а не «немає»: стан «у цього простору
-- орендодавця немає, хоч у бази є» для назви беззмістовний, а моделювати його
-- довелось би sentinel-значенням або окремим булеаном — ціна без користі.
--
-- Обидві колонки nullable і без DEFAULT — рівно як `tenant_name` у 023.

ALTER TABLE databases  ADD COLUMN IF NOT EXISTS landlord_name VARCHAR(200);
ALTER TABLE properties ADD COLUMN IF NOT EXISTS landlord_name VARCHAR(200);

-- ── Публічні превʼю ─────────────────────────────────────────────────────────
-- Три функції віддають нову колонку ОСТАННЬОЮ, решта лишається на місці, того
-- ж типу й у тому ж порядку. Це не педантизм: 050 перейменувала ключі в
-- гостьовому превʼю, і перший екран, який бачить запрошена людина, показав
-- сірий безіменний тайл. Тіла нижче взяті з `pg_get_functiondef` зібраної БД,
-- а не переписані з памʼяті — з тієї ж причини.
--
-- Значення вже ЗЛИТЕ: клієнту публічної сторінки нема з чим його зливати, бо
-- рядка бази він окремо не отримує.
--
-- Зміна типу результату вимагає DROP + CREATE — `CREATE OR REPLACE` на це не
-- здатна (42P13).

DROP FUNCTION IF EXISTS get_public_property_preview(TEXT);
CREATE FUNCTION get_public_property_preview(p_token TEXT)
RETURNS TABLE(
  property_id uuid, property_name text, property_status text, property_floor text,
  property_area_useful double precision, property_area_total double precision,
  property_area_basis text, property_rent_type text, property_rent_rate double precision,
  property_utilities_rate double precision, property_description text, property_address text,
  property_has_parking boolean, property_parking_spaces integer, property_parking_type text,
  property_ev_charger boolean, property_sale_price double precision,
  share_expires_at timestamptz, db_id uuid, db_name text, db_type text, db_color text,
  owner_first_name text, owner_last_name text, owner_tg_username text, owner_phone text,
  owner_currency text, photos text[],
  property_landlord_name text
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
    u.first_name, u.last_name, u.tg_username,
    CASE WHEN u.public_phone THEN u.phone ELSE NULL END,   -- 061
    u.currency,
    ARRAY(
      SELECT ph.storage_path FROM property_photos ph
      WHERE ph.property_id = p.id
      ORDER BY ph.sort_order
    ),
    COALESCE(p.landlord_name, d.landlord_name)::TEXT       -- 064
  FROM properties p
  JOIN databases d ON d.id = p.db_id
  JOIN users u ON u.id = p.owner_id
  WHERE p.share_token = p_token
    AND (p.share_expires_at IS NULL OR p.share_expires_at > now())
  LIMIT 1;
$$;
REVOKE ALL ON FUNCTION get_public_property_preview(TEXT) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION get_public_property_preview(TEXT) TO anon, authenticated, service_role;

DROP FUNCTION IF EXISTS get_public_db_preview(TEXT);
CREATE FUNCTION get_public_db_preview(p_token TEXT)
RETURNS TABLE(
  db_id uuid, db_name text, db_type text, db_color text, share_expires_at timestamptz,
  property_id uuid, property_name text, property_status text, property_floor text,
  property_area_useful double precision, property_area_total double precision,
  property_rent_type text, property_rent_rate double precision,
  property_sale_price double precision, property_description text,
  owner_first_name text, owner_last_name text, owner_tg_username text, owner_phone text,
  owner_currency text, first_photo text,
  property_landlord_name text
)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT d.id, d.name, d.type, d.color, d.share_expires_at,
         p.id, p.name, p.status, p.floor,
         p.area_useful, p.area_total,
         p.rent_type, p.rent_rate, p.sale_price, p.description,
         o.first_name, o.last_name, o.tg_username,
         CASE WHEN o.public_phone THEN o.phone ELSE NULL END,   -- 061
         o.currency,
         (SELECT ph.storage_path FROM property_photos ph
          WHERE ph.property_id = p.id ORDER BY ph.sort_order, ph.created_at LIMIT 1),
         COALESCE(p.landlord_name, d.landlord_name)::TEXT       -- 064
  FROM databases d
  JOIN users o ON o.id = d.owner_id
  LEFT JOIN properties p ON p.db_id = d.id
  WHERE d.share_token = p_token
    AND (d.share_expires_at IS NULL OR d.share_expires_at > now())
  ORDER BY p.sort_order, p.created_at;
$$;
REVOKE ALL ON FUNCTION get_public_db_preview(TEXT) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION get_public_db_preview(TEXT) TO anon, authenticated, service_role;

DROP FUNCTION IF EXISTS get_public_collection_preview(TEXT);
CREATE FUNCTION get_public_collection_preview(p_token TEXT)
RETURNS TABLE(
  collection_id uuid, collection_name text, share_expires_at timestamptz,
  realtor_first_name text, realtor_last_name text, realtor_tg_username text, realtor_phone text,
  property_id uuid, property_name text, property_status text, property_floor text,
  property_area_useful double precision, property_area_total double precision,
  property_area_basis text, property_rent_type text, property_rent_rate double precision,
  property_sale_price double precision, property_description text, owner_currency text,
  db_id uuid, db_name text, db_type text, db_color text, first_photo text,
  property_landlord_name text
)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT c.id, c.name, c.share_expires_at,
         r.first_name, r.last_name, r.tg_username,
         CASE WHEN r.public_phone THEN r.phone ELSE NULL END,   -- 061
         p.id, p.name, p.status, p.floor,
         p.area_useful, p.area_total, COALESCE(p.area_basis, 'total'),
         p.rent_type, p.rent_rate, p.sale_price,
         p.description, po.currency,
         d.id, d.name, d.type, d.color,
         (SELECT ph.storage_path FROM property_photos ph
          WHERE ph.property_id = p.id ORDER BY ph.sort_order, ph.created_at LIMIT 1),
         COALESCE(p.landlord_name, d.landlord_name)::TEXT       -- 064
  FROM collections c
  JOIN users r ON r.id = c.realtor_id
  LEFT JOIN collection_properties cp ON cp.collection_id = c.id
  -- 056: показуємо обʼєкт, ЛИШЕ якщо рієлтор досі має до нього доступ —
  -- власний, або через активну підписку на його базу.
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

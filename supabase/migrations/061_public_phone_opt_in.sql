-- ============================================================================
-- 061 — телефон власника на публічній /v стає ОПЦІЄЮ, а не типовим станом
-- ============================================================================
-- Заміряно під час аудиту архітектури: усі три публічні превʼю віддають
-- `owner_phone` кожному, хто має шер-лінк. Разом із тим, що токен не має
-- терміну дії за замовчуванням, це означало просту річ: **людина, якій ви
-- одного разу надіслали посилання, тримає ваш номер телефону назавжди** — і
-- може передати лінк далі.
--
-- Це не діра в контролі доступу: превʼю віддає рівно те, що задумано віддавати
-- власнику лінка. Це надлишок ЗА ЗАМОВЧУВАННЯМ — контакт потрібен, щоб глядач
-- звʼязався, але в застосунку вже є рідний для Telegram канал
-- (`owner_tg_username`), який не розкриває номер.
--
-- Тому: `users.public_phone` DEFAULT **false**, і всі три превʼю віддають
-- `owner_phone` ЛИШЕ коли власник свідомо його увімкнув. Приватність за
-- замовчуванням, а не як налаштування, яке треба знайти.
--
-- КОНТРАКТ НЕ ЗМІНЮЄТЬСЯ: колонка `owner_phone` лишається на місці, у тому ж
-- порядку, того ж типу — просто приходить NULL, коли опція вимкнена. Клієнт
-- уже вміє з цим працювати (`ContactRow` приймає `phone: string | null` і не
-- малює рядок для NULL), тож фронт сумісний в обидва боки — урок 050.
--
-- Хто вже ділився номером свідомо, нічого не втрачає раптово: колонка нова,
-- і власник вмикає її одним перемикачем у Профілі.
-- ============================================================================

ALTER TABLE users ADD COLUMN IF NOT EXISTS public_phone BOOLEAN NOT NULL DEFAULT false;

COMMENT ON COLUMN users.public_phone IS
  'Чи показувати номер телефону на публічних /v сторінках. DEFAULT false — приватність за замовчуванням (061).';

-- ── Три превʼю: телефон під прапорцем ──────────────────────────────────────
-- Тіла беруться з ОСТАННІХ визначень (042 для property, 040 для db/collection,
-- 056 для collection) і змінюються рівно в одному місці кожне.

CREATE OR REPLACE FUNCTION get_public_db_preview(p_token TEXT)
RETURNS TABLE (
  db_id UUID, db_name TEXT, db_type TEXT, db_color TEXT,
  share_expires_at TIMESTAMPTZ,
  property_id UUID, property_name TEXT, property_status TEXT, property_floor TEXT,
  property_area_useful DOUBLE PRECISION, property_area_total DOUBLE PRECISION,
  property_rent_type TEXT, property_rent_rate DOUBLE PRECISION,
  property_sale_price DOUBLE PRECISION, property_description TEXT,
  owner_first_name TEXT, owner_last_name TEXT, owner_tg_username TEXT,
  owner_phone TEXT, owner_currency TEXT, first_photo TEXT
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
          WHERE ph.property_id = p.id ORDER BY ph.sort_order, ph.created_at LIMIT 1)
  FROM databases d
  JOIN users o ON o.id = d.owner_id
  LEFT JOIN properties p ON p.db_id = d.id
  WHERE d.share_token = p_token
    AND (d.share_expires_at IS NULL OR d.share_expires_at > now())
  ORDER BY p.sort_order, p.created_at;
$$;
REVOKE ALL ON FUNCTION get_public_db_preview(TEXT) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION get_public_db_preview(TEXT) TO anon, authenticated, service_role;


-- ── Обʼєкт і підбірка: те саме, одна зміна в кожній ────────────────────────
-- Тіла ВЗЯТІ З ЗІБРАНОЇ БД (`pg_get_functiondef`), а не переписані з памʼяті:
-- у property-превʼю 28 рядків і 28 колонок, у collection — 24; ручне
-- відтворення тут — це запрошення до дрейфу, який уже коштував нам 050.

CREATE OR REPLACE FUNCTION public.get_public_property_preview(p_token text)
 RETURNS TABLE(property_id uuid, property_name text, property_status text, property_floor text, property_area_useful double precision, property_area_total double precision, property_area_basis text, property_rent_type text, property_rent_rate double precision, property_utilities_rate double precision, property_description text, property_address text, property_has_parking boolean, property_parking_spaces integer, property_parking_type text, property_ev_charger boolean, property_sale_price double precision, share_expires_at timestamp with time zone, db_id uuid, db_name text, db_type text, db_color text, owner_first_name text, owner_last_name text, owner_tg_username text, owner_phone text, owner_currency text, photos text[])
 LANGUAGE sql
 STABLE SECURITY DEFINER
 SET search_path TO 'public'
AS $function$
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
    )
  FROM properties p
  JOIN databases d ON d.id = p.db_id
  JOIN users u ON u.id = p.owner_id
  WHERE p.share_token = p_token
    AND (p.share_expires_at IS NULL OR p.share_expires_at > now())
  LIMIT 1;
$function$;

REVOKE ALL ON FUNCTION get_public_property_preview(TEXT) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION get_public_property_preview(TEXT) TO anon, authenticated, service_role;

CREATE OR REPLACE FUNCTION public.get_public_collection_preview(p_token text)
 RETURNS TABLE(collection_id uuid, collection_name text, share_expires_at timestamp with time zone, realtor_first_name text, realtor_last_name text, realtor_tg_username text, realtor_phone text, property_id uuid, property_name text, property_status text, property_floor text, property_area_useful double precision, property_area_total double precision, property_area_basis text, property_rent_type text, property_rent_rate double precision, property_sale_price double precision, property_description text, owner_currency text, db_id uuid, db_name text, db_type text, db_color text, first_photo text)
 LANGUAGE sql
 STABLE SECURITY DEFINER
 SET search_path TO 'public'
AS $function$
  SELECT c.id, c.name, c.share_expires_at,
         r.first_name, r.last_name, r.tg_username,
         CASE WHEN r.public_phone THEN r.phone ELSE NULL END,   -- 061
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
$function$;

REVOKE ALL ON FUNCTION get_public_collection_preview(TEXT) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION get_public_collection_preview(TEXT) TO anon, authenticated, service_role;

NOTIFY pgrst, 'reload schema';

-- ═══════════════════════════════════════════════════════════════════════════
-- 066 — три залишки, знайдені наскрізним безпековим рев'ю
--   1. current_app_user_id() без якоря — єдине джерело особи для ВСІХ політик
--   2. storage_photos_select без ролі — масове перелічення бакета
--   3. db_guest_select не перевіряє, що ЦІЛЬ належить видавцю лінка
-- ═══════════════════════════════════════════════════════════════════════════


-- ── 1. ЯКІР ОСОБИ ──────────────────────────────────────────────────────────
--
-- `current_app_user_id()` резолвить особу для КОЖНОЇ політики в схемі, і
-- робить це найслабшою з двох наявних перевірок:
--
--     jwt_email NOT LIKE '%@telegram.propspace.app'      ← суфікс, без якоря
--     SPLIT_PART(jwt_email, '@', 1)::BIGINT              ← ПЕРШИЙ сегмент
--
-- Загартований близнюк `get_app_user_id_from_auth_uid()` має і якір, і
-- `tg_id > 0` — їх додала 031 (CRITICAL-2) саме проти самостійної реєстрації
-- під `<чийсь_tg_id>@будь-що`, а 045 відновила після регресії 038. Ширше
-- вживана функція їх не отримала жодного разу.
--
-- ЧЕСНО ПРО ЕКСПЛУАТОВАНІСТЬ: адреса, що обходить суфікс і дає потрібний
-- перший сегмент, потребує ДВОХ `@` (`123@x.com@telegram.propspace.app`), а
-- GoTrue таку найімовірніше відхилить — підтвердити це з нашого середовища
-- неможливо. Тобто це не звіт про живу діру, а усунення АСИМЕТРІЇ: дві
-- функції з однією роллю не мають різнитись у тому, наскільки суворо вони
-- впізнають людину. Ціна зміни нульова, ціна помилки — весь граф RLS.
CREATE OR REPLACE FUNCTION current_app_user_id()
RETURNS UUID
LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
  jwt_email TEXT;
  tg_id_val BIGINT;
BEGIN
  jwt_email := current_setting('request.jwt.claims', true)::jsonb->>'email';
  -- Якір з обох боків + рівно цифри в локальній частині. `{1,20}` — стеля
  -- BIGINT; довше все одно впало б на касті, але падати мовчки не треба.
  IF jwt_email IS NULL OR jwt_email !~ '^\d{1,20}@telegram\.propspace\.app$' THEN
    RETURN NULL;
  END IF;
  tg_id_val := SPLIT_PART(jwt_email, '@', 1)::BIGINT;
  IF tg_id_val <= 0 THEN
    RETURN NULL;
  END IF;
  RETURN (SELECT id FROM users WHERE tg_id = tg_id_val LIMIT 1);
EXCEPTION WHEN OTHERS THEN RETURN NULL;
END;
$$;


-- ── 2. ПЕРЕЛІЧЕННЯ БАКЕТА ФОТО ─────────────────────────────────────────────
--
-- Останнє визначення (016) — `FOR SELECT USING (bucket_id = 'photos')`, БЕЗ
-- `TO`, тобто для PUBLIC: `anon` включно. Anon-ключ за задумом лежить у
-- клієнтському бандлі, отже будь-хто міг перелічити ВСІ обʼєкти бакета через
-- Storage list API. Імена — `{propertyId}/{timestamp}_{rand}.ext`, тож це
-- повний список UUID обʼєктів системи плюс прямі URL кожного фото.
--
-- 054 і 062 перебудували insert/update/delete на цьому бакеті, а select не
-- чіпали — тому й лишився.
--
-- МЕЖА ЦЬОГО ФІКСА, названа прямо: бакет `photos` — ПУБЛІЧНИЙ (`public=true`,
-- 008/016), і саме на цьому стоїть `/v`: `photoUrl()` будує
-- `/object/public/photos/...`, який читається БЕЗ політик і без сесії. Тобто
-- ця міграція прибирає ПЕРЕЛІЧЕННЯ (знайти шляхи), а не читання за вже
-- відомим шляхом. Закрити друге можна лише зробивши бакет приватним і
-- перевівши публічну сторінку на підписані URL — це продуктова зміна з
-- власною ціною (термін життя посилань у розданих оголошеннях), тож вона
-- свідомо не тут.
--
-- Форма — та сама, що в `pfiles_storage_select` (054): без підзапитів під
-- RLS, через SECURITY DEFINER хелпери, з ОДНИМ джерелом особи.
DROP POLICY IF EXISTS "storage_photos_select" ON storage.objects;
CREATE POLICY "storage_photos_select" ON storage.objects
  FOR SELECT TO authenticated
  USING (
    bucket_id = 'photos'
    AND (
      split_part(name, '/', 1) IN (
        SELECT p::TEXT FROM get_owner_property_ids(get_app_user_id_from_auth_uid()) p
      )
      OR split_part(name, '/', 1) IN (
        SELECT p::TEXT FROM get_realtor_property_ids(get_app_user_id_from_auth_uid()) p
      )
      OR split_part(name, '/', 1) IN (
        SELECT p::TEXT FROM get_editor_property_ids(get_app_user_id_from_auth_uid()) p
      )
    )
  );


-- ── 3. ГОСТЬОВИЙ ЛІНК: ЦІЛЬ МУСИТЬ НАЛЕЖАТИ ВИДАВЦЮ ────────────────────────
--
-- Пʼятий інстанс класу, який 046 / 050 / 053 / 056 / 063 виправляли скрізь,
-- крім цієї політики. 046 закрила ЗАПИС (`guest_links` з чужим `db_id`) і
-- читання через `is_guest_of_property`; 050 — третього споживача
-- (`get_guest_property_preview`). `db_guest_select` лишилась із предикатом
-- ДО 046: питає лише «лінк мій?», не питаючи, чи ціль належить тому, хто
-- лінк видав.
--
-- Наслідок для рядка, посадженого ДО 046 (`owner_id` зловмисника, `db_id`
-- жертви): гість читає рядок бази жертви цілком — назву, адресу, тип,
-- `landlord_name` І `share_token` з `share_expires_at`, тобто вічний
-- публічний /v-лінк, який переживе відкликання його ж гостьового доступу.
-- Нові такі рядки неможливі з 046, отже це ЗАЛИШОК, а не відкритий вектор —
-- рівно того класу, заради якого 050 і писалась.
DROP POLICY IF EXISTS "db_guest_select" ON databases;
CREATE POLICY "db_guest_select" ON databases
  FOR SELECT USING (
    EXISTS (
      SELECT 1 FROM guest_links gl
      WHERE gl.guest_user_id = current_app_user_id()
        AND gl.status = 'active'
        AND gl.db_id = databases.id
        -- ЄДИНА ЗМІНА, і вона вся тут.
        AND gl.owner_id = databases.owner_id
    )
  );


-- ── Аудит: чи лежать у базі лінки з чужою ціллю ─────────────────────────────
-- Має показати 0. Ненульове означає, що такі рядки посаджено до 046 — після
-- цієї міграції вони мертві, але їх варто прибрати руками.
DO $$
DECLARE n INT;
BEGIN
  SELECT COUNT(*) INTO n
  FROM guest_links gl
  JOIN databases d ON d.id = gl.db_id
  WHERE gl.db_id IS NOT NULL AND d.owner_id <> gl.owner_id;
  IF n > 0 THEN
    RAISE WARNING '066: гостьових лінків із ЧУЖОЮ базою: % — вони більше не діють, але рядки лишились', n;
  END IF;
END $$;

-- ============================================================================
-- 074 — ВИДАЛЕННЯ АКАУНТА: імʼя зникає з чужих баз, автор не висне
-- ============================================================================
-- ЩО ЛІКУЄ. Знайдено ВИКОНАННЯМ на живому Postgres, а не читанням: редактор
-- вписав надходження в базу власника і видалив свій акаунт.
-- `delete_my_account()` звітує успіх, але:
--
--   1. ВИСЯЧИЙ КЛЮЧ. `rent_payment_parts.created_by` лишався на НЕІСНУЮЧОМУ
--      користувачі. Каскад `ON DELETE SET NULL` — це UPDATE, а тригер 073 на
--      кожному UPDATE повертає автора з OLD («автора не переписує ніхто»),
--      тож каскад мовчки скасовувався. Postgres цього не помічає: для нього
--      ключ «не змінився», і перевірка обмеження пропускається. Наслідок не
--      косметичний — логічний бекап відновлює обмеження ПІСЛЯ даних і падає
--      саме на ньому (заміряно: «violates foreign key constraint»). Тобто
--      одне видалення акаунта робило базу невідновлюваною з дампу.
--
--   2. ІМʼЯ ЛИШАЛОСЬ. Політика обіцяє «видалити акаунт і всі повʼязані
--      дані», а заморожені копії імені — їх тримають саме для того, щоб
--      бачили інші, — переживали видалення в ЧОТИРЬОХ місцях: журнал змін і
--      автор надходження (073), аналітика переглядів (`viewer_name`, її
--      показують 063 і екран аналітики) і гостьові лінки (048). 051
--      знеособлювала лише КЛЮЧІ.
--
-- ПРАВИЛО: заморожена копія імені живе рівно доки живе посилання на людину.
-- Посилання перерізали — імʼя йде слідом. Тримає це ТРИГЕР, а не
-- `delete_my_account`: так правило діє на БУДЬ-ЯКОМУ шляху видалення
-- користувача, а не лише на кнопці в профілі.
--
-- ЗАПИСИ ЛИШАЮТЬСЯ. Надходження з сумою, подія журналу, перегляд — це облік
-- ВЛАСНИКА бази, і гроші не зникають через те, що їх вписав той, хто пішов.
-- Зникає лише «хто». Вихід із команди (без видалення акаунта) імені НЕ
-- стирає: людина є, і запис про те, що вона робила, правдивий.
-- ============================================================================

BEGIN;

-- ── 1. Автор надходження: виняток для каскаду ──────────────────────────────
-- Тіло — з 073 дослівно, крім гілки UPDATE. Розрізнити каскад і підробку
-- можна лише одним способом, який клієнт не здатен підробити: автора вже не
-- існує. Каскад біжить ПІСЛЯ видалення рядка `users`, тож у ньому
-- `NOT EXISTS` істинне; клієнт, що пробує стерти чи підмінити автора живої
-- людини, і далі дістає старе значення.
CREATE OR REPLACE FUNCTION public.stamp_rent_part_author()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
BEGIN
  IF TG_OP = 'UPDATE' THEN
    IF NEW.created_by IS NULL AND OLD.created_by IS NOT NULL
       AND NOT EXISTS (SELECT 1 FROM users u WHERE u.id = OLD.created_by) THEN
      NEW.created_by_name := NULL;
      RETURN NEW;
    END IF;
    NEW.created_by      := OLD.created_by;
    NEW.created_by_name := OLD.created_by_name;
    RETURN NEW;
  END IF;

  -- Перенесене підтвердження СТАРОГО клієнта (071: сума на періоді без
  -- надходжень стає першим надходженням). Гроші вписав хтось раніше, і
  -- приписати їх тому, чия дія спричинила перенос, було б неправдою.
  -- Звичайний перший платіж періоду так не виглядає: період без надходжень
  -- має порожню суму (її обнуляє тригер 071).
  IF EXISTS (SELECT 1 FROM rent_payment_records r
              WHERE r.id = NEW.record_id AND r.amount > 0
                AND r.status IN ('paid', 'partial'))
     AND NOT EXISTS (SELECT 1 FROM rent_payment_parts pp WHERE pp.record_id = NEW.record_id) THEN
    NEW.created_by      := NULL;
    NEW.created_by_name := NULL;
    RETURN NEW;
  END IF;

  NEW.created_by      := NULL;
  NEW.created_by_name := NULL;
  SELECT u.id, NULLIF(trim(concat(u.first_name, ' ', coalesce(u.last_name, ''))), '')
    INTO NEW.created_by, NEW.created_by_name
    FROM users u WHERE u.id = current_app_user_id();
  RETURN NEW;
END;
$$;

REVOKE ALL ON FUNCTION public.stamp_rent_part_author() FROM PUBLIC;

-- ── 2. Решта копій імені ────────────────────────────────────────────────────
-- Один тригер на три таблиці: аргументи — колонка посилання і колонка імені.
-- Спрацьовує лише на ПЕРЕХОДІ «було посилання → немає», тож службові рядки,
-- що від початку без посилання (публічні «Веб-перегляд»), не зачіпає.
-- Посилання тут обнуляє лише видалення акаунта: явний UPDATE у 051
-- (перегляди — їхній ключ `NO ACTION`, і гостьові лінки) і каскад
-- `SET NULL` (журнал). Інших записів, що рвуть ці посилання, у схемі немає.
CREATE OR REPLACE FUNCTION public.erase_frozen_name()
RETURNS TRIGGER
LANGUAGE plpgsql
SET search_path = public, pg_temp
AS $$
BEGIN
  IF to_jsonb(NEW) ->> TG_ARGV[0] IS NULL AND to_jsonb(OLD) ->> TG_ARGV[0] IS NOT NULL THEN
    NEW := jsonb_populate_record(NEW, jsonb_build_object(TG_ARGV[1], NULL));
  END IF;
  RETURN NEW;
END;
$$;

REVOKE ALL ON FUNCTION public.erase_frozen_name() FROM PUBLIC;

DROP TRIGGER IF EXISTS trg_erase_viewer_name ON property_views;
CREATE TRIGGER trg_erase_viewer_name
  BEFORE UPDATE OF viewer_id ON property_views
  FOR EACH ROW EXECUTE FUNCTION public.erase_frozen_name('viewer_id', 'viewer_name');

DROP TRIGGER IF EXISTS trg_erase_guest_name ON guest_links;
CREATE TRIGGER trg_erase_guest_name
  BEFORE UPDATE OF guest_user_id ON guest_links
  FOR EACH ROW EXECUTE FUNCTION public.erase_frozen_name('guest_user_id', 'guest_name');

DROP TRIGGER IF EXISTS trg_erase_actor_name ON db_activity;
CREATE TRIGGER trg_erase_actor_name
  BEFORE UPDATE OF actor_id ON db_activity
  FOR EACH ROW EXECUTE FUNCTION public.erase_frozen_name('actor_id', 'actor_name');

-- ── 3. Ремонт того, що вже встигло статись ──────────────────────────────────
-- Порядок важливий: тригери вище МУСЯТЬ стояти раніше, інакше перший UPDATE
-- скасував би сам себе тим самим тригером 073, який тут лагодиться.
UPDATE rent_payment_parts pp SET created_by = NULL
 WHERE pp.created_by IS NOT NULL
   AND NOT EXISTS (SELECT 1 FROM users u WHERE u.id = pp.created_by);

-- Подію журналу без дійової особи записати неможливо (073 пише лише з
-- особою), тож порожнє посилання тут означає рівно видалений акаунт.
UPDATE db_activity SET actor_name = NULL
 WHERE actor_id IS NULL AND actor_name IS NOT NULL;

-- Гостьовий лінк дістає імʼя лише разом із посиланням на того, хто його
-- прийняв (048), тож імʼя без посилання — залишок видаленого акаунта.
UPDATE guest_links SET guest_name = NULL
 WHERE guest_user_id IS NULL AND guest_name IS NOT NULL;

-- Перегляди — обережно: публічні відкриття пишуться БЕЗ посилання, але зі
-- СЛУЖБОВИМ підписом (059), і екран аналітики його показує. Стирати можна
-- лише те, що не є цим підписом.
UPDATE property_views SET viewer_name = NULL
 WHERE viewer_id IS NULL AND viewer_name IS NOT NULL
   AND viewer_name NOT IN ('Веб-перегляд', 'Веб-перегляд бази', 'Веб-перегляд підбірки');

NOTIFY pgrst, 'reload schema';

COMMIT;

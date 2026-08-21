-- ============================================================================
-- 052 — нагадування про платежі: функція, ЯКА НІКОЛИ НЕ ПОВЕРТАЛА ЖОДНОГО
--       РЯДКА, плюс два ACL-недогляди на тих самих функціях
-- ============================================================================
-- Знайдено ВИКОНАННЯМ міграцій на справжньому Postgres (scripts/verify-
-- migrations.sh), не читанням: усі три дефекти невидимі для будь-якого
-- джерельного гарда.
--
-- ── 1. ЗЛАМАНИЙ ТИП РЕЗУЛЬТАТУ (обидві функції, з моменту створення) ────────
-- `014_security_hardening.sql` звузив `properties.name`/`tenant_name` до
-- VARCHAR(200). `021_rent_payments.sql` (пізніша!) оголосила
-- `RETURNS TABLE(... property_name TEXT ...)` і повертає `p.name` без касту.
-- plpgsql звіряє тип КОЛОНКИ, а не тільки родину типів, тож кожен виклик
-- падає з
--     structure of query does not match function result type
--     Returned type character varying(200) does not match expected type text
-- Наслідок: `send-reminders` не міг створити ЖОДНОГО рядка `notifications`
-- за весь час існування — а `notifications` наповнює ВИКЛЮЧНО ця функція.
-- Тобто причин, чому сповіщень у проді не було, було ДВІ, а не одна:
-- відсутній планувальник (полагоджено раніше) і ця помилка.
--
-- ── 2. КЛАМП ДНЯ МІСЯЦЯ — ЗАХИСТ, А НЕ ФІКС (гіпотезу СПРОСТОВАНО) ─────────
-- `get_due_reminders_today` кладе сирий `rp.due_day` у `make_date`, тобто
-- `make_date(2026,4,31)` дав би `date field value out of range` і вбив би
-- ВЕСЬ прогін, а не один рядок. Виглядає як третій дефект — і саме так це
-- тут спершу й було записано. Перевірка на живій БД його НЕ підтвердила:
-- `rent_payments_due_day_check` тримає `due_day BETWEEN 1 AND 28`, тож
-- значення, яке переповнює будь-який місяць, у таблицю не потрапляє в
-- принципі. Кламп (той самий, що вже мала `get_due_guest_reminders`)
-- лишається як симетрія між двома функціями, а не як виправлення живої
-- помилки — щоб наступний, хто помітить розбіжність, не шукав дефекту там,
-- де його немає.
--
-- ── 3. PUBLIC МАВ EXECUTE на обох service-role функціях ────────────────────
-- `GRANT ... TO service_role` НЕ знімає дефолтний грант PUBLIC, який Postgres
-- вішає на кожну функцію при створенні — він лише матеріалізує його в ACL
-- (`{=X/postgres,postgres=X/postgres,service_role=X/postgres}`, де порожній
-- грантополучач і є PUBLIC). Решта чутливих функцій проєкту мають явний
-- `REVOKE ALL ... FROM PUBLIC` (див. 013/014/020/023/026/027); ці дві його
-- не отримали.
--   • `get_due_reminders_today()` — SECURITY DEFINER, повертає `owner_id`,
--     `tg_id`, назву обʼєкта та ІМʼЯ ОРЕНДАРЯ по ВСІХ власниках одразу, без
--     жодного параметра. З anon-ключем, що за задумом лежить у клієнтському
--     бандлі, це наскрізний дамп PII без автентифікації.
--   • `mark_overdue_payments()` — глобальний UPDATE по `rent_payment_records`
--     усіх власників, теж із anon.
--
-- ПОРЯДОК ФІКСІВ ТУТ НЕ ДОВІЛЬНИЙ: поки тип результату зламаний, витік
-- (3) не експлуатується — виклик падає раніше, ніж віддасть рядок. Тобто
-- виправити ЛИШЕ тип означало б УВІМКНУТИ дамп. Обидві частини мусять
-- їхати одним файлом.
-- ============================================================================

CREATE OR REPLACE FUNCTION get_due_reminders_today()
RETURNS TABLE (
  owner_id      UUID,
  tg_id         BIGINT,
  property_id   UUID,
  property_name TEXT,
  due_day       INT,
  tenant_name   TEXT,
  due_date      DATE
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE v_today DATE := current_date;
BEGIN
  RETURN QUERY
  SELECT rp.owner_id, u.tg_id, rp.property_id,
         p.name::TEXT,
         rp.due_day::INT,
         p.tenant_name::TEXT,
         make_date(
           EXTRACT(YEAR  FROM (v_today + rp.notify_days_before * INTERVAL '1 day'))::INT,
           EXTRACT(MONTH FROM (v_today + rp.notify_days_before * INTERVAL '1 day'))::INT,
           LEAST(
             rp.due_day,
             EXTRACT(DAY FROM (
               DATE_TRUNC('month', (v_today + rp.notify_days_before * INTERVAL '1 day'))
               + INTERVAL '1 month' - INTERVAL '1 day'
             ))::INT
           )
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

CREATE OR REPLACE FUNCTION get_due_guest_reminders()
RETURNS TABLE (
  guest_id      UUID,
  tg_id         BIGINT,
  property_id   UUID,
  property_name TEXT,
  due_day       INT,
  due_date      DATE
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE v_today DATE := current_date;
BEGIN
  RETURN QUERY
  SELECT DISTINCT ON (u.id, rp.property_id)
    u.id, u.tg_id, rp.property_id,
    p.name::TEXT,
    rp.due_day::INT,
    make_date(
      EXTRACT(YEAR  FROM (v_today + rp.notify_days_before * INTERVAL '1 day'))::INT,
      EXTRACT(MONTH FROM (v_today + rp.notify_days_before * INTERVAL '1 day'))::INT,
      LEAST(
        rp.due_day,
        EXTRACT(DAY FROM (
          DATE_TRUNC('month', (v_today + rp.notify_days_before * INTERVAL '1 day'))
          + INTERVAL '1 month' - INTERVAL '1 day'
        ))::INT
      )
    )
  FROM rent_payments rp
  JOIN properties p ON p.id = rp.property_id
  JOIN guest_links gl ON (gl.property_id = rp.property_id OR gl.db_id = p.db_id)
                      AND gl.status = 'active'
  JOIN users u ON u.id = gl.guest_user_id
  WHERE rp.is_active = true
    AND p.status = 'occupied'
    AND EXTRACT(DAY FROM (v_today + rp.notify_days_before * INTERVAL '1 day'))::INT = rp.due_day
    AND NOT EXISTS (
      SELECT 1 FROM notifications n
      WHERE n.user_id = u.id
        AND n.type = 'rent_reminder'
        AND (n.data->>'property_id')::UUID = rp.property_id
        AND DATE_TRUNC('month', n.created_at) = DATE_TRUNC('month', v_today::TIMESTAMPTZ)
    )
  ORDER BY u.id, rp.property_id;
END;
$$;

-- Дефолтний грант PUBLIC знімається ЯВНО — `GRANT ... TO service_role` його
-- не чіпає.
REVOKE ALL ON FUNCTION get_due_reminders_today()  FROM PUBLIC;
REVOKE ALL ON FUNCTION get_due_guest_reminders()  FROM PUBLIC;
REVOKE ALL ON FUNCTION mark_overdue_payments()    FROM PUBLIC;
GRANT EXECUTE ON FUNCTION get_due_reminders_today() TO service_role;
GRANT EXECUTE ON FUNCTION get_due_guest_reminders() TO service_role;
GRANT EXECUTE ON FUNCTION mark_overdue_payments()   TO service_role;

NOTIFY pgrst, 'reload schema';

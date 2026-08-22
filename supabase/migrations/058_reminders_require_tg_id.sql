-- ============================================================================
-- 058 — нагадування для власника БЕЗ tg_id зациклювались на щоденний ретрай
-- ============================================================================
-- Знайдено власним аудитом `send-reminders` — функції, чия УСПІШНА гілка до
-- 052 не виконувалась у проді жодного разу, тобто весь її happy path був
-- непротестованою територією.
--
-- `users.tg_id` NULLABLE (унікальний індекс частковий: `WHERE tg_id IS NOT
-- NULL`), а обидві функції нагадувань джойнять `users` без цієї умови. Для
-- власника без `tg_id` рядок повертається з `tg_id = NULL`; edge-функція
-- кличе Telegram з `chat_id: null`, дістає 400 — і, оскільки рядок у
-- `notifications` пишеться ЛИШЕ на `res?.ok`, маркер дедуплікації не
-- зʼявляється НІКОЛИ.
--
-- Наслідок: `NOT EXISTS (… DATE_TRUNC('month') …)` не стає істинним, тож той
-- самий рядок віддається ЩОДНЯ до кінця місяця — один провалений виклик і
-- один рядок в лог на добу, безкінечно.
--
-- Заміряно на живій БД до фікса: `рядків для власника БЕЗ tg_id: 1 (tg_id=NULL)`.
--
-- Це НЕ витік і не втрата даних — операційний дефект, який стає досяжним рівно
-- тоді, коли 052 вмикає нагадування. Доти функція падала раніше, ніж встигала
-- віддати такий рядок.
--
-- Фікс — один предикат у кожній функції. Решта тіла (включно з `053`-ним
-- `rp.owner_id = p.owner_id` і клампом дня місяця) переноситься дослівно.
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
    AND rp.owner_id = p.owner_id   -- 053: не розсилати чужі дані власнику розкладу
    AND u.tg_id IS NOT NULL        -- 058: інакше вічний щоденний ретрай
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
    AND u.tg_id IS NOT NULL        -- 058: див. вище
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

REVOKE ALL ON FUNCTION get_due_reminders_today()  FROM PUBLIC;
REVOKE ALL ON FUNCTION get_due_guest_reminders()  FROM PUBLIC;
GRANT EXECUTE ON FUNCTION get_due_reminders_today() TO service_role;
GRANT EXECUTE ON FUNCTION get_due_guest_reminders() TO service_role;

NOTIFY pgrst, 'reload schema';

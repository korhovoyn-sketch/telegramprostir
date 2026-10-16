-- ============================================================================
-- 070 — нагадування про оплату НЕ йде, коли платіж уже підтверджено
-- ============================================================================
-- Знайдено аудитом розділу платежів. `get_due_reminders_today()` питає лише
-- «чи настав день нагадування» і «чи не нагадували цього місяця», але НЕ
-- питає, чи гроші вже прийшли. Орендар, що заплатив на тиждень раніше, а
-- власник це підтвердив, — і за три дні до дати власник однаково отримує в
-- Telegram «оплата через 3 дні». Гість (орендар) — те саме від гостьової
-- функції. Нагадування, що бреше про стан грошей, вчить їх ігнорувати.
--
-- Друга умова того самого класу: дата ДО початку договору. Обʼєкт, зданий
-- 10-го з днем оплати 5-го, у перший місяць не винен нічого (`isOwedUnderLease`
-- на клієнті це вже знає), а нагадування про «оплату 5-го» приходило.
--
-- Тіла перенесені з 058 ДОСЛІВНО (включно з 053-м `rp.owner_id = p.owner_id`,
-- 058-м `tg_id IS NOT NULL` і клампом дня місяця). Змінено одне: дата платежу
-- рахується РАЗ у `LATERAL`, бо тепер вона потрібна в трьох місцях, і
-- додано два предикати. Контракт результату той самий — `CREATE OR REPLACE`
-- без зміни типу (урок 42P13 з 044).
--
-- Посилання на колонки КВАЛІФІКОВАНІ: `due_date`, `property_id`, `owner_id` —
-- це ще й OUT-параметри функції, і неякісний `due_date` був би неоднозначним
-- (урок 055).
-- ============================================================================

BEGIN;

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
         d.due
  FROM rent_payments rp
  JOIN properties p ON p.id = rp.property_id
  JOIN users u ON u.id = rp.owner_id
  CROSS JOIN LATERAL (
    SELECT make_date(
      EXTRACT(YEAR  FROM (v_today + rp.notify_days_before * INTERVAL '1 day'))::INT,
      EXTRACT(MONTH FROM (v_today + rp.notify_days_before * INTERVAL '1 day'))::INT,
      LEAST(
        rp.due_day,
        EXTRACT(DAY FROM (
          DATE_TRUNC('month', (v_today + rp.notify_days_before * INTERVAL '1 day'))
          + INTERVAL '1 month' - INTERVAL '1 day'
        ))::INT
      )
    ) AS due
  ) d
  WHERE rp.is_active = true
    AND p.status = 'occupied'
    AND rp.owner_id = p.owner_id   -- 053: не розсилати чужі дані власнику розкладу
    AND u.tg_id IS NOT NULL        -- 058: інакше вічний щоденний ретрай
    AND EXTRACT(DAY FROM (v_today + rp.notify_days_before * INTERVAL '1 day'))::INT = rp.due_day
    -- 070: до початку договору платежу немає.
    AND (p.lease_start_date IS NULL OR d.due >= p.lease_start_date)
    -- 070: гроші вже прийшли — нагадувати нема про що.
    AND NOT EXISTS (
      SELECT 1 FROM rent_payment_records r
      WHERE r.property_id = rp.property_id
        AND r.due_date = d.due
        AND r.status = 'paid'
    )
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
    d.due
  FROM rent_payments rp
  JOIN properties p ON p.id = rp.property_id
  JOIN guest_links gl ON (gl.property_id = rp.property_id OR gl.db_id = p.db_id)
                      AND gl.status = 'active'
  JOIN users u ON u.id = gl.guest_user_id
  CROSS JOIN LATERAL (
    SELECT make_date(
      EXTRACT(YEAR  FROM (v_today + rp.notify_days_before * INTERVAL '1 day'))::INT,
      EXTRACT(MONTH FROM (v_today + rp.notify_days_before * INTERVAL '1 day'))::INT,
      LEAST(
        rp.due_day,
        EXTRACT(DAY FROM (
          DATE_TRUNC('month', (v_today + rp.notify_days_before * INTERVAL '1 day'))
          + INTERVAL '1 month' - INTERVAL '1 day'
        ))::INT
      )
    ) AS due
  ) d
  WHERE rp.is_active = true
    AND p.status = 'occupied'
    AND u.tg_id IS NOT NULL        -- 058: див. вище
    AND EXTRACT(DAY FROM (v_today + rp.notify_days_before * INTERVAL '1 day'))::INT = rp.due_day
    AND (p.lease_start_date IS NULL OR d.due >= p.lease_start_date)   -- 070
    AND NOT EXISTS (                                                   -- 070
      SELECT 1 FROM rent_payment_records r
      WHERE r.property_id = rp.property_id
        AND r.due_date = d.due
        AND r.status = 'paid'
    )
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

COMMIT;

NOTIFY pgrst, 'reload schema';

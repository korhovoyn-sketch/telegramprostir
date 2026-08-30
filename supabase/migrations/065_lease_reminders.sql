-- ============================================================================
-- 065 — нагадування про КІНЕЦЬ ДОГОВОРУ в Telegram
-- ============================================================================
-- Прогалина, названа продуктово: `useLeaseAlerts` рахує наближення кінця
-- договору НА КЛІЄНТІ, тобто власник дізнається про це, лише якщо сам відкрив
-- застосунок. Поза застосунком іде рівно один тип — `rent_reminder`, і пише
-- його виключно `send-reminders`. Договір, що спливає через тиждень, не
-- доходить до людини нічим.
--
-- Похідний блок на екрані лишається як є (він показує СТАН і зникає сам, щойно
-- договір продовжили) — ця функція додає поруч ПОДІЮ: разове повідомлення на
-- кожному з порогів.
--
-- ── Пороги, і чому саме такі ───────────────────────────────────────────────
-- {30, 7, 1, 0} днів. Щоденна розсилка все 30-денне вікно перетворила б
-- нагадування на шум, після якого його вимикають; один поріг за 30 днів —
-- запізно для «встигнути передомовитись». Нуль — це «сьогодні останній день».
--
-- ── Дедуп ключується ДАТОЮ ДОГОВОРУ, а не лише обʼєктом ────────────────────
-- Інакше продовжений договір ніколи більше не нагадав би про себе: рядок
-- `notifications` про старий поріг лишається назавжди. Ключ
-- (property_id, lease_end_date, days_left) дає рівно одне повідомлення на
-- кожен поріг КОЖНОГО договору, і продовження автоматично відкриває нову
-- серію.
--
-- ── Три вже оплачені уроки, застосовані тут одразу ─────────────────────────
--  • 052: `properties.name`/`tenant_name` — VARCHAR(200), а plpgsql звіряє тип
--    КОЛОНКИ. Без `::TEXT` кожен виклик падає з «structure of query does not
--    match function result type», і жодного рядка не зʼявляється НІКОЛИ.
--  • 058: `users.tg_id` NULLABLE. Без `IS NOT NULL` edge-функція кличе
--    Telegram із `chat_id: null`, дістає 400, а рядок `notifications`
--    пишеться лише на `res.ok` — тобто маркер дедупу не зʼявляється, і той
--    самий рядок віддається ЩОДНЯ.
--  • правило 12: `GRANT ... TO service_role` НЕ знімає дефолтного PUBLIC.
--    Функція віддає `tg_id`, назву обʼєкта та ІМʼЯ ОРЕНДАРЯ по всіх власниках
--    без параметрів — з anon-ключем це наскрізний дамп PII. Тому явний
--    `REVOKE ALL ... FROM PUBLIC` ПЕРЕД грантом.
-- ============================================================================

BEGIN;

DROP FUNCTION IF EXISTS get_due_lease_reminders();

CREATE FUNCTION get_due_lease_reminders()
RETURNS TABLE (
  owner_id        UUID,
  tg_id           BIGINT,
  property_id     UUID,
  property_name   TEXT,
  tenant_name     TEXT,
  lease_end_date  DATE,
  days_left       INT
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE v_today DATE := current_date;
BEGIN
  RETURN QUERY
  SELECT p.owner_id,
         u.tg_id,
         p.id,
         p.name::TEXT,
         p.tenant_name::TEXT,
         p.lease_end_date,
         (p.lease_end_date - v_today)::INT
  FROM properties p
  JOIN users u ON u.id = p.owner_id
  WHERE p.status = 'occupied'
    AND p.lease_end_date IS NOT NULL
    AND u.tg_id IS NOT NULL
    AND (p.lease_end_date - v_today)::INT IN (30, 7, 1, 0)
    AND NOT EXISTS (
      SELECT 1 FROM notifications n
      WHERE n.user_id = p.owner_id
        AND n.type = 'lease_reminder'
        AND (n.data->>'property_id')::UUID = p.id
        AND (n.data->>'lease_end_date') = p.lease_end_date::TEXT
        AND (n.data->>'days_left')::INT = (p.lease_end_date - v_today)::INT
    );
END;
$$;

REVOKE ALL ON FUNCTION get_due_lease_reminders() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION get_due_lease_reminders() TO service_role;

COMMIT;

NOTIFY pgrst, 'reload schema';

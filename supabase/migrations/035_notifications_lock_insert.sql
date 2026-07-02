-- 035: Lock notifications INSERT to service_role only.
--
-- Background (backend audit): the `notifs_own` policy was `FOR ALL` with
-- WITH CHECK (user_id = current_app_user_id()), which let an authenticated user
-- INSERT their own notification rows. The rent-reminder dedup in
-- get_due_reminders_today / get_due_guest_reminders keys off
-- (user_id, type='rent_reminder', data->>'property_id'), so a user could
-- pre-insert a fake row to silence their own reminder for a month. Impact is
-- self-inflicted only (current_app_user_id() scopes it — no cross-tenant access),
-- hence low severity, but there is no legitimate reason for the client to insert.
--
-- The client (src/hooks/useNotifications.ts) only SELECTs, UPDATEs is_read, and
-- DELETEs. Reminder rows are written exclusively by the send-reminders Edge
-- Function using the service_role key (notifs_service policy, untouched here).
-- So we scope the client policy to SELECT/UPDATE/DELETE and drop INSERT.

DROP POLICY IF EXISTS "notifs_own"         ON notifications;
DROP POLICY IF EXISTS "notifs_own_select"  ON notifications;
DROP POLICY IF EXISTS "notifs_own_update"  ON notifications;
DROP POLICY IF EXISTS "notifs_own_delete"  ON notifications;

CREATE POLICY "notifs_own_select" ON notifications FOR SELECT
  USING (user_id = current_app_user_id());

CREATE POLICY "notifs_own_update" ON notifications FOR UPDATE
  USING (user_id = current_app_user_id())
  WITH CHECK (user_id = current_app_user_id());

CREATE POLICY "notifs_own_delete" ON notifications FOR DELETE
  USING (user_id = current_app_user_id());

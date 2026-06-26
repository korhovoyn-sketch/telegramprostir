-- ============================================================================
-- 034_notifications_realtime.sql — Enable Realtime for notifications table
-- Idempotent. Run in Supabase SQL Editor.
--
-- Without this, the postgres_changes INSERT subscription in useNotifications.ts
-- (subscribeToNotifications) silently never fires — new rows from send-reminders
-- are not broadcast to connected clients even when NotificationsScreen is open.
-- ============================================================================

-- Add notifications to the supabase_realtime publication so INSERT events are
-- broadcast to subscribed clients. REPLICA IDENTITY FULL required for RLS-filtered
-- Realtime channels to work correctly (otherwise the filter can't match old/new row).
ALTER TABLE notifications REPLICA IDENTITY FULL;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_publication_tables
    WHERE pubname = 'supabase_realtime' AND tablename = 'notifications'
  ) THEN
    ALTER PUBLICATION supabase_realtime ADD TABLE notifications;
  END IF;
END
$$;

NOTIFY pgrst, 'reload schema';

SELECT 'notifications table added to supabase_realtime publication' AS result;

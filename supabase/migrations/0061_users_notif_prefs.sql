-- PropSpace v1.0.0 — Migration 006: Notification preferences on users table
--
-- Stores push-notification preferences server-side so they survive
-- localStorage clears, private mode, and device changes.
--
-- APPLY: Supabase Dashboard → SQL Editor → paste and run.

ALTER TABLE users
  ADD COLUMN IF NOT EXISTS notification_push    BOOLEAN NOT NULL DEFAULT true,
  ADD COLUMN IF NOT EXISTS notification_weekly  BOOLEAN NOT NULL DEFAULT true,
  ADD COLUMN IF NOT EXISTS notification_views   BOOLEAN NOT NULL DEFAULT true;

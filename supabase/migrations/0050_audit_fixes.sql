-- PropSpace v1.0.0 — Migration 005: Security & Performance audit fixes
--
-- APPLY: Supabase Dashboard → SQL Editor → paste and run this file.

-- ── BLOCKER-2: Replace permissive views_insert_all policy ──────────────────
-- Old policy allowed ANY authenticated user to insert views for ANY property
-- with ANY viewer_id. Replaced with a policy that restricts viewer_id to the
-- current authenticated user (or NULL for anonymous views).
DROP POLICY IF EXISTS "views_insert_all" ON property_views;

CREATE POLICY "views_insert_auth" ON property_views
  FOR INSERT WITH CHECK (
    viewer_id IS NULL OR viewer_id = current_app_user_id()
  );

-- ── MEDIUM-6: Index on users.tg_id ────────────────────────────────────────
-- current_app_user_id() does SELECT id FROM users WHERE tg_id = ?
-- on every RLS row evaluation. Without an index this is a sequential scan.
CREATE UNIQUE INDEX IF NOT EXISTS users_tg_id_idx ON users(tg_id);

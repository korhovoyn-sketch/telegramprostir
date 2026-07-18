-- PropSpace v1.0.0 — Migration 004: Fix share-token RLS
--
-- PROBLEM: New users (not yet subscribed) cannot SELECT from `databases`
-- because the only SELECT policies require being the owner OR already subscribed.
-- This breaks QR scanning and deep-link processing: to create a subscription
-- you first need to find the database by share_token — but RLS hides it.
--
-- FIX: Allow any authenticated user to SELECT a database that has a non-null
-- share_token. The share_token is the access-control mechanism (like a secret
-- link), so this is intentional and safe.
--
-- APPLY: Supabase Dashboard → SQL Editor → paste and run this file.

CREATE POLICY IF NOT EXISTS "db_share_lookup" ON databases
  FOR SELECT
  USING (share_token IS NOT NULL);

-- ══════════════════════════════════════════════════════════════════
-- Prostir — RLS Policies + Performance Indexes
-- Run in: Supabase Dashboard → SQL Editor
-- ══════════════════════════════════════════════════════════════════

-- ────────────────────────────────────────────────────────────────
-- Ensure telegram_id column exists on users table
-- ────────────────────────────────────────────────────────────────
ALTER TABLE public.users
  ADD COLUMN IF NOT EXISTS telegram_id TEXT,
  ADD COLUMN IF NOT EXISTS city       TEXT,
  ADD COLUMN IF NOT EXISTS plan       TEXT NOT NULL DEFAULT 'free';

-- telegram_id must be unique (one Supabase account per Telegram user)
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
    WHERE conname = 'users_telegram_id_unique'
  ) THEN
    ALTER TABLE public.users
      ADD CONSTRAINT users_telegram_id_unique UNIQUE (telegram_id);
  END IF;
END$$;

-- ────────────────────────────────────────────────────────────────
-- TABLE: users
-- ────────────────────────────────────────────────────────────────
ALTER TABLE public.users ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS "users_self_select" ON public.users;
DROP POLICY IF EXISTS "users_self_insert" ON public.users;
DROP POLICY IF EXISTS "users_self_update" ON public.users;

CREATE POLICY "users_self_select" ON public.users
  FOR SELECT USING (auth.uid() = id);

CREATE POLICY "users_self_insert" ON public.users
  FOR INSERT WITH CHECK (auth.uid() = id);

CREATE POLICY "users_self_update" ON public.users
  FOR UPDATE USING (auth.uid() = id)
  WITH CHECK (auth.uid() = id);

-- ────────────────────────────────────────────────────────────────
-- TABLE: databases
-- ────────────────────────────────────────────────────────────────
ALTER TABLE public.databases ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS "db_owner_select" ON public.databases;
DROP POLICY IF EXISTS "db_owner_insert" ON public.databases;
DROP POLICY IF EXISTS "db_owner_update" ON public.databases;
DROP POLICY IF EXISTS "db_owner_delete" ON public.databases;

-- owner_id must match the authenticated user's UUID
CREATE POLICY "db_owner_select" ON public.databases
  FOR SELECT USING (owner_id = auth.uid());

CREATE POLICY "db_owner_insert" ON public.databases
  FOR INSERT WITH CHECK (owner_id = auth.uid());

CREATE POLICY "db_owner_update" ON public.databases
  FOR UPDATE USING (owner_id = auth.uid())
  WITH CHECK (owner_id = auth.uid());

CREATE POLICY "db_owner_delete" ON public.databases
  FOR DELETE USING (owner_id = auth.uid());

-- ────────────────────────────────────────────────────────────────
-- TABLE: objects
-- ────────────────────────────────────────────────────────────────
ALTER TABLE public.objects ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS "obj_owner_select" ON public.objects;
DROP POLICY IF EXISTS "obj_owner_insert" ON public.objects;
DROP POLICY IF EXISTS "obj_owner_update" ON public.objects;
DROP POLICY IF EXISTS "obj_owner_delete" ON public.objects;

CREATE POLICY "obj_owner_select" ON public.objects
  FOR SELECT USING (owner_id = auth.uid());

-- CRITICAL: also verify db_id belongs to the same owner.
-- Prevents cross-owner object injection even if someone manipulates DOM.
CREATE POLICY "obj_owner_insert" ON public.objects
  FOR INSERT WITH CHECK (
    owner_id = auth.uid()
    AND EXISTS (
      SELECT 1 FROM public.databases
      WHERE id = db_id
        AND owner_id = auth.uid()
    )
  );

CREATE POLICY "obj_owner_update" ON public.objects
  FOR UPDATE USING (owner_id = auth.uid())
  WITH CHECK (owner_id = auth.uid());

CREATE POLICY "obj_owner_delete" ON public.objects
  FOR DELETE USING (owner_id = auth.uid());

-- ────────────────────────────────────────────────────────────────
-- Performance indexes
-- ────────────────────────────────────────────────────────────────

-- Speeds up loadBases(), loadDashboard(), profile stat counts
CREATE INDEX IF NOT EXISTS idx_databases_owner_created
  ON public.databases (owner_id, created_at DESC);

-- Speeds up loadObjects(), cycleStatus(), doDeleteObject()
CREATE INDEX IF NOT EXISTS idx_objects_owner_created
  ON public.objects (owner_id, created_at DESC);

-- Speeds up loadObjects(dbId) — the most frequent query
CREATE INDEX IF NOT EXISTS idx_objects_db_id_owner
  ON public.objects (db_id, owner_id);

-- Speeds up telegram-auth edge function lookup
CREATE INDEX IF NOT EXISTS idx_users_telegram_id
  ON public.users (telegram_id)
  WHERE telegram_id IS NOT NULL;

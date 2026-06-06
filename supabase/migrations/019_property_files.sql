-- ── Property Files ──────────────────────────────────────────────────────────
-- Attachments (PDF / DOC / DOCX) linked to a property.
-- Storage: private bucket "property-files", signed URLs.

CREATE TABLE IF NOT EXISTS property_files (
  id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  property_id  UUID NOT NULL REFERENCES properties(id) ON DELETE CASCADE,
  owner_id     UUID NOT NULL REFERENCES users(id)     ON DELETE CASCADE,
  storage_path TEXT    NOT NULL,
  file_name    TEXT    NOT NULL,
  file_size    BIGINT  NOT NULL DEFAULT 0,
  mime_type    TEXT    NOT NULL,
  sort_order   INT     NOT NULL DEFAULT 0,
  created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

ALTER TABLE property_files ENABLE ROW LEVEL SECURITY;

-- Owner: full CRUD on files of their own properties
CREATE POLICY "pfiles_select_owner" ON property_files
  FOR SELECT USING (owner_id = current_app_user_id());

CREATE POLICY "pfiles_insert_owner" ON property_files
  FOR INSERT WITH CHECK (owner_id = current_app_user_id());

CREATE POLICY "pfiles_delete_owner" ON property_files
  FOR DELETE USING (owner_id = current_app_user_id());

-- Realtor: read-only access to files in databases they subscribed to
CREATE POLICY "pfiles_select_realtor" ON property_files
  FOR SELECT USING (
    EXISTS (
      SELECT 1
      FROM realtor_subscriptions rs
      JOIN properties p ON p.db_id = rs.db_id
      WHERE rs.realtor_id = current_app_user_id()
        AND p.id = property_files.property_id
    )
  );

-- ── Storage bucket ───────────────────────────────────────────────────────────
INSERT INTO storage.buckets (id, name, public, file_size_limit, allowed_mime_types)
VALUES (
  'property-files',
  'property-files',
  false,
  20971520,  -- 20 MB
  ARRAY[
    'application/pdf',
    'application/msword',
    'application/vnd.openxmlformats-officedocument.wordprocessingml.document'
  ]
)
ON CONFLICT (id) DO UPDATE
  SET public             = false,
      file_size_limit    = 20971520,
      allowed_mime_types = ARRAY[
        'application/pdf',
        'application/msword',
        'application/vnd.openxmlformats-officedocument.wordprocessingml.document'
      ];

-- Storage policies (auth only — row-level trust is via property_files RLS)
DROP POLICY IF EXISTS "pfiles_storage_select" ON storage.objects;
DROP POLICY IF EXISTS "pfiles_storage_insert" ON storage.objects;
DROP POLICY IF EXISTS "pfiles_storage_delete" ON storage.objects;

CREATE POLICY "pfiles_storage_select" ON storage.objects
  FOR SELECT TO authenticated
  USING (bucket_id = 'property-files');

CREATE POLICY "pfiles_storage_insert" ON storage.objects
  FOR INSERT TO authenticated
  WITH CHECK (bucket_id = 'property-files');

CREATE POLICY "pfiles_storage_delete" ON storage.objects
  FOR DELETE TO authenticated
  USING (bucket_id = 'property-files');

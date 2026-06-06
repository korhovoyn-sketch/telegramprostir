-- Add sort_order to properties for manual reordering within a database.
-- Default 0 means "not yet ordered" — the front-end initialises positions
-- on the user's first reorder action.
ALTER TABLE properties ADD COLUMN IF NOT EXISTS sort_order INT NOT NULL DEFAULT 0;

CREATE INDEX IF NOT EXISTS idx_properties_sort_order ON properties(db_id, sort_order, created_at);

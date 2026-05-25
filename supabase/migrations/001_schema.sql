-- PropSpace v1.0.0 — Full Schema

CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- Users
CREATE TABLE users (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tg_id BIGINT UNIQUE NOT NULL,
  tg_username TEXT,
  first_name TEXT NOT NULL,
  last_name TEXT,
  email TEXT,
  phone TEXT,
  role TEXT NOT NULL DEFAULT 'owner' CHECK (role IN ('owner', 'realtor')),
  language_code TEXT DEFAULT 'uk',
  currency TEXT DEFAULT 'USD',
  plan TEXT DEFAULT 'free' CHECK (plan IN ('free', 'pro')),
  created_at TIMESTAMPTZ DEFAULT now(),
  updated_at TIMESTAMPTZ DEFAULT now()
);

-- Databases (buildings / properties groupings)
CREATE TABLE databases (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  owner_id UUID REFERENCES users(id) ON DELETE CASCADE NOT NULL,
  name TEXT NOT NULL,
  address TEXT,
  type TEXT NOT NULL CHECK (type IN ('business_center','residential','retail','warehouse','individual','parking')),
  color TEXT NOT NULL DEFAULT 'purple',
  share_token TEXT UNIQUE DEFAULT encode(gen_random_bytes(12), 'hex'),
  share_expires_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ DEFAULT now(),
  updated_at TIMESTAMPTZ DEFAULT now()
);

-- Properties (units within a database)
CREATE TABLE properties (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  db_id UUID REFERENCES databases(id) ON DELETE CASCADE NOT NULL,
  owner_id UUID REFERENCES users(id) ON DELETE CASCADE NOT NULL,
  name TEXT NOT NULL,
  floor TEXT,
  status TEXT DEFAULT 'free' CHECK (status IN ('free','occupied','for_sale')),
  area_useful FLOAT,
  area_total FLOAT,
  rent_type TEXT DEFAULT 'per_m2' CHECK (rent_type IN ('per_m2','fixed')),
  rent_rate FLOAT,
  utilities_rate FLOAT,
  has_parking BOOLEAN DEFAULT false,
  parking_spaces INT DEFAULT 0,
  description TEXT,
  created_at TIMESTAMPTZ DEFAULT now(),
  updated_at TIMESTAMPTZ DEFAULT now()
);

-- Property photos
CREATE TABLE property_photos (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  property_id UUID REFERENCES properties(id) ON DELETE CASCADE NOT NULL,
  storage_path TEXT NOT NULL,
  sort_order INT DEFAULT 0,
  created_at TIMESTAMPTZ DEFAULT now()
);

-- Realtor subscriptions to owner databases
CREATE TABLE realtor_subscriptions (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  realtor_id UUID REFERENCES users(id) ON DELETE CASCADE NOT NULL,
  db_id UUID REFERENCES databases(id) ON DELETE CASCADE NOT NULL,
  created_at TIMESTAMPTZ DEFAULT now(),
  UNIQUE(realtor_id, db_id)
);

-- Collections (realtor's curated property sets)
CREATE TABLE collections (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  realtor_id UUID REFERENCES users(id) ON DELETE CASCADE NOT NULL,
  name TEXT NOT NULL,
  is_draft BOOLEAN DEFAULT true,
  created_at TIMESTAMPTZ DEFAULT now(),
  updated_at TIMESTAMPTZ DEFAULT now()
);

-- Collection <-> Property many-to-many
CREATE TABLE collection_properties (
  collection_id UUID REFERENCES collections(id) ON DELETE CASCADE NOT NULL,
  property_id UUID REFERENCES properties(id) ON DELETE CASCADE NOT NULL,
  added_at TIMESTAMPTZ DEFAULT now(),
  PRIMARY KEY (collection_id, property_id)
);

-- Property view events
CREATE TABLE property_views (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  property_id UUID REFERENCES properties(id) ON DELETE CASCADE NOT NULL,
  viewer_id UUID REFERENCES users(id),
  viewer_name TEXT,
  action TEXT DEFAULT 'view' CHECK (action IN ('view','photo','document','share','favorite')),
  created_at TIMESTAMPTZ DEFAULT now()
);

-- Notifications
CREATE TABLE notifications (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID REFERENCES users(id) ON DELETE CASCADE NOT NULL,
  type TEXT NOT NULL,
  title TEXT NOT NULL,
  body TEXT,
  is_read BOOLEAN DEFAULT false,
  data JSONB,
  created_at TIMESTAMPTZ DEFAULT now()
);

-- Indexes
CREATE INDEX idx_databases_owner ON databases(owner_id);
CREATE INDEX idx_properties_db ON properties(db_id);
CREATE INDEX idx_properties_owner ON properties(owner_id);
CREATE INDEX idx_property_photos_prop ON property_photos(property_id);
CREATE INDEX idx_realtor_subs_realtor ON realtor_subscriptions(realtor_id);
CREATE INDEX idx_realtor_subs_db ON realtor_subscriptions(db_id);
CREATE INDEX idx_collections_realtor ON collections(realtor_id);
CREATE INDEX idx_property_views_prop ON property_views(property_id);
CREATE INDEX idx_notifications_user ON notifications(user_id);
CREATE INDEX idx_notifications_unread ON notifications(user_id, is_read) WHERE is_read = false;

-- Updated_at trigger
CREATE OR REPLACE FUNCTION update_updated_at()
RETURNS TRIGGER AS $$
BEGIN
  NEW.updated_at = now();
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_users_updated_at BEFORE UPDATE ON users FOR EACH ROW EXECUTE FUNCTION update_updated_at();
CREATE TRIGGER trg_databases_updated_at BEFORE UPDATE ON databases FOR EACH ROW EXECUTE FUNCTION update_updated_at();
CREATE TRIGGER trg_properties_updated_at BEFORE UPDATE ON properties FOR EACH ROW EXECUTE FUNCTION update_updated_at();
CREATE TRIGGER trg_collections_updated_at BEFORE UPDATE ON collections FOR EACH ROW EXECUTE FUNCTION update_updated_at();

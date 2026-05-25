-- PropSpace v1.0.0 — Row Level Security Policies

-- Enable RLS on all tables
ALTER TABLE users ENABLE ROW LEVEL SECURITY;
ALTER TABLE databases ENABLE ROW LEVEL SECURITY;
ALTER TABLE properties ENABLE ROW LEVEL SECURITY;
ALTER TABLE property_photos ENABLE ROW LEVEL SECURITY;
ALTER TABLE realtor_subscriptions ENABLE ROW LEVEL SECURITY;
ALTER TABLE collections ENABLE ROW LEVEL SECURITY;
ALTER TABLE collection_properties ENABLE ROW LEVEL SECURITY;
ALTER TABLE property_views ENABLE ROW LEVEL SECURITY;
ALTER TABLE notifications ENABLE ROW LEVEL SECURITY;

-- Helper: get current app user id from tg_id claim in JWT
CREATE OR REPLACE FUNCTION current_app_user_id()
RETURNS UUID AS $$
  SELECT id FROM users
  WHERE tg_id = (current_setting('request.jwt.claims', true)::jsonb->>'tg_id')::bigint
  LIMIT 1;
$$ LANGUAGE sql STABLE SECURITY DEFINER;

-- users
CREATE POLICY "users_own" ON users
  FOR ALL USING (id = current_app_user_id());

CREATE POLICY "users_service" ON users
  FOR ALL TO service_role USING (true);

-- databases
CREATE POLICY "db_owner_all" ON databases
  FOR ALL USING (owner_id = current_app_user_id());

CREATE POLICY "db_realtor_select" ON databases
  FOR SELECT USING (
    id IN (
      SELECT db_id FROM realtor_subscriptions WHERE realtor_id = current_app_user_id()
    )
  );

CREATE POLICY "db_service" ON databases
  FOR ALL TO service_role USING (true);

-- properties
CREATE POLICY "props_owner_all" ON properties
  FOR ALL USING (owner_id = current_app_user_id());

CREATE POLICY "props_realtor_select" ON properties
  FOR SELECT USING (
    db_id IN (
      SELECT db_id FROM realtor_subscriptions WHERE realtor_id = current_app_user_id()
    )
  );

CREATE POLICY "props_service" ON properties
  FOR ALL TO service_role USING (true);

-- property_photos
CREATE POLICY "photos_owner_all" ON property_photos
  FOR ALL USING (
    property_id IN (
      SELECT id FROM properties WHERE owner_id = current_app_user_id()
    )
  );

CREATE POLICY "photos_realtor_select" ON property_photos
  FOR SELECT USING (
    property_id IN (
      SELECT p.id FROM properties p
      JOIN realtor_subscriptions rs ON rs.db_id = p.db_id
      WHERE rs.realtor_id = current_app_user_id()
    )
  );

-- realtor_subscriptions
CREATE POLICY "subs_realtor_all" ON realtor_subscriptions
  FOR ALL USING (realtor_id = current_app_user_id());

CREATE POLICY "subs_owner_select" ON realtor_subscriptions
  FOR SELECT USING (
    db_id IN (
      SELECT id FROM databases WHERE owner_id = current_app_user_id()
    )
  );

-- collections
CREATE POLICY "col_realtor_all" ON collections
  FOR ALL USING (realtor_id = current_app_user_id());

-- collection_properties
CREATE POLICY "col_props_realtor_all" ON collection_properties
  FOR ALL USING (
    collection_id IN (
      SELECT id FROM collections WHERE realtor_id = current_app_user_id()
    )
  );

-- property_views
CREATE POLICY "views_owner_select" ON property_views
  FOR SELECT USING (
    property_id IN (
      SELECT id FROM properties WHERE owner_id = current_app_user_id()
    )
  );

CREATE POLICY "views_insert_all" ON property_views
  FOR INSERT WITH CHECK (true);

-- notifications
CREATE POLICY "notifs_own" ON notifications
  FOR ALL USING (user_id = current_app_user_id());

CREATE POLICY "notifs_service" ON notifications
  FOR ALL TO service_role USING (true);

-- Storage bucket policies (run after bucket is created in dashboard)
-- INSERT INTO storage.buckets (id, name, public) VALUES ('photos', 'photos', true) ON CONFLICT DO NOTHING;

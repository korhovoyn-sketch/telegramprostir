-- Rent payment schedules (one per occupied property)
CREATE TABLE IF NOT EXISTS rent_payments (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  property_id UUID NOT NULL REFERENCES properties(id) ON DELETE CASCADE,
  owner_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  due_day SMALLINT NOT NULL CHECK (due_day BETWEEN 1 AND 28),
  notify_days_before SMALLINT NOT NULL DEFAULT 3 CHECK (notify_days_before BETWEEN 0 AND 14),
  is_active BOOLEAN NOT NULL DEFAULT true,
  created_at TIMESTAMPTZ DEFAULT now(),
  updated_at TIMESTAMPTZ DEFAULT now(),
  UNIQUE(property_id)
);

ALTER TABLE rent_payments ENABLE ROW LEVEL SECURITY;

CREATE POLICY "owner manages rent_payments"
  ON rent_payments FOR ALL
  USING (owner_id = current_app_user_id())
  WITH CHECK (owner_id = current_app_user_id());

-- Rent payment records (actual received/overdue payments)
CREATE TABLE IF NOT EXISTS rent_payment_records (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  property_id UUID NOT NULL REFERENCES properties(id) ON DELETE CASCADE,
  owner_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  due_date DATE NOT NULL,
  paid_at TIMESTAMPTZ,
  amount FLOAT,
  status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'paid', 'overdue')),
  notes TEXT,
  created_at TIMESTAMPTZ DEFAULT now(),
  updated_at TIMESTAMPTZ DEFAULT now(),
  CONSTRAINT uniq_property_due UNIQUE(property_id, due_date)
);

ALTER TABLE rent_payment_records ENABLE ROW LEVEL SECURITY;

CREATE POLICY "owner manages payment_records"
  ON rent_payment_records FOR ALL
  USING (owner_id = current_app_user_id())
  WITH CHECK (owner_id = current_app_user_id());

CREATE INDEX IF NOT EXISTS idx_rent_payments_property ON rent_payments(property_id);
CREATE INDEX IF NOT EXISTS idx_rent_payments_owner ON rent_payments(owner_id, is_active);
CREATE INDEX IF NOT EXISTS idx_payment_records_property_due ON rent_payment_records(property_id, due_date);
CREATE INDEX IF NOT EXISTS idx_payment_records_owner_status ON rent_payment_records(owner_id, status);

-- Returns properties whose reminder notification is due today
-- Called by the Edge Function (SECURITY DEFINER so it can access all rows)
CREATE OR REPLACE FUNCTION get_due_reminders_today()
RETURNS TABLE(
  owner_id UUID,
  tg_id BIGINT,
  property_id UUID,
  property_name TEXT,
  due_day INT,
  tenant_name TEXT,
  due_date DATE
)
LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE
  v_today DATE := current_date;
BEGIN
  RETURN QUERY
  SELECT
    rp.owner_id,
    u.tg_id,
    rp.property_id,
    p.name AS property_name,
    rp.due_day::INT,
    p.tenant_name,
    -- Compute the actual due date for this month (today + notify_days lands on due_day)
    make_date(
      EXTRACT(YEAR FROM (v_today + rp.notify_days_before * INTERVAL '1 day'))::INT,
      EXTRACT(MONTH FROM (v_today + rp.notify_days_before * INTERVAL '1 day'))::INT,
      rp.due_day
    ) AS due_date
  FROM rent_payments rp
  JOIN properties p ON p.id = rp.property_id
  JOIN users u ON u.id = rp.owner_id
  WHERE rp.is_active = true
    AND p.status = 'occupied'
    -- Fire when: today + notify_days_before lands on the due_day of the month
    AND EXTRACT(DAY FROM (v_today + rp.notify_days_before * INTERVAL '1 day'))::INT = rp.due_day
    -- Deduplication: skip if notification already inserted this month for this property
    AND NOT EXISTS (
      SELECT 1 FROM notifications n
      WHERE n.user_id = rp.owner_id
        AND n.type = 'rent_reminder'
        AND (n.data->>'property_id')::UUID = rp.property_id
        AND DATE_TRUNC('month', n.created_at) = DATE_TRUNC('month', v_today::TIMESTAMPTZ)
    );
END;
$$;

GRANT EXECUTE ON FUNCTION get_due_reminders_today() TO service_role;

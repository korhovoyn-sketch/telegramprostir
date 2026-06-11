-- ── 024_payment_auto_overdue.sql ─────────────────────────────────────────────
-- Idempotent: auto-marks pending payment records as 'overdue' when due_date
-- passes without a payment. Also provides a callable batch function.
-- Run in Supabase SQL Editor after 021_rent_payments.sql.

-- 1. Trigger function: applied BEFORE INSERT OR UPDATE on rent_payment_records.
--    If the record has no paid_at and its due_date is in the past → force 'overdue'.
CREATE OR REPLACE FUNCTION trg_auto_overdue_fn()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  IF NEW.paid_at IS NULL AND NEW.due_date < CURRENT_DATE THEN
    NEW.status := 'overdue';
  END IF;
  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trg_auto_overdue ON rent_payment_records;
CREATE TRIGGER trg_auto_overdue
  BEFORE INSERT OR UPDATE ON rent_payment_records
  FOR EACH ROW
  EXECUTE FUNCTION trg_auto_overdue_fn();

-- 2. Batch function: marks all existing stale 'pending' records as 'overdue'.
--    Can be called from send-reminders Edge Function or a scheduled cron.
CREATE OR REPLACE FUNCTION mark_overdue_payments()
RETURNS int
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE cnt int;
BEGIN
  UPDATE rent_payment_records
  SET    status     = 'overdue',
         updated_at = now()
  WHERE  status     = 'pending'
    AND  paid_at    IS NULL
    AND  due_date   < CURRENT_DATE;
  GET DIAGNOSTICS cnt = ROW_COUNT;
  RETURN cnt;
END;
$$;

GRANT EXECUTE ON FUNCTION mark_overdue_payments() TO service_role;

-- 3. Fix any existing stale records immediately
SELECT mark_overdue_payments();

NOTIFY pgrst, 'reload schema';

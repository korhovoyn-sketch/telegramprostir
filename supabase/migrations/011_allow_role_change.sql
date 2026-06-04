-- Fix prevent_privilege_escalation trigger to allow owner→realtor role changes.
-- The original trigger blocked ALL role updates from client sessions, which broke
-- the onboarding flow: new users who selected "Realtor" stayed as "Owner" forever.
--
-- New rule: only block realtor→owner escalation. Allow owner→realtor (downgrade).
-- Plan changes remain fully blocked from client sessions.
--
-- Run this in the Supabase SQL Editor if you previously applied 010_security_perf.sql.

CREATE OR REPLACE FUNCTION prevent_privilege_escalation()
RETURNS TRIGGER LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
BEGIN
  IF current_setting('request.jwt.claims', true) IS NOT NULL
     AND current_setting('request.jwt.claims', true) != '' THEN
    -- Block plan changes from client sessions entirely
    NEW.plan := OLD.plan;
    -- Block privilege escalation only: realtor→owner is not allowed
    -- owner→realtor is allowed (initial onboarding / deliberate downgrade)
    IF NEW.role = 'owner' AND OLD.role = 'realtor' THEN
      NEW.role := OLD.role;
    END IF;
  END IF;
  RETURN NEW;
END;
$$;

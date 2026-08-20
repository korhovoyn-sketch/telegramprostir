-- ═══════════════════════════════════════════════════════════════════════════
-- 048: імʼя гостя, що прийняв запрошення
-- ═══════════════════════════════════════════════════════════════════════════
--
-- ЩО ЛІКУЄ. `db_members` має `member_name` — його заповнює `claim_team_invite`
-- (041), тож у розділі «Команда» власник бачить РЕАЛЬНЕ імʼя людини. У
-- `guest_links` такої колонки не було взагалі: лишався `guest_user_id` (UUID,
-- який ніде не показати) і `label` — підпис, який власник вигадав САМ ще до
-- того, як лінк хтось прийняв.
--
-- Наслідок для власника: список гостей відповідав на питання «як я назвав ці
-- запрошення», але не на питання «хто цим користується». Для доступу до
-- нерухомості це різні питання, і важливе саме друге.
--
-- Дзеркалить 041 буквально: та сама колонка, той самий спосіб зібрати імʼя,
-- той самий момент запису — щоб два розділи не розійшлись знову.

ALTER TABLE guest_links ADD COLUMN IF NOT EXISTS guest_name TEXT;

-- ── Клейм тепер фіксує імʼя ─────────────────────────────────────────────────
-- Повне тіло, а не патч: `CREATE OR REPLACE` замінює функцію цілком, тож усі
-- наявні гарди (заборона клейму власного лінка, ідемпотентність, revoked)
-- мусять лишитись ТУТ. Копія з 028 плюс `guest_name`.
CREATE OR REPLACE FUNCTION claim_guest_link(p_token TEXT)
RETURNS JSONB LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE
  v_uid  UUID := current_app_user_id();
  v_link RECORD;
  v_name TEXT;
BEGIN
  IF v_uid IS NULL THEN
    RAISE EXCEPTION 'not authenticated';
  END IF;

  SELECT id, property_id, db_id, guest_user_id, status, owner_id
  INTO v_link
  FROM guest_links
  WHERE invite_token = p_token
  FOR UPDATE;

  IF NOT FOUND THEN
    RETURN jsonb_build_object('error', 'not_found');
  END IF;

  IF v_link.status = 'revoked' THEN
    RETURN jsonb_build_object('error', 'revoked');
  END IF;

  -- Owner must never claim their own invite: it would demote them to guest role,
  -- locking them out of all their databases with no client-side recovery path.
  IF v_uid = v_link.owner_id THEN
    RETURN jsonb_build_object('error', 'cannot_claim_own_link');
  END IF;

  -- Already claimed by this user → idempotent success
  IF v_link.status = 'active' AND v_link.guest_user_id = v_uid THEN
    RETURN jsonb_build_object(
      'property_id', v_link.property_id,
      'db_id',       v_link.db_id
    );
  END IF;

  -- Already claimed by someone else
  IF v_link.status = 'active' AND v_link.guest_user_id IS DISTINCT FROM v_uid THEN
    RETURN jsonb_build_object('error', 'already_claimed');
  END IF;

  SELECT NULLIF(trim(concat(u.first_name, ' ', coalesce(u.last_name, ''))), '')
  INTO v_name
  FROM users u WHERE u.id = v_uid;

  UPDATE guest_links
  SET guest_user_id = v_uid,
      status        = 'active',
      claimed_at    = now(),
      guest_name    = v_name
  WHERE id = v_link.id;

  -- Ensure user has guest role (onboarding may have left them as owner default)
  UPDATE users SET role = 'guest' WHERE id = v_uid AND role = 'owner';

  RETURN jsonb_build_object(
    'property_id', v_link.property_id,
    'db_id',       v_link.db_id
  );
END;
$$;
REVOKE ALL ON FUNCTION claim_guest_link(TEXT) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION claim_guest_link(TEXT) TO authenticated;

-- ── Backfill для вже прийнятих лінків ───────────────────────────────────────
-- Без нього власник побачив би імена лише в НОВИХ гостей, а наявні лишились би
-- безіменними назавжди — тобто фіча виглядала б зламаною саме там, де в неї
-- найбільше даних.
UPDATE guest_links g
SET guest_name = NULLIF(trim(concat(u.first_name, ' ', coalesce(u.last_name, ''))), '')
FROM users u
WHERE g.guest_user_id = u.id
  AND g.guest_name IS NULL;

NOTIFY pgrst, 'reload schema';

-- ── Verification ────────────────────────────────────────────────────────────
-- Має показати named = скільки прийнятих лінків уже мають імʼя.
SELECT count(*) FILTER (WHERE guest_user_id IS NOT NULL)               AS claimed,
       count(*) FILTER (WHERE guest_user_id IS NOT NULL
                          AND guest_name IS NOT NULL)                  AS named
FROM guest_links;

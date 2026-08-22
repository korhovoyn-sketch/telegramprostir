-- ============================================================================
-- 059 — UUID обʼєкта більше не приймається як «токен» (залишок класу 049)
-- ============================================================================
-- Знайдено незалежним рев'ю (як PLAUSIBLE), підтверджено читанням джерела.
--
-- Дві функції приймали СИРИЙ UUID обʼєкта там, де мав бути нездогадний
-- share-токен, — обидві через одну й ту саму «легасі»-гілку:
--
--   WHEN p_token ~ '^[0-9a-f]{8}-…$' THEN p.id = p_token::UUID
--
--   • `lookup_shared_property(TEXT)` — SECURITY DEFINER, грант `authenticated`;
--   • `record_public_view(TEXT, TEXT)` — SECURITY DEFINER, грант **anon**.
--
-- Це дослівно те, що забороняє правило 2 чеклісту §5 Audit playbook: «UUID НЕ
-- секрет — він осідає в історії, скріншотах, логах, `screenParams`». І це той
-- самий клас, який 049 вже прибрала для підбірок, видаливши
-- `get_shared_collection(UUID)`. Тут його просто не довели до кінця.
--
-- ── ЩО САМЕ ДАВАЛА КОЖНА ───────────────────────────────────────────────────
-- `record_public_view` (anon!) — будь-хто, знаючи UUID чужого обʼєкта, пише
-- рядки «Веб-перегляд» у ЧУЖУ аналітику (1/хв через дедуп). Тобто цифри, на
-- які власник дивиться, вирішуючи ціну й канали просування, підробляються без
-- автентифікації.
-- `lookup_shared_property` — автентифікований користувач за UUID дістає
-- `db_id`. Вмісту це не дає (екран вантажиться під звичайною RLS і чужому
-- покаже `RetryState`), але сам UUID секретом не є: його віддає
-- `get_public_db_preview(token)` для КОЖНОГО обʼєкта бази.
--
-- Разом: одного шер-лінка досить, щоб зібрати UUID усіх обʼєктів жертви й
-- накрутити їй перегляди.
--
-- ── ЦІНА, НАЗВАНА ЧЕСНО ────────────────────────────────────────────────────
-- Лінки старого вигляду `prop_<uuid>` перестають резолвитись. Ризик малий:
-- `share_token` існує з 020/023, і 023 форсила `NOT NULL`, тож у КОЖНОГО
-- обʼєкта він є, а поточний шаринг генерує саме його. Ламаються лише
-- посилання, роздані до того. Рівно такий самий обмін уже зроблено в 049.
-- ============================================================================

CREATE OR REPLACE FUNCTION lookup_shared_property(p_token TEXT)
RETURNS TABLE (id UUID, db_id UUID)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT p.id, p.db_id FROM properties p
  WHERE p.share_token = p_token
    AND (p.share_expires_at IS NULL OR p.share_expires_at > now())
  LIMIT 1;
$$;
REVOKE ALL ON FUNCTION lookup_shared_property(TEXT) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION lookup_shared_property(TEXT) TO authenticated, service_role;

CREATE OR REPLACE FUNCTION record_public_view(p_token TEXT, p_kind TEXT DEFAULT 'prop')
RETURNS BOOLEAN
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE
  v_id UUID;
BEGIN
  IF p_kind = 'db' THEN
    SELECT d.id INTO v_id FROM databases d
    WHERE d.share_token = p_token
      AND (d.share_expires_at IS NULL OR d.share_expires_at > now())
    LIMIT 1;
    IF v_id IS NULL THEN RETURN FALSE; END IF;
    IF EXISTS (
      SELECT 1 FROM property_views
      WHERE db_id = v_id AND viewer_id IS NULL
        AND created_at > now() - interval '1 minute'
    ) THEN RETURN TRUE; END IF;
    INSERT INTO property_views (property_id, db_id, viewer_id, viewer_name, action)
    VALUES (NULL, v_id, NULL, 'Веб-перегляд бази', 'view');
    RETURN TRUE;

  ELSIF p_kind = 'col' THEN
    SELECT c.id INTO v_id FROM collections c
    WHERE c.share_token = p_token
      AND (c.share_expires_at IS NULL OR c.share_expires_at > now())
    LIMIT 1;
    IF v_id IS NULL THEN RETURN FALSE; END IF;
    IF EXISTS (
      SELECT 1 FROM property_views
      WHERE collection_id = v_id AND viewer_id IS NULL
        AND created_at > now() - interval '1 minute'
    ) THEN RETURN TRUE; END IF;
    INSERT INTO property_views (property_id, collection_id, viewer_id, viewer_name, action)
    VALUES (NULL, v_id, NULL, 'Веб-перегляд підбірки', 'view');
    RETURN TRUE;

  ELSE
    -- 059: ЛИШЕ share_token. Легасі-гілка по UUID прибрана — див. шапку.
    SELECT p.id INTO v_id FROM properties p
    WHERE p.share_token = p_token
      AND (p.share_expires_at IS NULL OR p.share_expires_at > now())
    LIMIT 1;
    IF v_id IS NULL THEN RETURN FALSE; END IF;
    IF EXISTS (
      SELECT 1 FROM property_views
      WHERE property_id = v_id AND viewer_id IS NULL
        AND created_at > now() - interval '1 minute'
    ) THEN RETURN TRUE; END IF;
    INSERT INTO property_views (property_id, viewer_id, viewer_name, action)
    VALUES (v_id, NULL, 'Веб-перегляд', 'view');
    RETURN TRUE;
  END IF;
END;
$$;
REVOKE ALL ON FUNCTION record_public_view(TEXT, TEXT) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION record_public_view(TEXT, TEXT) TO anon, authenticated, service_role;

NOTIFY pgrst, 'reload schema';

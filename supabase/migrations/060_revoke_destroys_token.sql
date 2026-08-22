-- ============================================================================
-- 060 — «Відкликати» тепер СПРАВДІ знищує доступ, а не лише протермінує
-- ============================================================================
-- Знайдено безпековим аудитом архітектури (заміри на живій БД, серпень 2026).
--
-- `manage_share(…, 'revoke')` ставила `share_expires_at = now()`, але
-- **лишала `share_token` незмінним**. Наслідки:
--
--  1. Токен — це BEARER-креденшл: хто його зберіг, той тримає його назавжди.
--     Після «відкликання» він мертвий лише доти, доки діє перевірка терміну.
--  2. Будь-який наступний `set_expiry`/`clear_expiry` ОЖИВЛЯЄ старий лінк —
--     для ВСІХ, хто його зберіг. Це вже було описане в CLAUDE.md як клас
--     «дії, що скасовують ефект безпекової операції», і закрите на клієнті
--     підтвердженням `askRevive`. Але UI-підтвердження — не механізм безпеки:
--     воно лише питає, тоді як сам креденшл лишається валідним.
--
-- Слово «відкликати» обіцяє знищення доступу. Тепер воно його й робить:
-- revoke ротує токен ОДНОЧАСНО з протермінуванням, тож старе посилання
-- перестає існувати як ключ — оживити його неможливо в принципі, і
-- `clear_expiry` після revoke відкриває вже НОВИЙ токен, якого ні в кого немає.
--
-- Публічна поверхня від цього ще й звужується: превʼю віддає `owner_phone` і
-- `owner_tg_username`, тобто вічний токен = вічний доступ до контактів
-- власника. Після 060 «відкликати» справді забирає його.
--
-- Контракт функції НЕ змінюється: ті самі три колонки, ті самі коди помилок,
-- ті самі чотири дії. Міняється лише те, що робить `revoke`.
-- ============================================================================

CREATE OR REPLACE FUNCTION manage_share(
  p_kind   TEXT,
  p_id     UUID,
  p_action TEXT,
  p_days   INT DEFAULT NULL
)
RETURNS TABLE (share_token TEXT, share_expires_at TIMESTAMPTZ, error TEXT)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE
  v_uid   UUID;
  v_owner UUID;
  v_tok   TEXT;
  v_exp   TIMESTAMPTZ;
BEGIN
  v_uid := current_app_user_id();
  IF v_uid IS NULL THEN
    RETURN QUERY SELECT NULL::TEXT, NULL::TIMESTAMPTZ, 'not_authenticated'::TEXT; RETURN;
  END IF;
  IF p_kind NOT IN ('db','prop','col') OR p_action NOT IN ('rotate','set_expiry','clear_expiry','revoke') THEN
    RETURN QUERY SELECT NULL::TEXT, NULL::TIMESTAMPTZ, 'bad_request'::TEXT; RETURN;
  END IF;
  IF p_action = 'set_expiry' AND (p_days IS NULL OR p_days < 1 OR p_days > 365) THEN
    RETURN QUERY SELECT NULL::TEXT, NULL::TIMESTAMPTZ, 'bad_request'::TEXT; RETURN;
  END IF;

  IF p_kind = 'db' THEN
    SELECT owner_id INTO v_owner FROM databases WHERE id = p_id FOR UPDATE;
  ELSIF p_kind = 'prop' THEN
    SELECT owner_id INTO v_owner FROM properties WHERE id = p_id FOR UPDATE;
  ELSE
    SELECT realtor_id INTO v_owner FROM collections WHERE id = p_id FOR UPDATE;
  END IF;

  IF v_owner IS NULL OR v_owner <> v_uid THEN
    RETURN QUERY SELECT NULL::TEXT, NULL::TIMESTAMPTZ, 'forbidden'::TEXT; RETURN;
  END IF;

  -- 060: `revoke` тепер у списку дій, що ротують токен, поруч із `rotate`.
  IF p_kind = 'db' THEN
    UPDATE databases SET
      share_token      = CASE WHEN p_action IN ('rotate','revoke')
                              THEN encode(gen_random_bytes(12),'hex')
                              ELSE databases.share_token END,
      share_expires_at = CASE p_action
                           WHEN 'set_expiry'   THEN now() + make_interval(days => p_days)
                           WHEN 'clear_expiry' THEN NULL
                           WHEN 'revoke'       THEN now()
                           ELSE databases.share_expires_at
                         END
    WHERE id = p_id
    RETURNING databases.share_token, databases.share_expires_at INTO v_tok, v_exp;
  ELSIF p_kind = 'prop' THEN
    UPDATE properties SET
      share_token      = CASE WHEN p_action IN ('rotate','revoke')
                              THEN encode(gen_random_bytes(12),'hex')
                              ELSE properties.share_token END,
      share_expires_at = CASE p_action
                           WHEN 'set_expiry'   THEN now() + make_interval(days => p_days)
                           WHEN 'clear_expiry' THEN NULL
                           WHEN 'revoke'       THEN now()
                           ELSE properties.share_expires_at
                         END
    WHERE id = p_id
    RETURNING properties.share_token, properties.share_expires_at INTO v_tok, v_exp;
  ELSE
    UPDATE collections SET
      share_token      = CASE WHEN p_action IN ('rotate','revoke')
                              THEN encode(gen_random_bytes(12),'hex')
                              ELSE collections.share_token END,
      share_expires_at = CASE p_action
                           WHEN 'set_expiry'   THEN now() + make_interval(days => p_days)
                           WHEN 'clear_expiry' THEN NULL
                           WHEN 'revoke'       THEN now()
                           ELSE collections.share_expires_at
                         END
    WHERE id = p_id
    RETURNING collections.share_token, collections.share_expires_at INTO v_tok, v_exp;
  END IF;

  RETURN QUERY SELECT v_tok, v_exp, NULL::TEXT;
END;
$$;

REVOKE ALL ON FUNCTION manage_share(TEXT, UUID, TEXT, INT) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION manage_share(TEXT, UUID, TEXT, INT) TO authenticated, service_role;

NOTIFY pgrst, 'reload schema';

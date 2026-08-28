-- 063: `views_insert_auth` пускає перегляди РЕДАКТОРІВ і перегляди БАЗ.
--
-- Політика з 036 дозволяла вставку лише коли `property_id` належить власнику
-- або підписаному рієлтору. Два наслідки, обидва мовчазні (RLS не віддає
-- помилки на заблокований INSERT — рівно клас правила 8 у Security rules):
--
--   1. РЕДАКТОР КОМАНДИ не міг записати перегляд картки: `get_editor_property_ids`
--      у переліку немає. Тобто 041 дала редактору право писати обʼєкти, фото й
--      платежі, але не власний слід перегляду.
--   2. Перегляд БАЗИ не міг записати НІХТО. Рядок бази має `property_id = NULL`
--      (так його пише `record_public_view` з 040), а `NULL IN (...)` дає NULL,
--      не TRUE — тобто предикат не виконувався в принципі.
--
-- Читання цих рядків уже дозволене: `views_owner_select` (картки власника),
-- `views_db_owner_select` (040, рядки баз) і `views_editor_select` (047).
-- Тобто діра була рівно на боці ЗАПИСУ.
--
-- Обидві гілки перевіряють, що ЦІЛЬ доступна тому, хто пише, — той самий урок,
-- що в 046/053/056: політика на таблиці слідів мусить питати не лише «це я?»,
-- а й «чи моя ціль?». Інакше будь-хто садив би сліди в чужу базу.

DROP POLICY IF EXISTS "views_insert_auth" ON property_views;

CREATE POLICY "views_insert_auth" ON property_views
  FOR INSERT WITH CHECK (
    auth.role() = 'authenticated'
    -- Чужу особу підставити не можна (лишається з 036).
    AND (viewer_id IS NULL OR viewer_id = current_app_user_id())
    AND (
      -- Перегляд КАРТКИ: обʼєкт мусить бути досяжний тому, хто пише.
      (
        property_id IS NOT NULL AND (
          property_id IN (SELECT get_owner_property_ids(current_app_user_id()))
          OR property_id IN (SELECT get_realtor_property_ids(current_app_user_id()))
          OR property_id IN (SELECT get_editor_property_ids(current_app_user_id()))
        )
      )
      OR
      -- Перегляд БАЗИ: рядок без обʼєкта. Та сама вимога — база мусить бути
      -- досяжна; `collection_id` тут свідомо НЕ згадується, бо підбірки
      -- рахує `record_public_view` під service_role, а не клієнт.
      (
        property_id IS NULL AND db_id IS NOT NULL AND (
          db_id IN (SELECT get_owner_db_ids(current_app_user_id()))
          OR db_id IN (SELECT get_realtor_db_ids(current_app_user_id()))
          OR db_id IN (SELECT get_editor_db_ids(current_app_user_id()))
        )
      )
    )
  );

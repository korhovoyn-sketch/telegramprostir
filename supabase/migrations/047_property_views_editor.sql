-- 047: редактор команди бачить лічильник переглядів
--
-- ЩО НЕ ТАК. `041_team_members.sql` дала редактору паралельні політики майже на
-- все, що показує екран бази — properties, photos, files, rent_payments,
-- rent_payment_records, storage; `043` додала папки. Одну таблицю пропущено:
-- `property_views`. У неї RLS увімкнена, editor-політики немає, отже під RLS
-- вбудований підзапит просто віддає ПОРОЖНЬО — без помилки.
--
-- Наслідок не в доступі, а у ВІДОБРАЖЕННІ: `useProperties` рахує `_view_count`
-- з цього вбудованого набору, тож редактор бачить на кожній картці «0
-- переглядів», хоч у власника там реальні цифри. Мовчазний нуль читається як
-- «переглядів немає», а не як «тобі не видно» — тобто редактор і власник
-- дивляться на ту саму базу й бачать різні дані, без жодного натяку чому.
--
-- ЧОМУ САМЕ SELECT І НІЧОГО БІЛЬШЕ. Перегляди пише `record_public_view()`
-- (SECURITY DEFINER) від імені публічного глядача, а чистить їх власник
-- (`views_db_owner_delete` з 040). Редактору потрібно рівно читання: він не
-- створює і не видаляє переглядів. Ширші права тут були б не зручністю, а
-- новою поверхнею.
--
-- Дзеркалить `views_db_owner_select` з 040, лише джерело id-шників інше:
-- get_editor_property_ids / get_editor_db_ids замість owner-хелперів.

DROP POLICY IF EXISTS "views_editor_select" ON property_views;
CREATE POLICY "views_editor_select" ON property_views FOR SELECT
  USING (
    property_id IN (SELECT get_editor_property_ids(current_app_user_id()))
    OR db_id     IN (SELECT get_editor_db_ids(current_app_user_id()))
  );

-- Перевірка: мусить зʼявитись рівно один рядок.
SELECT tablename, policyname
  FROM pg_policies
 WHERE tablename = 'property_views' AND policyname = 'views_editor_select';

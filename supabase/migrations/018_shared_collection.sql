CREATE OR REPLACE FUNCTION get_shared_collection(p_collection_id UUID)
RETURNS JSONB
SECURITY DEFINER
SET search_path = public
LANGUAGE plpgsql AS $$
DECLARE
  v_col RECORD;
BEGIN
  SELECT id, name, is_draft INTO v_col
  FROM collections
  WHERE id = p_collection_id AND is_draft = false;

  IF NOT FOUND THEN RETURN NULL; END IF;

  RETURN jsonb_build_object(
    'id',   v_col.id,
    'name', v_col.name,
    'properties', COALESCE((
      SELECT jsonb_agg(
        jsonb_build_object(
          'id',          p.id,
          'name',        p.name,
          'status',      p.status,
          'area_useful', p.area_useful,
          'area_total',  p.area_total,
          'rent_rate',   p.rent_rate,
          'rent_type',   p.rent_type,
          'floor',       p.floor,
          'first_photo', (
            SELECT storage_path FROM property_photos
            WHERE property_id = p.id
            ORDER BY sort_order, created_at
            LIMIT 1
          )
        ) ORDER BY p.sort_order, p.created_at
      )
      FROM collection_properties cp
      JOIN properties p ON p.id = cp.property_id
      WHERE cp.collection_id = v_col.id
    ), '[]'::jsonb)
  );
END;
$$;

GRANT EXECUTE ON FUNCTION get_shared_collection(UUID) TO authenticated, anon;

\set ON_ERROR_STOP on
SET ROLE appsec_owner;

-- Applies tenant isolation and owner-based defaults to an application-owned table.
-- The caller must own the target table; this function does not elevate privileges.
CREATE OR REPLACE FUNCTION appsec.protect_tenant_owned_table(
  target_table regclass,
  tenant_column name,
  owner_column name,
  read_all_role text DEFAULT NULL,
  write_all_role text DEFAULT NULL
) RETURNS void
LANGUAGE plpgsql SECURITY INVOKER
SET search_path = pg_catalog, appsec
AS $$
DECLARE
  relation_kind "char";
  tenant_type oid;
  owner_type oid;
  table_sql text := target_table::text;
  read_predicate text;
  write_predicate text;
BEGIN
  SELECT c.relkind INTO relation_kind
  FROM pg_class c WHERE c.oid = target_table;
  IF relation_kind IS DISTINCT FROM 'r' AND relation_kind IS DISTINCT FROM 'p' THEN
    RAISE EXCEPTION 'target must be an ordinary or partitioned table' USING ERRCODE = '22023';
  END IF;

  SELECT a.atttypid INTO tenant_type FROM pg_attribute a
   WHERE a.attrelid = target_table AND a.attname = tenant_column AND a.attnum > 0 AND NOT a.attisdropped;
  SELECT a.atttypid INTO owner_type FROM pg_attribute a
   WHERE a.attrelid = target_table AND a.attname = owner_column AND a.attnum > 0 AND NOT a.attisdropped;
  IF tenant_type IS DISTINCT FROM 'uuid'::regtype::oid OR owner_type IS DISTINCT FROM 'uuid'::regtype::oid THEN
    RAISE EXCEPTION 'tenant and owner columns must both exist and have type uuid' USING ERRCODE = '22023';
  END IF;

  read_predicate := format('(%I = appsec.uid() OR %s OR pg_has_role(session_user, ''appsec_operator_base'', ''member''))', owner_column,
    CASE WHEN read_all_role IS NULL THEN 'false' ELSE format('appsec.has_role(%L)', read_all_role) END);
  write_predicate := format('(%I = appsec.uid() OR %s OR pg_has_role(session_user, ''appsec_operator_base'', ''member''))', owner_column,
    CASE WHEN write_all_role IS NULL THEN 'false' ELSE format('appsec.has_role(%L)', write_all_role) END);

  EXECUTE format('ALTER TABLE %s ENABLE ROW LEVEL SECURITY', table_sql);
  EXECUTE format('ALTER TABLE %s FORCE ROW LEVEL SECURITY', table_sql);
  EXECUTE format('DROP POLICY IF EXISTS appsec_tenant_select ON %s', table_sql);
  EXECUTE format('DROP POLICY IF EXISTS appsec_tenant_insert ON %s', table_sql);
  EXECUTE format('DROP POLICY IF EXISTS appsec_tenant_update ON %s', table_sql);
  EXECUTE format('DROP POLICY IF EXISTS appsec_tenant_delete ON %s', table_sql);
  EXECUTE format('CREATE POLICY appsec_tenant_select ON %s FOR SELECT USING ((%I = appsec.tenant_id() OR pg_has_role(session_user, ''appsec_operator_base'', ''member'')) AND %s)', table_sql, tenant_column, read_predicate);
  EXECUTE format('CREATE POLICY appsec_tenant_insert ON %s FOR INSERT WITH CHECK ((%I = appsec.tenant_id() OR pg_has_role(session_user, ''appsec_operator_base'', ''member'')) AND %I = appsec.uid())', table_sql, tenant_column, owner_column);
  EXECUTE format('CREATE POLICY appsec_tenant_update ON %s FOR UPDATE USING ((%I = appsec.tenant_id() OR pg_has_role(session_user, ''appsec_operator_base'', ''member'')) AND %s) WITH CHECK ((%I = appsec.tenant_id() OR pg_has_role(session_user, ''appsec_operator_base'', ''member'')) AND %s)', table_sql, tenant_column, write_predicate, tenant_column, write_predicate);
  EXECUTE format('CREATE POLICY appsec_tenant_delete ON %s FOR DELETE USING ((%I = appsec.tenant_id() OR pg_has_role(session_user, ''appsec_operator_base'', ''member'')) AND %s)', table_sql, tenant_column, write_predicate);
END
$$;

-- Applies column grants for the shared application base role. Existing grants
-- to other roles must be audited separately; PostgreSQL privileges are additive.
CREATE OR REPLACE FUNCTION appsec.configure_column_access(
  target_table regclass,
  readable_columns name[] DEFAULT '{}',
  insertable_columns name[] DEFAULT '{}',
  updatable_columns name[] DEFAULT '{}'
) RETURNS void
LANGUAGE plpgsql SECURITY INVOKER
SET search_path = pg_catalog, appsec
AS $$
DECLARE
  table_sql text := target_table::text;
  col_list text;
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_class WHERE oid=target_table AND relkind IN ('r','p')) THEN
    RAISE EXCEPTION 'target must be an ordinary or partitioned table' USING ERRCODE='22023';
  END IF;
  IF EXISTS (
    SELECT 1 FROM unnest(coalesce(readable_columns,'{}'::name[]) || coalesce(insertable_columns,'{}'::name[]) || coalesce(updatable_columns,'{}'::name[])) AS cols(col)
    WHERE NOT EXISTS (SELECT 1 FROM pg_attribute a WHERE a.attrelid=target_table AND a.attname=cols.col AND a.attnum>0 AND NOT a.attisdropped)
  ) THEN RAISE EXCEPTION 'one or more requested columns do not exist' USING ERRCODE='22023'; END IF;

  EXECUTE format('REVOKE ALL ON TABLE %s FROM PUBLIC, appsec_app_base, appsec_operator_base', table_sql);
  IF cardinality(readable_columns) > 0 THEN
    SELECT string_agg(format('%I', n), ',') INTO col_list FROM unnest(readable_columns) n;
    EXECUTE format('GRANT SELECT (%s) ON TABLE %s TO appsec_app_base', col_list, table_sql);
  END IF;
  IF cardinality(insertable_columns) > 0 THEN
    SELECT string_agg(format('%I', n), ',') INTO col_list FROM unnest(insertable_columns) n;
    EXECUTE format('GRANT INSERT (%s) ON TABLE %s TO appsec_app_base', col_list, table_sql);
  END IF;
  IF cardinality(updatable_columns) > 0 THEN
    SELECT string_agg(format('%I', n), ',') INTO col_list FROM unnest(updatable_columns) n;
    EXECUTE format('GRANT UPDATE (%s) ON TABLE %s TO appsec_app_base', col_list, table_sql);
  END IF;
END
$$;

REVOKE ALL ON FUNCTION appsec.protect_tenant_owned_table(regclass,name,name,text,text),
  appsec.configure_column_access(regclass,name[],name[],name[]) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION appsec.protect_tenant_owned_table(regclass,name,name,text,text),
  appsec.configure_column_access(regclass,name[],name[],name[]) TO appsec_operator_base;

RESET ROLE;
